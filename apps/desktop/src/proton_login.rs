//! Signs in to a Proton account, picks the best working server and writes the WireGuard
//! profile the VPN uses. The password lives in memory for this one run; only the device key
//! (so Proton recognises the same device next time) and the finished profile are saved.
use base64::{Engine, engine::general_purpose::STANDARD};
use proton::{Client, Error, Filter, HumanToken, Keys, Login, Request, Response, Transport};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

/// Servers tried per sign-in: enough to find a good one, few enough to finish quickly.
const CANDIDATES: usize = 6;
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
const USER_STEP_TIMEOUT: Duration = Duration::from_secs(300);
/// Never offered as an exit: the point of the VPN is to leave Brazil.
const EXCLUDED_COUNTRIES: [&str; 1] = ["BR"];

#[derive(Clone, Default, PartialEq, Eq)]
pub enum Stage {
	#[default]
	Idle,
	Working(String),
	NeedCode,
	NeedCaptcha { url: String, challenge: String },
	Done(String),
	Failed(String),
}

/// What the interface thread and the sign-in task exchange.
#[derive(Default)]
pub struct Shared {
	pub stage: Stage,
	pub code: Option<String>,
	pub human: Option<HumanToken>,
	pub cancelled: bool,
}

pub type Handle = Arc<Mutex<Shared>>;

fn set(shared: &Handle, stage: Stage, wake: &impl Fn()) {
	if let Ok(mut guard) = shared.lock() {
		guard.stage = stage;
	}
	wake();
}

struct Wreq(wreq::Client);

impl Wreq {
	fn new() -> Result<Self, &'static str> {
		wreq::Client::builder()
			.cookie_store(true)
			.timeout(Duration::from_secs(30))
			.build()
			.map(Self)
			.map_err(|_| "Network client unavailable")
	}
}

impl Transport for Wreq {
	async fn send(&self, request: Request) -> Result<Response, Error> {
		let url = format!("{}{}", proton::API, request.path);
		let mut builder = match request.method {
			"GET" => self.0.get(url.as_str()),
			_ => self.0.post(url.as_str()),
		};
		for (name, value) in request.headers {
			builder = builder.header(name, value);
		}
		if let Some(body) = request.body {
			builder = builder.json(&body);
		}
		let response = builder.send().await.map_err(|error| Error::Network(error.to_string()))?;
		let status = response.status().as_u16();
		let body = response.json::<serde_json::Value>().await.unwrap_or(serde_json::Value::Null);
		Ok(Response { status, body })
	}
}

fn seed_path(root: &Path) -> PathBuf {
	root.join("vpn").join("proton-device.key")
}

/// The device key, created on first use. Proton tracks the registered key, so it must persist.
fn device_keys(root: &Path) -> Result<Keys, &'static str> {
	let path = seed_path(root);
	if let Ok(text) = std::fs::read_to_string(&path)
		&& let Ok(bytes) = STANDARD.decode(text.trim())
		&& let Ok(seed) = <[u8; 32]>::try_from(bytes)
	{
		return Ok(Keys::from_seed(seed));
	}
	let keys = Keys::generate()?;
	std::fs::create_dir_all(path.parent().ok_or("Profile storage is unavailable")?)
		.map_err(|_| "Could not create the profile folder")?;
	crate::vpn_setup::write_private(&path, STANDARD.encode(keys.seed()).as_bytes())?;
	Ok(keys)
}

async fn wait_for<T>(shared: &Handle, mut take: impl FnMut(&mut Shared) -> Option<T>) -> Result<T, String> {
	let started = std::time::Instant::now();
	loop {
		{
			let mut guard = shared.lock().map_err(|_| "Internal error".to_owned())?;
			if guard.cancelled {
				return Err("Cancelled.".into());
			}
			if let Some(value) = take(&mut guard) {
				return Ok(value);
			}
		}
		if started.elapsed() > USER_STEP_TIMEOUT {
			return Err("Timed out waiting for the next step.".into());
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

fn describe(error: &Error) -> String {
	match error {
		Error::AppOutdated => "Proton no longer accepts this client version. Import a .conf from your Proton account instead.".into(),
		other => other.to_string(),
	}
}

pub struct SignIn {
	pub username: String,
	pub password: Zeroizing<String>,
	pub countries: Vec<String>,
	pub root: PathBuf,
}

/// The whole sign-in. Reports progress through `shared`; the result is also the saved profile.
pub async fn run(request: SignIn, shared: Handle, wake: impl Fn() + Send + Sync + 'static) {
	let outcome = flow(&request, &shared, &wake).await;
	set(
		&shared,
		match outcome {
			Ok(message) => Stage::Done(message),
			Err(message) => Stage::Failed(message),
		},
		&wake,
	);
}

async fn flow(request: &SignIn, shared: &Handle, wake: &(impl Fn() + Send + Sync)) -> Result<String, String> {
	let client = Client::new(Wreq::new().map_err(str::to_owned)?);
	set(shared, Stage::Working("Signing in to Proton…".into()), wake);
	let mut human: Option<HumanToken> = None;
	let login = loop {
		match client.login(&request.username, request.password.as_bytes(), human.as_ref()).await {
			Ok(login) => break login,
			Err(Error::HumanVerification { token, url }) => {
				if human.is_some() {
					return Err("Proton rejected the verification. Try again.".into());
				}
				set(shared, Stage::NeedCaptcha { url, challenge: token }, wake);
				human = Some(wait_for(shared, |s| s.human.take()).await?);
				set(shared, Stage::Working("Signing in to Proton…".into()), wake);
			}
			Err(error) => return Err(describe(&error)),
		}
	};
	let session = match login {
		Login::Done(session) => session,
		Login::SecondFactor(session) => {
			set(shared, Stage::NeedCode, wake);
			let code = wait_for(shared, |s| s.code.take()).await?;
			set(shared, Stage::Working("Checking the two-factor code…".into()), wake);
			client.second_factor(&session, code.trim()).await.map_err(|e| describe(&e))?;
			session
		}
	};
	set(shared, Stage::Working("Reading your plan and the server list…".into()), wake);
	let plan = client.plan(&session).await.map_err(|e| describe(&e))?;
	let servers = client.servers(&session).await.map_err(|e| describe(&e))?;
	let keys = device_keys(&request.root)?;
	client.register(&session, &keys, "Serein").await.map_err(|e| describe(&e))?;

	let exclude: Vec<String> = EXCLUDED_COUNTRIES.iter().map(|c| (*c).to_owned()).collect();
	let candidates = proton::select(servers, &Filter { max_tier: plan.max_tier, countries: &request.countries, exclude: &exclude });
	if candidates.is_empty() {
		return Err("No server matches your plan and countries.".into());
	}
	// Spread the trial over countries (least loaded first within each) so one crowded location
	// does not fill the list.
	let mut seen = std::collections::HashSet::new();
	let (firsts, rest): (Vec<_>, Vec<_>) = candidates
		.into_iter()
		.partition(|server| seen.insert(server.country.clone()));
	let candidates: Vec<_> = firsts.into_iter().chain(rest).take(CANDIDATES).collect();

	let mut best: Option<(bool, Duration, proton::Server)> = None;
	for (index, server) in candidates.into_iter().enumerate() {
		set(shared, Stage::Working(format!("Testing {} ({}/{CANDIDATES})…", server.name, index + 1)), wake);
		if shared.lock().map_or(true, |g| g.cancelled) {
			return Err("Cancelled.".into());
		}
		let Ok(config) = vpn::Config::parse(&proton::profile(&keys, &server)) else { continue };
		let Ok(probe) = vpn::probe(config, PROBE_TIMEOUT).await else { continue };
		let better = best.as_ref().is_none_or(|(discord, time, _)| {
			(probe.discord, std::cmp::Reverse(probe.handshake)) > (*discord, std::cmp::Reverse(*time))
		});
		if better {
			best = Some((probe.discord, probe.handshake, server));
		}
	}
	let Some((discord, handshake, server)) = best else {
		return Err("No server answered. Check that UDP is not blocked, or try other countries.".into());
	};
	crate::vpn_setup::save_profile(&request.root, proton::profile(&keys, &server).as_bytes())?;
	Ok(format!(
		"Found {} ({}, {}) in {} ms{}. Turn the VPN on and restart Serein.",
		server.name,
		server.city,
		server.country,
		handshake.as_millis(),
		if discord { "" } else { ", but Discord did not answer through it" },
	))
}

pub fn countries(text: &str) -> Vec<String> {
	text.split([',', ' ', ';'])
		.map(|part| part.trim().to_ascii_uppercase())
		.filter(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_alphabetic()))
		.take(8)
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn country_list_accepts_codes_only() {
		assert_eq!(countries("us, mx;ca  junk x1"), ["US", "MX", "CA"]);
		assert!(countries("").is_empty());
	}
}
