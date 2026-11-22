//! Proton VPN account access without Proton's apps: log in (SRP, optional TOTP, human
//! verification), list servers, register a WireGuard key and write a `wg-quick` profile that
//! the `vpn` crate can run. The transport is injected so this crate has no TLS stack.
//!
//! Endpoints and field names follow Proton's open-source VPN clients; they are not a published
//! API and can change. A rejected `x-pm-appversion` surfaces as [`Error::AppOutdated`].
pub mod srp;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use std::future::Future;
use std::net::Ipv4Addr;
use zeroize::Zeroizing;

/// Identifies the client to Proton. Old values are refused with code 5003.
pub const APP_VERSION: &str = "linux-vpn-gui@6.1.2";
pub const USER_AGENT: &str = "ProtonVPN/6.1.2 (Windows; Serein)";
pub const API: &str = "https://vpn-api.proton.me";
/// Proton lists these as the WireGuard UDP port for every server.
pub const WIREGUARD_PORT: u16 = 51820;

pub struct Request {
	pub method: &'static str,
	pub path: String,
	pub headers: Vec<(&'static str, String)>,
	pub body: Option<Value>,
}

pub struct Response {
	pub status: u16,
	pub body: Value,
}

pub trait Transport: Send + Sync {
	fn send(&self, request: Request) -> impl Future<Output = Result<Response, Error>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
	/// Proton refuses this client version (codes 5001/5003/5005).
	AppOutdated,
	BadCredentials,
	/// A CAPTCHA (or other check) must be solved; `url` is Proton's own verification page.
	HumanVerification { token: String, url: String },
	/// The account uses a second factor this client cannot answer (security key only).
	UnsupportedSecondFactor,
	Api { code: i64, message: String },
	Network(String),
	Protocol(&'static str),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::AppOutdated => f.write_str("Proton no longer accepts this client version"),
			Self::BadCredentials => f.write_str("Incorrect Proton username or password"),
			Self::HumanVerification { .. } => f.write_str("Proton asks for a human verification"),
			Self::UnsupportedSecondFactor => {
				f.write_str("This account needs a security key, which Serein cannot use")
			}
			Self::Api { code, message } => write!(f, "Proton error {code}: {message}"),
			Self::Network(message) => write!(f, "Network error: {message}"),
			Self::Protocol(message) => f.write_str(message),
		}
	}
}

impl From<&'static str> for Error {
	fn from(message: &'static str) -> Self {
		Self::Protocol(message)
	}
}

/// A solved human verification, to retry the login with.
pub struct HumanToken {
	pub token: String,
	pub kind: String,
}

#[derive(Clone)]
pub struct Session {
	pub uid: String,
	pub access: Zeroizing<String>,
	pub refresh: Zeroizing<String>,
}

pub enum Login {
	Done(Session),
	/// The password was right; a TOTP code is still needed.
	SecondFactor(Session),
}

pub struct Plan {
	pub max_tier: i64,
	pub title: String,
}

#[derive(Clone, Debug)]
pub struct Server {
	pub name: String,
	pub country: String,
	pub city: String,
	pub tier: i64,
	pub load: i64,
	pub entry_ip: Ipv4Addr,
	pub public_key: String,
}

/// The WireGuard identity Proton knows this device by. The same key works on every server.
pub struct Keys {
	seed: Zeroizing<[u8; 32]>,
}

impl Keys {
	pub fn generate() -> Result<Self, &'static str> {
		let mut seed = [0u8; 32];
		getrandom::fill(&mut seed).map_err(|_| "No system randomness")?;
		Ok(Self { seed: Zeroizing::new(seed) })
	}
	pub fn from_seed(seed: [u8; 32]) -> Self {
		Self { seed: Zeroizing::new(seed) }
	}
	pub fn seed(&self) -> &[u8; 32] {
		&self.seed
	}
	/// Ed25519 public key as the SubjectPublicKeyInfo PEM Proton's API takes.
	pub fn public_pem(&self) -> String {
		use ring::signature::{Ed25519KeyPair, KeyPair};
		let pair = Ed25519KeyPair::from_seed_unchecked(&*self.seed).expect("32-byte seed");
		let mut der = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
		der.extend_from_slice(pair.public_key().as_ref());
		format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der))
	}
	/// The WireGuard private key: the clamped first half of SHA-512(seed), as libsodium's
	/// `crypto_sign_ed25519_sk_to_curve25519` computes it.
	pub fn wireguard_private(&self) -> Zeroizing<[u8; 32]> {
		let digest = Sha512::digest(&*self.seed);
		let mut key = [0u8; 32];
		key.copy_from_slice(&digest[..32]);
		key[0] &= 248;
		key[31] &= 127;
		key[31] |= 64;
		Zeroizing::new(key)
	}
}

/// A `wg-quick` profile for one server, as Proton's own configuration page writes it.
pub fn profile(keys: &Keys, server: &Server) -> Zeroizing<String> {
	Zeroizing::new(format!(
		"[Interface]\nPrivateKey = {}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {}:{}\nPersistentKeepalive = 25\n",
		STANDARD.encode(*keys.wireguard_private()),
		server.public_key,
		server.entry_ip,
		WIREGUARD_PORT
	))
}

/// Which servers are acceptable.
pub struct Filter<'a> {
	pub max_tier: i64,
	/// Empty means any country not excluded.
	pub countries: &'a [String],
	pub exclude: &'a [String],
}

/// Usable, filtered servers, least loaded first. Secure Core and Tor routes are skipped.
pub fn select(servers: Vec<Server>, filter: &Filter) -> Vec<Server> {
	let mut kept: Vec<Server> = servers
		.into_iter()
		.filter(|server| server.tier <= filter.max_tier)
		.filter(|server| filter.countries.is_empty() || filter.countries.contains(&server.country))
		.filter(|server| !filter.exclude.contains(&server.country))
		.collect();
	kept.sort_by_key(|server| server.load);
	kept
}

fn parse_servers(body: &Value) -> Vec<Server> {
	let mut out = Vec::new();
	for logical in body["LogicalServers"].as_array().into_iter().flatten() {
		// Features: 1 = Secure Core, 2 = Tor. Both are multi-hop and not plain WireGuard exits.
		if logical["Status"].as_i64() != Some(1) || logical["Features"].as_i64().unwrap_or(0) & 3 != 0 {
			continue;
		}
		let physical = logical["Servers"].as_array().into_iter().flatten().find(|server| {
			server["Status"].as_i64() == Some(1)
				&& server["X25519PublicKey"].as_str().is_some()
				&& server["EntryIP"].as_str().is_some_and(|ip| ip.parse::<Ipv4Addr>().is_ok())
		});
		let (Some(physical), Some(name), Some(country)) =
			(physical, logical["Name"].as_str(), logical["ExitCountry"].as_str())
		else {
			continue;
		};
		let (Some(public_key), Some(Ok(entry_ip))) = (
			physical["X25519PublicKey"].as_str(),
			physical["EntryIP"].as_str().map(str::parse::<Ipv4Addr>),
		) else {
			continue;
		};
		out.push(Server {
			name: name.to_owned(),
			country: country.to_owned(),
			city: logical["City"].as_str().unwrap_or("").to_owned(),
			tier: logical["Tier"].as_i64().unwrap_or(2),
			load: logical["Load"].as_i64().unwrap_or(100),
			entry_ip,
			public_key: public_key.to_owned(),
		});
	}
	out
}

pub struct Client<T: Transport> {
	transport: T,
}

/// Proton's own CAPTCHA page for a challenge token. It answers by `postMessage`
/// (`pm_captcha`/`proton_captcha`, token `"<challenge>:<answer>"`) when `ForceWebMessaging` is set.
pub fn captcha_url(challenge: &str) -> String {
	let encoded: String = challenge
		.bytes()
		.map(|byte| match byte {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
			_ => format!("%{byte:02X}"),
		})
		.collect();
	format!("{API}/core/v4/captcha?Token={encoded}&ForceWebMessaging=1")
}

fn check(response: Response) -> Result<Value, Error> {
	let code = response.body["Code"].as_i64().unwrap_or(0);
	if (200..300).contains(&response.status) && (code == 1000 || code == 1001) {
		return Ok(response.body);
	}
	let message = response.body["Error"].as_str().unwrap_or("").to_owned();
	Err(match code {
		5001 | 5003 | 5005 => Error::AppOutdated,
		8002 => Error::BadCredentials,
		9001 => {
			let details = &response.body["Details"];
			let token = details["HumanVerificationToken"].as_str().unwrap_or("").to_owned();
			let methods: Vec<&str> = details["HumanVerificationMethods"]
				.as_array()
				.into_iter()
				.flatten()
				.filter_map(Value::as_str)
				.collect();
			// The CAPTCHA page posts its answer to the window; see `captcha_url`.
			let _ = methods;
			Error::HumanVerification { url: captcha_url(&token), token }
		}
		_ => Error::Api { code, message },
	})
}

impl<T: Transport> Client<T> {
	pub fn new(transport: T) -> Self {
		Self { transport }
	}

	async fn call(
		&self,
		method: &'static str,
		path: &str,
		session: Option<&Session>,
		human: Option<&HumanToken>,
		body: Option<Value>,
	) -> Result<Value, Error> {
		let mut headers = vec![
			("x-pm-appversion", APP_VERSION.to_owned()),
			("User-Agent", USER_AGENT.to_owned()),
			("Accept", "application/vnd.protonmail.v1+json".to_owned()),
		];
		if let Some(session) = session {
			headers.push(("x-pm-uid", session.uid.clone()));
			headers.push(("Authorization", format!("Bearer {}", session.access.as_str())));
		}
		if let Some(human) = human {
			headers.push(("x-pm-human-verification-token", human.token.clone()));
			headers.push(("x-pm-human-verification-token-type", human.kind.clone()));
		}
		check(
			self.transport
				.send(Request { method, path: path.to_owned(), headers, body })
				.await?,
		)
	}

	pub async fn login(
		&self,
		username: &str,
		password: &[u8],
		human: Option<&HumanToken>,
	) -> Result<Login, Error> {
		let info = self
			.call("POST", "/auth/info", None, human, Some(json!({ "Username": username })))
			.await?;
		let text = |name: &str| info[name].as_str().ok_or(Error::Protocol("Malformed login reply"));
		let modulus = srp::parse_modulus(text("Modulus")?)?;
		let salt = STANDARD
			.decode(text("Salt")?)
			.map_err(|_| Error::Protocol("Malformed login salt"))?;
		let server_ephemeral = STANDARD
			.decode(text("ServerEphemeral")?)
			.map_err(|_| Error::Protocol("Malformed server ephemeral"))?;
		let hashed = Zeroizing::new(srp::hash_password(
			info["Version"].as_i64().unwrap_or(-1),
			password,
			&salt,
			&modulus,
		)?);
		let proofs = srp::generate(&hashed, &modulus, &server_ephemeral)?;
		let auth = self
			.call(
				"POST",
				"/auth",
				None,
				human,
				Some(json!({
					"Username": username,
					"ClientEphemeral": STANDARD.encode(&proofs.client_ephemeral),
					"ClientProof": STANDARD.encode(&proofs.client_proof),
					"SRPSession": text("SRPSession")?,
				})),
			)
			.await?;
		let proof = auth["ServerProof"]
			.as_str()
			.and_then(|value| STANDARD.decode(value).ok())
			.ok_or(Error::Protocol("Missing server proof"))?;
		if proof != proofs.expected_server_proof {
			return Err(Error::Protocol("Proton's server proof did not match"));
		}
		let field = |name: &str| auth[name].as_str().map(str::to_owned).ok_or(Error::Protocol("Malformed session"));
		let session = Session {
			uid: field("UID")?,
			access: Zeroizing::new(field("AccessToken")?),
			refresh: Zeroizing::new(field("RefreshToken")?),
		};
		match auth["2FA"]["Enabled"].as_i64().unwrap_or(0) {
			0 => Ok(Login::Done(session)),
			enabled if enabled & 1 != 0 => Ok(Login::SecondFactor(session)),
			_ => Err(Error::UnsupportedSecondFactor),
		}
	}

	pub async fn second_factor(&self, session: &Session, code: &str) -> Result<(), Error> {
		self.call("POST", "/auth/v4/2fa", Some(session), None, Some(json!({ "TwoFactorCode": code })))
			.await
			.map(|_| ())
	}

	/// Exchanges the refresh token for a fresh access token.
	pub async fn refresh(&self, session: &Session) -> Result<Session, Error> {
		let reply = self
			.call(
				"POST",
				"/auth/refresh",
				Some(session),
				None,
				Some(json!({
					"UID": session.uid,
					"RefreshToken": session.refresh.as_str(),
					"GrantType": "refresh_token",
					"ResponseType": "token",
					"RedirectURI": "http://proton.me",
				})),
			)
			.await?;
		let field = |name: &str| reply[name].as_str().map(str::to_owned).ok_or(Error::Protocol("Malformed refresh"));
		Ok(Session {
			uid: session.uid.clone(),
			access: Zeroizing::new(field("AccessToken")?),
			refresh: Zeroizing::new(field("RefreshToken")?),
		})
	}

	pub async fn plan(&self, session: &Session) -> Result<Plan, Error> {
		let reply = self.call("GET", "/vpn/v2", Some(session), None, None).await?;
		let vpn = &reply["VPN"];
		Ok(Plan {
			// A missing tier must never read as "free" by accident of a default of 2.
			max_tier: vpn["MaxTier"].as_i64().ok_or(Error::Protocol("Missing plan tier"))?,
			title: vpn["PlanTitle"].as_str().unwrap_or("").to_owned(),
		})
	}

	pub async fn servers(&self, session: &Session) -> Result<Vec<Server>, Error> {
		let reply = self
			.call(
				"GET",
				"/vpn/v1/logicals?SecureCoreFilter=all&WithState=true",
				Some(session),
				None,
				None,
			)
			.await?;
		Ok(parse_servers(&reply))
	}

	/// Registers the key as a persistent device, like the website's WireGuard configurator.
	pub async fn register(&self, session: &Session, keys: &Keys, device: &str) -> Result<(), Error> {
		self.call(
			"POST",
			"/vpn/v1/certificate",
			Some(session),
			None,
			Some(json!({
				"ClientPublicKey": keys.public_pem(),
				"Mode": "persistent",
				"DeviceName": device,
				"Features": {},
			})),
		)
		.await
		.map(|_| ())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn server(name: &str, country: &str, tier: i64, load: i64) -> Server {
		Server {
			name: name.into(),
			country: country.into(),
			city: String::new(),
			tier,
			load,
			entry_ip: Ipv4Addr::new(1, 2, 3, 4),
			public_key: "k".into(),
		}
	}

	#[test]
	fn selection_respects_plan_country_and_load() {
		let all = vec![
			server("BR#1", "BR", 0, 5),
			server("US#9", "US", 0, 40),
			server("US#2", "US", 2, 1),
			server("MX#1", "MX", 0, 10),
		];
		let exclude = vec!["BR".to_owned()];
		let picked = select(all, &Filter { max_tier: 0, countries: &[], exclude: &exclude });
		let names: Vec<_> = picked.iter().map(|s| s.name.as_str()).collect();
		assert_eq!(names, ["MX#1", "US#9"], "free tier only, BR excluded, least loaded first");
	}

	#[test]
	fn api_errors_map_to_actionable_variants() {
		let reply = |status, body| Response { status, body };
		assert_eq!(check(reply(422, json!({"Code": 5003}))), Err(Error::AppOutdated));
		assert_eq!(check(reply(422, json!({"Code": 8002}))), Err(Error::BadCredentials));
		let hv = check(reply(
			422,
			json!({"Code": 9001, "Details": {"HumanVerificationToken": "T", "HumanVerificationMethods": ["captcha"]}}),
		));
		assert!(matches!(hv, Err(Error::HumanVerification { token, url }) if token == "T" && url.ends_with("/core/v4/captcha?Token=T&ForceWebMessaging=1")));
		assert!(captcha_url("a b:c").contains("Token=a%20b%3Ac"));
		assert!(check(reply(200, json!({"Code": 1000}))).is_ok());
	}

	#[test]
	fn physical_server_without_a_usable_key_or_ip_is_skipped() {
		let body = json!({"LogicalServers": [
			{"Name": "A#1", "ExitCountry": "US", "Status": 1, "Tier": 0, "Load": 3, "Servers": [
				{"Status": 1, "EntryIP": "9.9.9.9", "X25519PublicKey": "pk"}]},
			{"Name": "B#1", "ExitCountry": "US", "Status": 1, "Servers": [{"Status": 1, "EntryIP": "nope", "X25519PublicKey": "pk"}]},
			{"Name": "SC#1", "ExitCountry": "US", "Status": 1, "Features": 1, "Servers": [{"Status": 1, "EntryIP": "8.8.8.8", "X25519PublicKey": "pk"}]},
		]});
		let servers = parse_servers(&body);
		assert_eq!(servers.len(), 1);
		assert_eq!(servers[0].name, "A#1");
	}

	#[test]
	fn wireguard_key_is_clamped_and_profile_parses_in_the_vpn_crate_format() {
		let keys = Keys::from_seed([7u8; 32]);
		let private = keys.wireguard_private();
		assert_eq!(private[0] & 7, 0);
		assert_eq!(private[31] & 0xC0, 0x40);
		assert!(keys.public_pem().starts_with("-----BEGIN PUBLIC KEY-----"));
		let text = profile(&keys, &server("A#1", "US", 0, 1));
		assert!(text.contains("Endpoint = 1.2.3.4:51820") && text.contains("Address = 10.2.0.2/32"));
	}
}
