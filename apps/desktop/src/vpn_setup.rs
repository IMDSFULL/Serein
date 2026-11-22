//! Host side of the in-process WireGuard VPN (see the `vpn` crate): the saved profile, the
//! tunnel's startup, the Proton sign-in and the status line of the settings page.
//!
//! The route is decided once, before the first connection: a tunnel that came up on a running
//! app could not move the Gateway and voice sockets that already exist. Toggling the switch later
//! therefore takes effect after a restart, and the settings page says so.
use crate::proton_login::{self, Stage};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use ui::vpn_settings::{ProtonAction, ProtonStage};

/// Tunnel tasks outlive any window or session runtime, so they get their own.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static STARTED: OnceLock<bool> = OnceLock::new();
static STATUS: Mutex<String> = Mutex::new(String::new());
static ROOT: OnceLock<PathBuf> = OnceLock::new();

fn set_status(text: impl Into<String>) {
	if let Ok(mut status) = STATUS.lock() {
		*status = text.into();
	}
}

fn profile_path(root: &Path) -> PathBuf {
	root.join("vpn").join("wireguard.conf")
}

fn read_profile(path: &Path) -> Result<vpn::Config, &'static str> {
	let mut text = String::new();
	std::fs::File::open(path)
		.map_err(|_| "No WireGuard profile imported")?
		.take(vpn::MAX_PROFILE_BYTES as u64 + 1)
		.read_to_string(&mut text)
		.map_err(|_| "The WireGuard profile is not readable text")?;
	vpn::Config::parse(&text)
}

/// Brings the tunnel up (or fails closed) before the first network use. Call once, early.
pub fn start_if_enabled(root: &Path, enabled: bool) {
	let _ = ROOT.set(root.to_owned());
	let _ = STARTED.set(enabled);
	if !enabled {
		set_status("Off");
		return;
	}
	// Nothing leaves directly from here on, whatever happens below.
	vpn::set_required(true);
	let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(1)
		.enable_all()
		.build()
	else {
		set_status("The VPN could not start; connections are blocked");
		return;
	};
	let runtime = RUNTIME.get_or_init(|| runtime);
	let path = profile_path(root);
	let result = runtime.block_on(async {
		let config = read_profile(&path)?;
		tokio::time::timeout(Duration::from_secs(15), vpn::Tunnel::start(config))
			.await
			.map_err(|_| "The VPN did not connect in time")?
	});
	match result {
		Ok(tunnel) => {
			vpn::set_active(Some(tunnel));
			set_status("Connected");
		}
		Err(error) => set_status(format!(
			"{error}. Connections are blocked until you fix the profile or turn the VPN off and restart."
		)),
	}
}

/// Atomic, owner-only write of a secret file.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
	let directory = path.parent().ok_or("Profile storage is unavailable")?;
	std::fs::create_dir_all(directory).map_err(|_| "Could not create the profile folder")?;
	let temporary = path.with_extension("tmp");
	std::fs::write(&temporary, bytes).map_err(|_| "Could not save the profile")?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
	}
	std::fs::rename(&temporary, path).map_err(|_| "Could not save the profile")
}

/// Validates before saving, so a bad profile never replaces a working one.
pub fn save_profile(root: &Path, text: &[u8]) -> Result<(), &'static str> {
	let parsed = std::str::from_utf8(text).map_err(|_| "The WireGuard profile is not readable text")?;
	vpn::Config::parse(parsed)?;
	write_private(&profile_path(root), text)
}

fn import(source: &Path) -> Result<(), &'static str> {
	let root = ROOT.get().ok_or("Profile storage is unavailable")?;
	let mut bytes = Vec::new();
	std::fs::File::open(source)
		.map_err(|_| "The profile could not be read")?
		.take(vpn::MAX_PROFILE_BYTES as u64 + 1)
		.read_to_end(&mut bytes)
		.map_err(|_| "The profile could not be read")?;
	save_profile(root, &bytes)
}

#[derive(Default)]
pub struct Panel {
	picker: Option<mpsc::Receiver<Option<PathBuf>>>,
	notice: Option<String>,
	proton: Option<proton_login::Handle>,
	captcha: Option<platform::proton_captcha::ProtonCaptcha>,
}

impl Panel {
	fn cancel_proton(&mut self) {
		if let Some(shared) = &self.proton
			&& let Ok(mut guard) = shared.lock()
		{
			guard.cancelled = true;
		}
		self.captcha = None;
		self.proton = None;
	}

	pub fn tick(
		&mut self,
		state: &mut ui::vpn_settings::State,
		ctx: &eframe::egui::Context,
		runtime: &tokio::runtime::Runtime,
		window: &Arc<winit::window::Window>,
	) {
		if state.import_requested {
			state.import_requested = false;
			if self.picker.is_none() {
				let (send, receive) = mpsc::sync_channel(1);
				let future = platform::save::vpn_profile_source(window.clone());
				let ctx = ctx.clone();
				runtime.spawn(async move {
					let _ = send.send(future.await);
					ctx.request_repaint();
				});
				self.picker = Some(receive);
			}
		}
		if let Some(receive) = &self.picker
			&& let Ok(choice) = receive.try_recv()
		{
			self.picker = None;
			if let Some(path) = choice {
				self.notice = Some(match import(&path) {
					Ok(()) => "Profile imported. Restart Serein to connect.".to_owned(),
					Err(error) => error.to_owned(),
				});
			}
		}
		self.tick_proton(state, ctx, runtime, window);
		let started = STARTED.get().copied().unwrap_or(false);
		state.status = if state.enabled != started {
			"Restart Serein to apply this change.".to_owned()
		} else if let Some(notice) = &self.notice {
			notice.clone()
		} else {
			STATUS.lock().map(|status| status.clone()).unwrap_or_default()
		};
	}

	fn tick_proton(
		&mut self,
		state: &mut ui::vpn_settings::State,
		ctx: &eframe::egui::Context,
		runtime: &tokio::runtime::Runtime,
		window: &Arc<winit::window::Window>,
	) {
		match state.proton_action.take() {
			Some(ProtonAction::SignIn) if self.proton.is_none() => match ROOT.get() {
				Some(root) => {
					let shared = Arc::new(Mutex::new(proton_login::Shared::default()));
					let request = proton_login::SignIn {
						username: state.proton_user.trim().to_owned(),
						// Moved out of the form: the task owns the only copy from here.
						password: std::mem::take(&mut state.proton_password),
						countries: proton_login::countries(&state.proton_countries),
						root: root.clone(),
					};
					let wake = ctx.clone();
					runtime.spawn(proton_login::run(request, shared.clone(), move || wake.request_repaint()));
					self.proton = Some(shared);
					self.notice = Some("Signing in to Proton…".to_owned());
				}
				None => self.notice = Some("Profile storage is unavailable".to_owned()),
			},
			Some(ProtonAction::SendCode) => {
				if let Some(shared) = &self.proton
					&& let Ok(mut guard) = shared.lock()
				{
					guard.code = Some(std::mem::take(&mut state.proton_code));
				}
			}
			Some(ProtonAction::Cancel) => {
				self.cancel_proton();
				state.proton_stage = ProtonStage::Idle;
				self.notice = Some("Cancelled.".to_owned());
			}
			_ => {}
		}
		let Some(shared) = self.proton.clone() else {
			state.proton_stage = ProtonStage::Idle;
			return;
		};
		let stage = shared.lock().map(|guard| guard.stage.clone()).unwrap_or_default();
		match stage {
			Stage::Idle => {}
			Stage::Working(text) => {
				state.proton_stage = ProtonStage::Working;
				self.notice = Some(text);
			}
			Stage::NeedCode => {
				state.proton_stage = ProtonStage::NeedCode;
				self.notice = Some("Enter the code from your authenticator app.".to_owned());
			}
			Stage::NeedCaptcha { url, challenge } => {
				state.proton_stage = ProtonStage::NeedCaptcha;
				self.notice = Some("Proton asks you to complete a verification.".to_owned());
				if self.captcha.is_none() {
					let wake = ctx.clone();
					match platform::proton_captcha::ProtonCaptcha::open(window.clone(), &url, &challenge, move || {
						wake.request_repaint()
					}) {
						Ok(view) => self.captcha = Some(view),
						Err(error) => {
							if let Ok(mut guard) = shared.lock() {
								guard.stage = Stage::Failed(error.to_owned());
							}
						}
					}
				}
				if let Some(view) = &self.captcha {
					let size = window.inner_size();
					let (width, height) = (size.width.min(640), size.height.min(720));
					view.set_bounds(
						(size.width.saturating_sub(width) / 2) as i32,
						(size.height.saturating_sub(height) / 2) as i32,
						width,
						height,
					);
					if let Some(token) = view.poll() {
						if let Ok(mut guard) = shared.lock() {
							guard.human = Some(proton::HumanToken { token, kind: "captcha".to_owned() });
						}
						self.captcha = None;
					} else if view.expired() {
						self.cancel_proton();
						state.proton_stage = ProtonStage::Idle;
						self.notice = Some("The verification timed out.".to_owned());
					}
				}
				ctx.request_repaint_after(Duration::from_millis(250));
			}
			Stage::Done(message) | Stage::Failed(message) => {
				self.captcha = None;
				self.proton = None;
				state.proton_stage = ProtonStage::Idle;
				self.notice = Some(message);
			}
		}
	}
}
