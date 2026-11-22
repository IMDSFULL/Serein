//! Host side of the in-process WireGuard VPN (see the `vpn` crate): the saved profile, the
//! tunnel's startup, and the status line of the settings page.
//!
//! The route is decided once, before the first connection: a tunnel that came up on a running
//! app could not move the Gateway and voice sockets that already exist. Toggling the switch later
//! therefore takes effect after a restart, and the settings page says so.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Tunnel tasks outlive any window or session runtime, so they get their own.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static STARTED: OnceLock<bool> = OnceLock::new();
static STATUS: Mutex<String> = Mutex::new(String::new());
static PROFILE: OnceLock<PathBuf> = OnceLock::new();

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
	let _ = PROFILE.set(profile_path(root));
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

#[derive(Default)]
pub struct Panel {
	picker: Option<mpsc::Receiver<Option<PathBuf>>>,
	notice: Option<String>,
}

impl Panel {
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
		let started = STARTED.get().copied().unwrap_or(false);
		state.status = if state.enabled != started {
			"Restart Serein to apply this change.".to_owned()
		} else if let Some(notice) = &self.notice {
			notice.clone()
		} else {
			STATUS.lock().map(|status| status.clone()).unwrap_or_default()
		};
	}
}

/// Validates before saving, so a bad file never replaces a working profile.
fn import(source: &Path) -> Result<(), &'static str> {
	let target = PROFILE.get().ok_or("Profile storage is unavailable")?;
	read_profile(source)?;
	let directory = target.parent().ok_or("Profile storage is unavailable")?;
	std::fs::create_dir_all(directory).map_err(|_| "Could not create the profile folder")?;
	let temporary = target.with_extension("conf.tmp");
	std::fs::copy(source, &temporary).map_err(|_| "Could not save the profile")?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
	}
	std::fs::rename(&temporary, target).map_err(|_| "Could not save the profile")
}
