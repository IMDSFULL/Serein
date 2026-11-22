//! Proton's CAPTCHA page in a temporary child webview of the main window. Only the CAPTCHA
//! answer leaves it; the page is locked to Proton's origin and the captcha providers it embeds.
use std::sync::Arc;

const MAX_ANSWER: usize = 16 * 1024;

fn host_in(host: &str, domain: &str) -> bool {
	host == domain || host.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.'))
}

/// Only Proton's own CAPTCHA route may be opened.
pub fn challenge_url_ok(value: &str) -> bool {
	url::Url::parse(value).is_ok_and(|url| {
		url.scheme() == "https"
			&& url.host_str().is_some_and(|host| host_in(host, "proton.me"))
			&& url.path() == "/core/v4/captcha"
	})
}

/// Pages the CAPTCHA may load or frame: Proton, and the providers it embeds.
fn navigation_ok(value: &str) -> bool {
	if value == "about:blank" {
		return true;
	}
	url::Url::parse(value).is_ok_and(|url| {
		url.scheme() == "https"
			&& url.host_str().is_some_and(|host| {
				["proton.me", "hcaptcha.com", "google.com", "gstatic.com", "recaptcha.net"]
					.iter()
					.any(|domain| host_in(host, domain))
			})
	})
}

/// The page answers `"<challenge>:<solution>"`; anything else is not this challenge's answer.
pub fn answer_ok(token: &str, challenge: &str) -> bool {
	token.len() <= MAX_ANSWER
		&& token
			.strip_prefix(challenge)
			.is_some_and(|rest| rest.starts_with(':') && rest.len() > 1)
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod imp {
	use super::*;
	use std::sync::mpsc::{self, Receiver};
	use std::time::{Duration, Instant};
	use wry::{WebView, WebViewBuilder};

	const SCRIPT: &str = r#"window.addEventListener('message', function (event) {
	var data = event.data;
	if (data && (data.type === 'pm_captcha' || data.type === 'proton_captcha') && typeof data.token === 'string') {
		window.ipc.postMessage(data.token);
	}
});"#;

	pub struct ProtonCaptcha {
		view: WebView,
		results: Receiver<String>,
		opened: Instant,
	}

	impl ProtonCaptcha {
		pub fn open(
			parent: Arc<winit::window::Window>,
			url: &str,
			challenge: &str,
			wake: impl Fn() + Send + Sync + 'static,
		) -> Result<Self, &'static str> {
			if !challenge_url_ok(url) {
				return Err("Proton's verification address was not recognised.");
			}
			let (send, results) = mpsc::sync_channel(1);
			let challenge = challenge.to_owned();
			let view = WebViewBuilder::new()
				.with_visible(false)
				.with_incognito(true)
				.with_devtools(false)
				.with_initialization_script(SCRIPT)
				.with_navigation_handler(|target| navigation_ok(&target))
				.with_new_window_req_handler(|_, _| wry::NewWindowResponse::Deny)
				.with_download_started_handler(|_, _| false)
				.with_ipc_handler(move |request| {
					// Messages count only from Proton's own page, never from a frame it embeds.
					if !challenge_url_ok(&request.uri().to_string()) {
						return;
					}
					let answer = zeroize::Zeroizing::new(request.into_body());
					if answer_ok(&answer, &challenge) && send.try_send(answer.to_string()).is_ok() {
						wake();
					}
				})
				.with_url(url)
				.build_as_child(parent.as_ref())
				.map_err(|_| "The native verification window could not open.")?;
			Ok(Self { view, results, opened: Instant::now() })
		}
		pub fn set_bounds(&self, x: i32, y: i32, width: u32, height: u32) {
			if self
				.view
				.set_bounds(wry::Rect {
					position: wry::dpi::PhysicalPosition::new(x, y).into(),
					size: wry::dpi::PhysicalSize::new(width, height).into(),
				})
				.is_ok()
			{
				let _ = self.view.set_visible(width > 0 && height > 0);
			}
		}
		pub fn poll(&self) -> Option<String> {
			self.results.try_recv().ok()
		}
		pub fn expired(&self) -> bool {
			self.opened.elapsed() >= Duration::from_secs(300)
		}
	}
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod imp {
	use super::*;
	pub struct ProtonCaptcha;
	impl ProtonCaptcha {
		pub fn open(
			_: Arc<winit::window::Window>,
			_: &str,
			_: &str,
			_: impl Fn() + Send + Sync + 'static,
		) -> Result<Self, &'static str> {
			Err("The Proton verification window is not available on this system; import a .conf instead.")
		}
		pub fn set_bounds(&self, _: i32, _: i32, _: u32, _: u32) {}
		pub fn poll(&self) -> Option<String> {
			None
		}
		pub fn expired(&self) -> bool {
			true
		}
	}
}

pub use imp::ProtonCaptcha;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_protons_captcha_route_and_matching_answers_are_accepted() {
		assert!(challenge_url_ok("https://vpn-api.proton.me/core/v4/captcha?Token=abc"));
		assert!(!challenge_url_ok("https://vpn-api.proton.me.evil.test/core/v4/captcha?Token=abc"));
		assert!(!challenge_url_ok("https://evilproton.me/core/v4/captcha"));
		assert!(!challenge_url_ok("http://proton.me/core/v4/captcha"));
		assert!(!challenge_url_ok("https://proton.me/other"));
		assert!(answer_ok("chal:solved", "chal"));
		assert!(!answer_ok("chal:", "chal"));
		assert!(!answer_ok("other:solved", "chal"));
		assert!(!answer_ok(&format!("chal:{}", "x".repeat(MAX_ANSWER)), "chal"));
		assert!(navigation_ok("https://newassets.hcaptcha.com/captcha/v1"));
		assert!(!navigation_ok("https://hcaptcha.com.evil.test/"));
	}
}
