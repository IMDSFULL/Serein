//! Intent for the in-process WireGuard VPN. The host owns the tunnel and the profile file; the
//! settings page only flips `enabled`, asks for an import and shows the host's `status`.

#[derive(Default)]
pub struct State {
	pub enabled: bool,
	pub status: String,
	pub import_requested: bool,
}
