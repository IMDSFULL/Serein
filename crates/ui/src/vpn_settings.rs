//! Intent for the in-process WireGuard VPN. The host owns the tunnel, the profile file and the
//! Proton sign-in; the settings page only edits these fields and shows the host's status.
use zeroize::Zeroizing;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum ProtonStage {
	#[default]
	Idle,
	Working,
	NeedCode,
	NeedCaptcha,
}

pub enum ProtonAction {
	SignIn,
	SendCode,
	Cancel,
}

#[derive(Default)]
pub struct State {
	pub enabled: bool,
	pub status: String,
	pub import_requested: bool,
	pub proton_user: String,
	pub proton_password: Zeroizing<String>,
	/// Comma-separated ISO country codes; empty means any (Brazil is always left out).
	pub proton_countries: String,
	pub proton_code: String,
	pub proton_stage: ProtonStage,
	/// Set by the page, taken by the host.
	pub proton_action: Option<ProtonAction>,
}
