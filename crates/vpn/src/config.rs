//! `wg-quick` profile parsing (the `.conf` Proton VPN exports). Secrets never reach Debug output.
use base64::{Engine, engine::general_purpose::STANDARD};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use zeroize::Zeroizing;

/// A profile is a few hundred bytes; anything larger is not one.
pub const MAX_PROFILE_BYTES: usize = 16 * 1024;

pub struct Config {
	pub private_key: Zeroizing<[u8; 32]>,
	pub peer_public: [u8; 32],
	pub preshared: Option<Zeroizing<[u8; 32]>>,
	pub address: Ipv4Addr,
	pub dns: Vec<Ipv4Addr>,
	pub endpoint: String,
	pub keepalive: Option<u16>,
	pub mtu: usize,
}

impl std::fmt::Debug for Config {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Config")
			.field("address", &self.address)
			.field("endpoint", &self.endpoint)
			.finish_non_exhaustive()
	}
}

fn key(value: &str) -> Result<[u8; 32], &'static str> {
	STANDARD
		.decode(value.trim())
		.ok()
		.and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
		.ok_or("Invalid WireGuard key")
}

impl Config {
	/// Resolves the peer outside the tunnel, with the system resolver.
	pub fn endpoint_addr(&self) -> Result<SocketAddr, &'static str> {
		self.endpoint
			.to_socket_addrs()
			.map_err(|_| "Could not resolve the VPN endpoint")?
			.find(SocketAddr::is_ipv4)
			.ok_or("The VPN endpoint has no IPv4 address")
	}

	pub fn parse(text: &str) -> Result<Self, &'static str> {
		if text.len() > MAX_PROFILE_BYTES {
			return Err("WireGuard profile is too large");
		}
		let (mut private, mut public, mut preshared) = (None, None, None);
		let (mut address, mut dns, mut endpoint) = (None, Vec::new(), None);
		let (mut keepalive, mut mtu) = (None, 1420usize);
		let mut section = "";
		let mut peers = 0;
		for line in text.lines() {
			let line = line.split('#').next().unwrap_or("").trim();
			if line.is_empty() {
				continue;
			}
			if line.starts_with('[') {
				section = if line.eq_ignore_ascii_case("[interface]") {
					"interface"
				} else if line.eq_ignore_ascii_case("[peer]") {
					peers += 1;
					"peer"
				} else {
					""
				};
				continue;
			}
			let Some((name, value)) = line.split_once('=') else {
				continue;
			};
			let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
			// Only the first peer is used; a second one would need routing by AllowedIPs.
			match (section, name.as_str()) {
				("interface", "privatekey") => private = Some(key(value)?),
				("interface", "address") => {
					// Proton adds an IPv6 address on some profiles; the tunnel is IPv4-only.
					address = value
						.split(',')
						.find_map(|part| part.trim().split('/').next()?.parse::<Ipv4Addr>().ok())
				}
				("interface", "dns") => {
					dns = value
						.split(',')
						.filter_map(|part| part.trim().parse().ok())
						.collect()
				}
				("interface", "mtu") => {
					mtu = value
						.parse()
						.ok()
						.filter(|mtu| (576..=1500).contains(mtu))
						.ok_or("Invalid MTU")?
				}
				("peer", "publickey") if peers == 1 => public = Some(key(value)?),
				("peer", "presharedkey") if peers == 1 => preshared = Some(key(value)?),
				("peer", "endpoint") if peers == 1 => endpoint = Some(value.to_owned()),
				("peer", "persistentkeepalive") if peers == 1 => keepalive = value.parse().ok(),
				_ => {}
			}
		}
		if peers != 1 {
			return Err("The profile must have exactly one [Peer]");
		}
		Ok(Self {
			private_key: Zeroizing::new(private.ok_or("Missing PrivateKey")?),
			peer_public: public.ok_or("Missing peer PublicKey")?,
			preshared: preshared.map(Zeroizing::new),
			address: address.ok_or("Missing IPv4 Address")?,
			dns,
			endpoint: endpoint.ok_or("Missing Endpoint")?,
			keepalive,
			mtu,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	#[test]
	fn proton_profile_parses_and_ignores_ipv6() {
		let text = format!(
			"[Interface]\nPrivateKey = {KEY}\nAddress = 10.2.0.2/32, fd00::2/128\nDNS = 10.2.0.1\n\
			 [Peer]\nPublicKey = {KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n"
		);
		let config = Config::parse(&text).unwrap();
		assert_eq!(config.address, Ipv4Addr::new(10, 2, 0, 2));
		assert_eq!(config.dns, [Ipv4Addr::new(10, 2, 0, 1)]);
		assert_eq!(config.endpoint_addr().unwrap().port(), 51820);
	}

	#[test]
	fn malformed_profiles_are_rejected_without_echoing_secrets() {
		assert!(Config::parse("[Interface]\nPrivateKey = not-base64\n").is_err());
		let two_peers = format!(
			"[Interface]\nPrivateKey = {KEY}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {KEY}\nEndpoint = 1.1.1.1:1\n[Peer]\nPublicKey = {KEY}\n"
		);
		assert!(Config::parse(&two_peers).is_err());
		assert!(Config::parse(&"a".repeat(MAX_PROFILE_BYTES + 1)).is_err());
		let secret = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
		let valid = format!(
			"[Interface]
PrivateKey = {secret}
Address = 10.0.0.2/32
[Peer]
PublicKey = {KEY}
Endpoint = 1.1.1.1:1
"
		);
		assert!(!format!("{:?}", Config::parse(&valid).unwrap()).contains("AQEBAQ"), "Debug must not print keys");
	}
}
