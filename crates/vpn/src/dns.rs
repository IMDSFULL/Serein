//! Minimal A-record lookup over the tunnel, so hostnames never leak to the local resolver.
use crate::Core;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

fn query(id: u16, host: &str) -> Option<Vec<u8>> {
	let mut packet = Vec::with_capacity(32 + host.len());
	packet.extend_from_slice(&id.to_be_bytes());
	packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, one question
	for label in host.trim_end_matches('.').split('.') {
		if label.is_empty() || label.len() > 63 || !label.is_ascii() {
			return None;
		}
		packet.push(label.len() as u8);
		packet.extend_from_slice(label.as_bytes());
	}
	packet.extend_from_slice(&[0, 0, 1, 0, 1]); // root, A, IN
	(packet.len() <= 512).then_some(packet)
}

fn skip_name(packet: &[u8], mut at: usize) -> Option<usize> {
	loop {
		let length = *packet.get(at)? as usize;
		if length & 0xC0 == 0xC0 {
			return Some(at + 2);
		}
		if length == 0 {
			return Some(at + 1);
		}
		at += 1 + length;
	}
}

/// First A record of a response to `id`, if any. Bounds-checked: the peer is the network.
fn answer(packet: &[u8], id: u16) -> Option<Ipv4Addr> {
	if packet.len() < 12 || packet[..2] != id.to_be_bytes() || packet[2] & 0x80 == 0 {
		return None;
	}
	let questions = u16::from_be_bytes([packet[4], packet[5]]);
	let answers = u16::from_be_bytes([packet[6], packet[7]]);
	let mut at = 12;
	for _ in 0..questions {
		at = skip_name(packet, at)? + 4;
	}
	for _ in 0..answers {
		at = skip_name(packet, at)?;
		let header = packet.get(at..at + 10)?;
		let (kind, length) = (
			u16::from_be_bytes([header[0], header[1]]),
			u16::from_be_bytes([header[8], header[9]]) as usize,
		);
		let data = packet.get(at + 10..at + 10 + length)?;
		if kind == 1 && length == 4 {
			return Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
		}
		at += 10 + length;
	}
	None
}

pub(crate) async fn resolve(core: &Core, server: SocketAddrV4, host: &str) -> io::Result<Ipv4Addr> {
	let mut random = [0u8; 2];
	getrandom::fill(&mut random).map_err(io::Error::other)?;
	let id = u16::from_be_bytes(random);
	let request = query(id, host).ok_or_else(|| io::Error::other("Invalid host name"))?;
	let socket = core.udp(server).await?;
	let mut buffer = [0u8; 1500];
	for _ in 0..3 {
		socket.send(&request).await?;
		let wait = async {
			loop {
				let n = socket.recv(&mut buffer).await?;
				if let Some(address) = answer(&buffer[..n], id) {
					return Ok::<_, io::Error>(address);
				}
			}
		};
		if let Ok(result) = tokio::time::timeout(Duration::from_secs(2), wait).await {
			return result;
		}
	}
	Err(io::Error::new(io::ErrorKind::TimedOut, "VPN DNS lookup timed out"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_compressed_a_answer_and_rejects_truncated_or_foreign_packets() {
		let mut response = query(7, "a.io").unwrap();
		response[2] |= 0x80;
		response[7] = 1; // one answer
		response.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 9, 8, 7, 6]);
		assert_eq!(answer(&response, 7), Some(Ipv4Addr::new(9, 8, 7, 6)));
		assert_eq!(answer(&response, 8), None, "foreign transaction id");
		assert_eq!(answer(&response[..response.len() - 2], 7), None, "truncated record");
		assert!(query(1, &format!("{}.io", "a".repeat(64))).is_none());
	}
}
