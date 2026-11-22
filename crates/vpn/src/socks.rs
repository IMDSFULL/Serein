//! Loopback SOCKS5 (CONNECT only) in front of the tunnel, for clients that can only dial through
//! a proxy (wreq's REST and WebSocket stacks). It demands the per-run password, so another
//! program on this machine cannot borrow the VPN.
use crate::Core;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CLIENTS: usize = 64;

pub(crate) async fn serve(listener: TcpListener, core: Arc<Core>, secret: zeroize::Zeroizing<String>) {
	let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
	let secret: Arc<str> = Arc::from(secret.as_str());
	while let Ok((stream, peer)) = listener.accept().await {
		if !peer.ip().is_loopback() {
			continue;
		}
		let Ok(permit) = slots.clone().try_acquire_owned() else {
			continue;
		};
		let (core, secret) = (core.clone(), secret.clone());
		tokio::spawn(async move {
			let _ = client(stream, &core, &secret).await;
			drop(permit);
		});
	}
}

async fn client(mut stream: TcpStream, core: &Core, secret: &str) -> std::io::Result<()> {
	let target = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
		// Greeting: only username/password (2) is offered.
		let mut head = [0u8; 2];
		stream.read_exact(&mut head).await?;
		let mut methods = vec![0u8; head[1] as usize];
		stream.read_exact(&mut methods).await?;
		if head[0] != 5 || !methods.contains(&2) {
			stream.write_all(&[5, 0xFF]).await?;
			return Err(std::io::Error::other("method"));
		}
		stream.write_all(&[5, 2]).await?;
		let mut auth = [0u8; 2];
		stream.read_exact(&mut auth).await?;
		let mut user = vec![0u8; auth[1] as usize];
		stream.read_exact(&mut user).await?;
		let mut length = [0u8; 1];
		stream.read_exact(&mut length).await?;
		let mut password = vec![0u8; length[0] as usize];
		stream.read_exact(&mut password).await?;
		if auth[0] != 1 || password != secret.as_bytes() {
			stream.write_all(&[1, 1]).await?;
			return Err(std::io::Error::other("auth"));
		}
		stream.write_all(&[1, 0]).await?;
		// Request: CONNECT to IPv4 or a name.
		let mut request = [0u8; 4];
		stream.read_exact(&mut request).await?;
		let host = match (request[0], request[1], request[3]) {
			(5, 1, 1) => {
				let mut octets = [0u8; 4];
				stream.read_exact(&mut octets).await?;
				Ipv4Addr::from(octets).to_string()
			}
			(5, 1, 3) => {
				let mut length = [0u8; 1];
				stream.read_exact(&mut length).await?;
				let mut name = vec![0u8; length[0] as usize];
				stream.read_exact(&mut name).await?;
				String::from_utf8(name).map_err(|_| std::io::Error::other("name"))?
			}
			_ => {
				stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
				return Err(std::io::Error::other("unsupported"));
			}
		};
		let mut port = [0u8; 2];
		stream.read_exact(&mut port).await?;
		Ok((host, u16::from_be_bytes(port)))
	})
	.await
	.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake"))??;
	let remote = async {
		let address = core.resolve(&target.0).await?;
		core.tcp(SocketAddrV4::new(address, target.1)).await
	}
	.await;
	let Ok(mut remote) = remote else {
		stream.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
		return Ok(());
	};
	stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
	tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
	Ok(())
}
