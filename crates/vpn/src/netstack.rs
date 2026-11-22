//! Userspace WireGuard (boringtun) feeding a userspace TCP/UDP stack (smoltcp). Nothing here
//! touches the OS routing table or needs elevation: only sockets opened through [`Handle`] use
//! the tunnel, everything else in the process and on the machine stays on the normal network.
use crate::Config;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, oneshot};

/// Bounds: the stack serves one chat client, not a router.
const MAX_CONNECTIONS: usize = 128;
const MAX_QUEUED_PACKETS: usize = 512;
const TCP_BUFFER: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
const CHANNEL_DEPTH: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Request {
	pub kind: Kind,
	pub reply: oneshot::Sender<io::Result<Conn>>,
}
pub(crate) enum Kind {
	Tcp(SocketAddrV4),
	Udp(SocketAddrV4),
}
pub(crate) enum Conn {
	Tcp(DuplexStream),
	Udp(crate::UdpConn),
}

/// Cloneable entry point of a running stack.
pub(crate) struct Handle {
	pub requests: mpsc::Sender<Request>,
	pub up: Arc<AtomicBool>,
}

struct Queue {
	rx: VecDeque<Vec<u8>>,
	tx: VecDeque<Vec<u8>>,
	mtu: usize,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for Rx {
	fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
		f(&self.0)
	}
}
impl TxToken for Tx<'_> {
	fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
		let mut packet = vec![0; len];
		let result = f(&mut packet);
		self.0.push_back(packet);
		result
	}
}
impl Device for Queue {
	type RxToken<'a> = Rx;
	type TxToken<'a> = Tx<'a>;
	fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
		let packet = self.rx.pop_front()?;
		Some((Rx(packet), Tx(&mut self.tx)))
	}
	fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
		(self.tx.len() < MAX_QUEUED_PACKETS).then(|| Tx(&mut self.tx))
	}
	fn capabilities(&self) -> DeviceCapabilities {
		let mut capabilities = DeviceCapabilities::default();
		capabilities.medium = Medium::Ip;
		capabilities.max_transmission_unit = self.mtu;
		capabilities
	}
}

struct Entry {
	handle: SocketHandle,
	/// Delivers received bytes/datagrams to the application; dropped to signal end of stream.
	to_app: Option<mpsc::Sender<Vec<u8>>>,
	from_app: mpsc::Receiver<Vec<u8>>,
	pending: Vec<u8>,
	sent: usize,
	app_done: bool,
	started: Instant,
	connecting: Option<(DuplexStream, oneshot::Sender<io::Result<Conn>>)>,
	/// Set for UDP entries: the single peer a datagram socket talks to.
	remote: Option<IpEndpoint>,
}

fn smol_now(start: Instant) -> SmolInstant {
	SmolInstant::from_micros(start.elapsed().as_micros() as i64)
}

fn endpoint(address: SocketAddrV4) -> IpEndpoint {
	IpEndpoint::new(IpAddress::Ipv4(*address.ip()), address.port())
}

pub(crate) async fn start(config: Config) -> Result<(Handle, tokio::task::JoinHandle<()>), &'static str> {
	let endpoint_addr = config.endpoint_addr()?;
	let outer = UdpSocket::bind("0.0.0.0:0")
		.await
		.map_err(|_| "Could not open the VPN socket")?;
	outer
		.connect(endpoint_addr)
		.await
		.map_err(|_| "Could not reach the VPN endpoint")?;
	let mut index = [0u8; 4];
	getrandom::fill(&mut index).map_err(|_| "No system randomness")?;
	let tunn = Tunn::new(
		StaticSecret::from(*config.private_key),
		PublicKey::from(config.peer_public),
		config.preshared.as_deref().copied(),
		config.keepalive.or(Some(25)),
		u32::from_le_bytes(index),
		None,
	);
	let up = Arc::new(AtomicBool::new(false));
	let (requests, receiver) = mpsc::channel(32);
	let task = tokio::spawn(run(config.address, config.mtu, tunn, outer, receiver, up.clone()));
	Ok((Handle { requests, up }, task))
}

async fn run(
	address: Ipv4Addr,
	mtu: usize,
	mut tunn: Tunn,
	outer: UdpSocket,
	mut requests: mpsc::Receiver<Request>,
	up: Arc<AtomicBool>,
) {
	let origin = Instant::now();
	let mut device = Queue {
		rx: VecDeque::new(),
		tx: VecDeque::new(),
		mtu,
	};
	let mut iface = Interface::new(
		IfaceConfig::new(HardwareAddress::Ip),
		&mut device,
		smol_now(origin),
	);
	iface.update_ip_addrs(|addresses| {
		let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(address), 32));
	});
	// Medium::Ip never resolves a next hop, so any gateway address routes everything.
	let _ = iface.routes_mut().add_default_ipv4_route(address);
	let mut sockets = SocketSet::new(Vec::new());
	let mut entries: Vec<Entry> = Vec::new();
	let notify = Arc::new(Notify::new());
	let mut next_port: u16 = 49152;
	let mut datagram = vec![0u8; 2048];
	let mut scratch = vec![0u8; 2048];
	let mut timers = tokio::time::interval(Duration::from_millis(250));
	timers.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

	// Starts the handshake right away so `start` can report a dead endpoint quickly.
	if let TunnResult::WriteToNetwork(packet) = tunn.format_handshake_initiation(&mut scratch, false) {
		let _ = outer.send(packet).await;
	}
	loop {
		let delay = if entries.is_empty() {
			Duration::from_millis(250)
		} else {
			iface
				.poll_delay(smol_now(origin), &sockets)
				.map_or(Duration::from_millis(20), |d| Duration::from_micros(d.total_micros()))
				.clamp(Duration::from_millis(1), Duration::from_millis(20))
		};
		tokio::select! {
			received = outer.recv(&mut datagram) => {
				let Ok(length) = received else { break };
				let mut input: &[u8] = &datagram[..length];
				// A handshake reply or queued packet may need several decapsulate calls.
				loop {
					match tunn.decapsulate(None, input, &mut scratch) {
						TunnResult::WriteToNetwork(reply) => { let _ = outer.send(reply).await; input = &[]; }
						TunnResult::WriteToTunnelV4(packet, _) => {
							if device.rx.len() < MAX_QUEUED_PACKETS { device.rx.push_back(packet.to_vec()); }
							break;
						}
						_ => break,
					}
				}
			}
			request = requests.recv() => {
				let Some(request) = request else { break };
				if entries.len() >= MAX_CONNECTIONS {
					let _ = request.reply.send(Err(io::Error::other("Too many VPN connections")));
				} else {
					next_port = if next_port == u16::MAX { 49152 } else { next_port + 1 };
					open(request, &mut iface, &mut sockets, &mut entries, next_port, &notify);
				}
			}
			_ = notify.notified() => {}
			_ = timers.tick() => {
				if let TunnResult::WriteToNetwork(packet) = tunn.update_timers(&mut scratch) {
					let _ = outer.send(packet).await;
				}
			}
			_ = tokio::time::sleep(delay) => {}
		}
		up.store(tunn.time_since_last_handshake().is_some(), Ordering::Relaxed);
		for _ in 0..2 {
			iface.poll(smol_now(origin), &mut device, &mut sockets);
			service(&mut entries, &mut sockets);
		}
		while let Some(packet) = device.tx.pop_front() {
			if let TunnResult::WriteToNetwork(out) = tunn.encapsulate(&packet, &mut scratch) {
				let _ = outer.send(out).await;
			}
		}
	}
}

fn open(
	request: Request,
	iface: &mut Interface,
	sockets: &mut SocketSet<'static>,
	entries: &mut Vec<Entry>,
	port: u16,
	notify: &Arc<Notify>,
) {
	let (to_app, from_net) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
	let (to_net, from_app) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
	match request.kind {
		Kind::Tcp(remote) => {
			let mut socket = tcp::Socket::new(
				tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
				tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
			);
			if socket.connect(iface.context(), endpoint(remote), port).is_err() {
				let _ = request.reply.send(Err(io::Error::other("VPN connect failed")));
				return;
			}
			let (app, net) = tokio::io::duplex(TCP_BUFFER);
			let (mut read, mut write) = tokio::io::split(net);
			let wake = notify.clone();
			tokio::spawn(async move {
				let mut buffer = vec![0u8; CHUNK];
				while let Ok(n) = read.read(&mut buffer).await {
					if n == 0 || to_net.send(buffer[..n].to_vec()).await.is_err() {
						break;
					}
					wake.notify_one();
				}
				// Dropping `to_net` tells the stack the application finished writing.
				drop(to_net);
				wake.notify_one();
			});
			tokio::spawn(async move {
				let mut from_net = from_net;
				while let Some(chunk) = from_net.recv().await {
					if write.write_all(&chunk).await.is_err() {
						return;
					}
				}
				let _ = write.shutdown().await;
			});
			entries.push(Entry {
				handle: sockets.add(socket),
				to_app: Some(to_app),
				from_app,
				pending: Vec::new(),
				sent: 0,
				app_done: false,
				started: Instant::now(),
				connecting: Some((app, request.reply)),
				remote: None,
			});
		}
		Kind::Udp(remote) => {
			let mut socket = udp::Socket::new(
				udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 64 * 1024]),
				udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 64 * 1024]),
			);
			if socket.bind(port).is_err() {
				let _ = request.reply.send(Err(io::Error::other("VPN bind failed")));
				return;
			}
			let conn = crate::UdpConn::new(to_net, from_net, notify.clone());
			let _ = request.reply.send(Ok(Conn::Udp(conn)));
			entries.push(Entry {
				handle: sockets.add(socket),
				to_app: Some(to_app),
				from_app,
				pending: Vec::new(),
				sent: 0,
				app_done: false,
				started: Instant::now(),
				connecting: None,
				remote: Some(endpoint(remote)),
			});
		}
	}
}

/// Moves bytes between each smoltcp socket and its application channels, and reaps dead ones.
fn service(entries: &mut Vec<Entry>, sockets: &mut SocketSet<'static>) {
	entries.retain_mut(|entry| {
		if let Some(remote) = entry.remote {
			return service_udp(entry, sockets, remote);
		}
		let socket = sockets.get_mut::<tcp::Socket>(entry.handle);
		if let Some((_, _)) = &entry.connecting {
			if socket.state() == tcp::State::Established {
				let (app, reply) = entry.connecting.take().unwrap();
				let _ = reply.send(Ok(Conn::Tcp(app)));
			} else if socket.state() == tcp::State::Closed || entry.started.elapsed() > CONNECT_TIMEOUT {
				let (_, reply) = entry.connecting.take().unwrap();
				let _ = reply.send(Err(io::Error::new(io::ErrorKind::TimedOut, "VPN connect failed")));
				socket.abort();
				sockets.remove(entry.handle);
				return false;
			} else {
				return true;
			}
		}
		// Network -> application. A full channel leaves bytes in smoltcp, which throttles the peer.
		while let Some(sender) = &entry.to_app {
			if !socket.can_recv() {
				break;
			}
			let Ok(permit) = sender.try_reserve() else { break };
			let chunk = socket
				.recv(|buffer| {
					let n = buffer.len().min(CHUNK);
					(n, buffer[..n].to_vec())
				})
				.unwrap_or_default();
			permit.send(chunk);
		}
		if !socket.may_recv() && !socket.can_recv() {
			entry.to_app = None;
		}
		// Application -> network.
		if entry.sent == entry.pending.len() {
			entry.pending.clear();
			entry.sent = 0;
			match entry.from_app.try_recv() {
				Ok(chunk) => entry.pending = chunk,
				Err(mpsc::error::TryRecvError::Disconnected) => entry.app_done = true,
				Err(mpsc::error::TryRecvError::Empty) => {}
			}
		}
		while entry.sent < entry.pending.len() && socket.can_send() {
			match socket.send_slice(&entry.pending[entry.sent..]) {
				Ok(0) | Err(_) => break,
				Ok(n) => entry.sent += n,
			}
		}
		if entry.app_done && entry.sent == entry.pending.len() && socket.may_send() {
			socket.close();
		}
		match socket.state() {
			tcp::State::Closed | tcp::State::TimeWait => {
				sockets.remove(entry.handle);
				false
			}
			_ => true,
		}
	});
}

fn service_udp(entry: &mut Entry, sockets: &mut SocketSet<'static>, remote: IpEndpoint) -> bool {
	let socket = sockets.get_mut::<udp::Socket>(entry.handle);
	let mut buffer = [0u8; 2048];
	while let Ok((n, _)) = socket.recv_slice(&mut buffer) {
		// Datagrams are lossy by contract: a slow reader loses the newest.
		if let Some(sender) = &entry.to_app {
			let _ = sender.try_send(buffer[..n].to_vec());
		}
	}
	loop {
		match entry.from_app.try_recv() {
			Ok(datagram) => {
				let _ = socket.send_slice(&datagram, remote);
			}
			Err(mpsc::error::TryRecvError::Empty) => return true,
			Err(mpsc::error::TryRecvError::Disconnected) => {
				sockets.remove(entry.handle);
				return false;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Tunnel;
	use zeroize::Zeroizing;

	/// The far side of the tunnel: its own WireGuard peer and TCP/IP stack, echoing TCP:80 and UDP:53.
	async fn echo_peer(socket: UdpSocket, mut tunn: Tunn, address: Ipv4Addr) {
		let origin = Instant::now();
		let mut device = Queue { rx: VecDeque::new(), tx: VecDeque::new(), mtu: 1420 };
		let mut iface = Interface::new(IfaceConfig::new(HardwareAddress::Ip), &mut device, smol_now(origin));
		iface.update_ip_addrs(|a| {
			let _ = a.push(IpCidr::new(IpAddress::Ipv4(address), 32));
		});
		let _ = iface.routes_mut().add_default_ipv4_route(address);
		let mut sockets = SocketSet::new(Vec::new());
		let tcp_handle = sockets.add(tcp::Socket::new(
			tcp::SocketBuffer::new(vec![0; 8192]),
			tcp::SocketBuffer::new(vec![0; 8192]),
		));
		let mut udp_socket = udp::Socket::new(
			udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]),
			udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]),
		);
		udp_socket.bind(53).unwrap();
		let udp_handle = sockets.add(udp_socket);
		let (mut client, mut datagram, mut scratch) = (None, vec![0u8; 2048], vec![0u8; 2048]);
		let mut pending = Vec::new();
		loop {
			if let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_millis(3), socket.recv_from(&mut datagram)).await {
				client = Some(from);
				let mut input: &[u8] = &datagram[..n];
				loop {
					match tunn.decapsulate(None, input, &mut scratch) {
						TunnResult::WriteToNetwork(reply) => { let _ = socket.send_to(reply, from).await; input = &[]; }
						TunnResult::WriteToTunnelV4(packet, _) => { device.rx.push_back(packet.to_vec()); break; }
						_ => break,
					}
				}
			}
			if let TunnResult::WriteToNetwork(packet) = tunn.update_timers(&mut scratch) && let Some(to) = client {
				let _ = socket.send_to(packet, to).await;
			}
			iface.poll(smol_now(origin), &mut device, &mut sockets);
			let listener = sockets.get_mut::<tcp::Socket>(tcp_handle);
			if !listener.is_open() {
				listener.listen(80).unwrap();
			}
			if listener.can_recv() && pending.len() < 4096 {
				let mut chunk = [0u8; 2048];
				if let Ok(n) = listener.recv_slice(&mut chunk) { pending.extend_from_slice(&chunk[..n]); }
			}
			if !pending.is_empty() && listener.can_send() {
				let sent = listener.send_slice(&pending).unwrap_or(0);
				pending.drain(..sent);
			}
			if listener.state() == tcp::State::CloseWait && pending.is_empty() { listener.close(); }
			let echo = sockets.get_mut::<udp::Socket>(udp_handle);
			let mut buffer = [0u8; 1500];
			while let Ok((n, meta)) = echo.recv_slice(&mut buffer) {
				let _ = echo.send_slice(&buffer[..n], meta.endpoint);
			}
			iface.poll(smol_now(origin), &mut device, &mut sockets);
			while let Some(packet) = device.tx.pop_front() {
				if let (TunnResult::WriteToNetwork(out), Some(to)) = (tunn.encapsulate(&packet, &mut scratch), client) {
					let _ = socket.send_to(out, to).await;
				}
			}
		}
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn tcp_and_udp_round_trip_through_a_wireguard_peer() {
		let (mut a, mut b) = ([7u8; 32], [9u8; 32]);
		a[0] = 1;
		b[0] = 2;
		let (secret_a, secret_b) = (StaticSecret::from(a), StaticSecret::from(b));
		let (public_a, public_b) = (PublicKey::from(&secret_a), PublicKey::from(&secret_b));
		let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let port = socket.local_addr().unwrap().port();
		let peer = Tunn::new(secret_b, public_a, None, None, 2, None);
		let peer_task = tokio::spawn(echo_peer(socket, peer, Ipv4Addr::new(10, 0, 0, 1)));
		let config = Config {
			private_key: Zeroizing::new(a),
			peer_public: public_b.to_bytes(),
			preshared: None,
			address: Ipv4Addr::new(10, 0, 0, 2),
			dns: vec![Ipv4Addr::new(10, 0, 0, 1)],
			endpoint: format!("127.0.0.1:{port}"),
			keepalive: Some(1),
			mtu: 1420,
		};
		let tunnel = Tunnel::start(config).await.unwrap();
		let server = Ipv4Addr::new(10, 0, 0, 1);

		let udp = tunnel.udp(SocketAddrV4::new(server, 53)).await.unwrap();
		udp.send(b"ping").await.unwrap();
		let mut buffer = [0u8; 64];
		let n = tokio::time::timeout(Duration::from_secs(5), udp.recv(&mut buffer)).await.unwrap().unwrap();
		assert_eq!(&buffer[..n], b"ping");

		// More than both TCP windows, so backpressure in both directions is exercised.
		let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
		let stream = tunnel.tcp(SocketAddrV4::new(server, 80)).await.unwrap();
		let (mut read, mut write) = tokio::io::split(stream);
		let sent = payload.clone();
		let writer = tokio::spawn(async move {
			write.write_all(&sent).await.unwrap();
			write
		});
		let mut echoed = vec![0u8; payload.len()];
		tokio::time::timeout(Duration::from_secs(30), read.read_exact(&mut echoed)).await.unwrap().unwrap();
		assert!(echoed == payload, "echoed bytes differ");
		drop(writer.await.unwrap());
		drop(read);
		// The one-socket test peer needs a moment to close the first connection and listen again.
		tokio::time::sleep(Duration::from_millis(600)).await;

		// The loopback SOCKS5 front: right password reaches the peer, a wrong one is refused.
		let url = tunnel.proxy_url();
		let (secret, port) = {
			let rest = url.strip_prefix("socks5h://serein:").unwrap();
			let (secret, port) = rest.split_once("@127.0.0.1:").unwrap();
			(secret.to_owned(), port.parse::<u16>().unwrap())
		};
		let handshake = |password: String| async move {
			let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
			stream.write_all(&[5, 1, 2]).await.unwrap();
			let mut reply = [0u8; 2];
			stream.read_exact(&mut reply).await.unwrap();
			assert_eq!(reply, [5, 2]);
			let mut auth = vec![1, 6];
			auth.extend_from_slice(b"serein");
			auth.push(password.len() as u8);
			auth.extend_from_slice(password.as_bytes());
			stream.write_all(&auth).await.unwrap();
			stream.read_exact(&mut reply).await.unwrap();
			(stream, reply)
		};
		let (_, refused) = handshake("wrong".into()).await;
		assert_eq!(refused, [1, 1]);
		let (mut stream, accepted) = handshake(secret).await;
		assert_eq!(accepted, [1, 0]);
		stream.write_all(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 80]).await.unwrap();
		let mut connected = [0u8; 10];
		stream.read_exact(&mut connected).await.unwrap();
		assert_eq!(connected[1], 0, "CONNECT through the tunnel succeeds");
		stream.write_all(b"hello").await.unwrap();
		let mut echo = [0u8; 5];
		tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echo)).await.unwrap().unwrap();
		assert_eq!(&echo, b"hello");
		peer_task.abort();
	}
}
