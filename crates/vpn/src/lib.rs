//! In-process WireGuard client (e.g. a Proton VPN profile) for Serein's own traffic.
//!
//! There is no OS tunnel: REST and Gateway WebSockets reach the network through a local,
//! authenticated SOCKS5 listener ([`Tunnel::proxy_url`]) and voice/stream UDP uses
//! [`Tunnel::udp`] directly, so the rest of the machine never changes route.
mod config;
mod dns;
mod netstack;
mod socks;

pub use config::{Config, MAX_PROFILE_BYTES};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::sync::{Notify, mpsc, oneshot};
use zeroize::Zeroizing;

/// A UDP flow to one peer through the tunnel. Datagrams are best effort, like the real thing.
pub struct UdpConn {
	to_net: mpsc::Sender<Vec<u8>>,
	from_net: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
	wake: Arc<Notify>,
}

impl UdpConn {
	pub(crate) fn new(
		to_net: mpsc::Sender<Vec<u8>>,
		from_net: mpsc::Receiver<Vec<u8>>,
		wake: Arc<Notify>,
	) -> Self {
		Self {
			to_net,
			from_net: tokio::sync::Mutex::new(from_net),
			wake,
		}
	}
	pub async fn send(&self, datagram: &[u8]) -> io::Result<usize> {
		self.to_net
			.send(datagram.to_vec())
			.await
			.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "VPN stopped"))?;
		self.wake.notify_one();
		Ok(datagram.len())
	}
	/// Never waits: a full queue drops the datagram, which real-time media prefers to lag.
	pub fn try_send(&self, datagram: &[u8]) -> io::Result<usize> {
		self.to_net
			.try_send(datagram.to_vec())
			.map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "VPN queue full or stopped"))?;
		self.wake.notify_one();
		Ok(datagram.len())
	}
	/// Waits for the next datagram, truncating it to `buffer`.
	pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
		let datagram = self
			.from_net
			.lock()
			.await
			.recv()
			.await
			.ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "VPN stopped"))?;
		let n = datagram.len().min(buffer.len());
		buffer[..n].copy_from_slice(&datagram[..n]);
		Ok(n)
	}
}

/// What the SOCKS listener and callers share: the way into the stack, nothing else.
pub struct Core {
	handle: netstack::Handle,
	dns: Option<Ipv4Addr>,
}

pub struct Tunnel {
	core: Arc<Core>,
	port: u16,
	secret: Zeroizing<String>,
	tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Tunnel {
	fn drop(&mut self) {
		for task in &self.tasks {
			task.abort();
		}
	}
}

impl std::ops::Deref for Tunnel {
	type Target = Core;
	fn deref(&self) -> &Core {
		&self.core
	}
}

impl Tunnel {
	/// Connects, waits for the WireGuard handshake and opens the local SOCKS5 listener.
	pub async fn start(config: Config) -> Result<Arc<Self>, &'static str> {
		let dns = config.dns.first().copied();
		let (handle, stack) = netstack::start(config).await?;
		let ready = async {
			while !handle.up.load(Ordering::Relaxed) {
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		};
		if tokio::time::timeout(Duration::from_secs(10), ready).await.is_err() {
			stack.abort();
			return Err("VPN handshake failed: check the profile and that UDP is not blocked");
		}
		let mut random = [0u8; 18];
		getrandom::fill(&mut random).map_err(|_| "No system randomness")?;
		let secret = Zeroizing::new(random.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
		let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
			.await
			.map_err(|_| "Could not open the local VPN proxy")?;
		let port = listener.local_addr().map_err(|_| "No proxy port")?.port();
		let core = Arc::new(Core { handle, dns });
		let serving = tokio::spawn(socks::serve(listener, core.clone(), secret.clone()));
		Ok(Arc::new(Self {
			core,
			port,
			secret,
			tasks: vec![stack, serving],
		}))
	}

	/// `socks5h://` so hostnames resolve through the tunnel's DNS, never the local resolver.
	pub fn proxy_url(&self) -> Zeroizing<String> {
		Zeroizing::new(format!("socks5h://serein:{}@127.0.0.1:{}", *self.secret, self.port))
	}
}

impl Core {
	pub fn is_up(&self) -> bool {
		self.handle.up.load(Ordering::Relaxed)
	}

	async fn open(&self, kind: netstack::Kind) -> io::Result<netstack::Conn> {
		let (reply, answer) = oneshot::channel();
		self.handle
			.requests
			.send(netstack::Request { kind, reply })
			.await
			.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "VPN stopped"))?;
		answer
			.await
			.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "VPN stopped"))?
	}

	pub async fn tcp(&self, address: SocketAddrV4) -> io::Result<DuplexStream> {
		match self.open(netstack::Kind::Tcp(address)).await? {
			netstack::Conn::Tcp(stream) => Ok(stream),
			netstack::Conn::Udp(_) => Err(io::Error::other("VPN answered a TCP request with UDP")),
		}
	}

	pub async fn udp(&self, remote: SocketAddrV4) -> io::Result<UdpConn> {
		match self.open(netstack::Kind::Udp(remote)).await? {
			netstack::Conn::Udp(conn) => Ok(conn),
			netstack::Conn::Tcp(_) => Err(io::Error::other("VPN answered a UDP request with TCP")),
		}
	}

	/// IPv4 only: the tunnel carries no IPv6.
	pub async fn resolve(&self, host: &str) -> io::Result<Ipv4Addr> {
		if let Ok(address) = host.parse() {
			return Ok(address);
		}
		let server = self
			.dns
			.ok_or_else(|| io::Error::other("The VPN profile has no DNS server"))?;
		dns::resolve(self, SocketAddrV4::new(server, 53), host).await
	}
}

static ACTIVE: RwLock<Option<Arc<Tunnel>>> = RwLock::new(None);
static REQUIRED: AtomicBool = AtomicBool::new(false);
// Serialises start/stop so two toggles cannot interleave their publish step.
static LIFECYCLE: Mutex<()> = Mutex::new(());

/// How the next connection must leave this machine.
pub enum Route {
	Direct,
	Tunnel(Arc<Tunnel>),
	/// The user turned the VPN on but it is not connected: nothing may go out directly.
	Blocked,
}

pub fn route() -> Route {
	if let Some(tunnel) = ACTIVE.read().ok().and_then(|slot| slot.clone()) {
		Route::Tunnel(tunnel)
	} else if REQUIRED.load(Ordering::Relaxed) {
		Route::Blocked
	} else {
		Route::Direct
	}
}

/// Proxy for HTTP-style clients, or `None` for a direct connection. While the VPN is required but
/// down, an unreachable address makes every request fail instead of leaking the real IP.
pub fn proxy_url() -> Option<Zeroizing<String>> {
	match route() {
		Route::Direct => None,
		Route::Tunnel(tunnel) => Some(tunnel.proxy_url()),
		Route::Blocked => Some(Zeroizing::new("socks5h://127.0.0.1:1".into())),
	}
}

/// Marks the VPN as wanted (fail closed) or not. Call before starting, and with `false` only
/// when the user turns it off.
pub fn set_required(required: bool) {
	REQUIRED.store(required, Ordering::Relaxed);
}

/// Publishes (or retires) the running tunnel that [`route`] hands out.
pub fn set_active(tunnel: Option<Arc<Tunnel>>) {
	let _guard = LIFECYCLE.lock();
	if let Ok(mut slot) = ACTIVE.write() {
		*slot = tunnel;
	}
}
