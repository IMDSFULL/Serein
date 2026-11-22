# WireGuard VPN (in-process)

Serein can send **its own traffic** through a WireGuard profile, such as one exported from
Proton VPN. It does not create a system-wide VPN, change the routing table, install a driver or
need elevation: the rest of the computer keeps using the normal connection.

## Use

1. In your VPN provider, create/export a WireGuard configuration (`.conf`). For Proton VPN:
   *Downloads → WireGuard configuration*, choose a platform, a server and create it. Use a
   server that supports what you need (P2P/streaming servers are not required for Discord).
2. In Serein: **Settings → General → VPN → Import .conf**, pick the file.
3. Turn on **Route Serein through WireGuard** and restart Serein.

The profile is validated before it replaces the saved one and is stored as
`<data dir>/vpn/wireguard.conf` (`%APPDATA%`/`~/.local/share`-style data directory of Serein).
It holds a private key; protect that folder like the login files.

## What goes through the tunnel

| Traffic | Path |
|---|---|
| REST API, CDN, uploads, downloads, avatars | wreq clients → loopback SOCKS5 (`socks5h`) → tunnel |
| Gateway and voice/stream signaling (WebSocket) | same SOCKS5 listener |
| Voice, video and screen-share media (UDP) | `vpn::UdpConn` directly, no SOCKS |
| DNS for those hosts | the profile's `DNS =` server, through the tunnel |

The loopback SOCKS5 listener binds `127.0.0.1` on a random port, accepts only the per-run random
password and only CONNECT, so other programs on the machine cannot borrow the VPN.

## Behaviour and limits

- **Fail closed.** While the VPN is enabled and not connected (bad profile, endpoint unreachable,
  handshake timeout) every Serein connection is refused instead of going out directly. Turn the
  switch off and restart to leave the VPN.
- The route is chosen at startup, before any connection. Toggling the switch or importing a new
  profile applies after a restart.
- **IPv4 only** inside the tunnel (the profile's IPv6 address is ignored; IPv6 voice servers are
  refused while the VPN is on).
- One `[Peer]`; `AllowedIPs` is not interpreted — everything Serein sends goes to that peer.
- A shared free VPN server can be saturated or blocked by a destination; pick another server.
- Using a VPN does not change Discord's rules for third-party clients (see the README warning).

## Code map

- `crates/vpn` — `Config` (wg-quick parser), `netstack` (boringtun + smoltcp), `socks`, `dns`,
  and the process-wide `route()` / `proxy_url()` consulted by every transport.
- `crates/client-core/src/fingerprint/transport.rs` — `tunnel()` (any wreq client) and the
  Gateway WebSocket.
- `crates/discord-api/src/proxy.rs` — the REST client; the VPN overrides an API proxy.
- `crates/discord-voice/src/transport.rs` — `MediaSocket` (direct UDP or tunnel UDP).
- `apps/desktop/src/vpn_setup.rs`, `crates/ui/src/vpn_settings.rs` — startup and settings.
