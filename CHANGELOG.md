# Changelog

All notable changes to this project are documented in this file.

## [1.12.1] - 2026-07-05
- Reverted: hardware masking (TTL=128, TCP timestamps off, hostname `router`, avahi disabled, MAC spoofing) removed from all three deploy scripts and rolled back on the live Ubuntu box. TPROXY already provides full transparency at the network level, making OS/hardware-level masking unnecessary — decided not to carry the extra complexity.

## [1.12.0] - 2026-07-05
- Added: network-hardware masking (anti-fingerprint of the box itself) in all three deploy scripts — hides the "Linux laptop" tells from the ISP / proxy provider: outbound **TTL normalized to 128** (Windows-like, vs Linux 64) via `iptables -j TTL`, **TCP timestamps off**, neutral **hostname `router`** (no `family-…` in DHCP/mDNS), **avahi/mDNS disabled**, and **MAC spoofing** of the WAN interface (random, plausible OUI). MAC spoofing is auto-skipped during a remote (`ssh`) deploy since it would drop the link — it's applied only on a local run, with the manual command printed otherwise. Applied and verified live on the Ubuntu box (tcpdump confirmed egress `ttl 128`). Note: this masks the box from the ISP; it does **not** change what target sites see (they see the residential exit node), and it cannot spoof the connected devices' TLS/JA3 fingerprints — that requires an antidetect browser, not a transparent gateway.

## [1.11.2] - 2026-07-05
- Added: macOS support for the remote deploy — `deploy.command` double-click launcher (parity with `deploy.bat`), and docs clarifying that macOS/Linux use `python3 deploy.py` (there is no `python` on macOS). `deploy.py` itself is already cross-platform: the Windows-only `chcp`/ANSI setup is guarded behind `os.name == "nt"`, so nothing Windows-specific runs on a Mac. (Deliberately did **not** add SSH ControlMaster multiplexing: on macOS the control-socket path under `/var/folders` often exceeds the 104-char UNIX-socket limit and would break — not worth the risk while it can't be tested on a Mac.)

## [1.11.1] - 2026-07-05
- Fixed: all deploy scripts died on the very first line (`clear`) when run without a proper TTY/TERM — e.g. when launched remotely by `deploy.py` over `ssh` or detached — printing a cryptic `'unknown': I need something more specific.` under `set -euo pipefail`. `clear` is now non-fatal (`clear 2>/dev/null || true`). Verified end-to-end: a full remote deploy now completes through all 8 steps.
- Fixed: `deploy.py` crashed on Windows with `UnicodeEncodeError` when its output was piped/redirected (cp1251) — now forces UTF-8 output (and `chcp 65001` on Windows) so the boxes/Cyrillic render without crashing.

## [1.11.0] - 2026-07-05
- Added: `deploy.py` (+ `deploy.bat` launcher) — one-command remote deploy from the client. Enter the server IP + SSH login, it checks the connection, sets up passwordless `sudo` (NOPASSWD), lets you pick the deploy type by a simple name (UBUNTU + ROUTER / RASPBERRY + ROUTER / RASPBERRY + WIFI), then copies the files over `scp` and runs the matching installer over `ssh -t` — no more manual file copying. Normalizes CRLF→LF on the server so scripts run even if checked out on Windows.
- Added: `.gitattributes` forcing LF on `*.sh` / `*.service` / `*.py` so server scripts are never broken by Windows line endings.

## [1.10.0] - 2026-07-05
- Added: `deploy-rpi5-ap.sh` — a second Raspberry Pi installer where the Pi is a **standalone Wi-Fi router**: internet comes in over the **Ethernet cable (`eth0` = WAN)** and the Pi broadcasts **its own Wi-Fi access point (`wlan0`, WPA2)** that devices connect to — no technical router needed. Uses NetworkManager AP mode for the hotspot + our dnsmasq for DHCP, asks for the SSID/password/country, sets the Wi-Fi regulatory domain, and keeps the same compatibility checks and leak protection (TProxy TCP+UDP, FakeIP, MSS clamp, IPv6 block, reboot-resilient dnsmasq). Complements `deploy-rpi5.sh` (Wi-Fi = WAN, Ethernet = LAN).

## [1.9.1] - 2026-07-05
- Added: both deploy scripts now offer to pin the box's own WAN IP as **static** (the address the client connects to), defaulting to the current IP so nothing breaks. Prevents the control IP from changing on DHCP-lease renewal. Interactive prompt (custom IP or keep DHCP); applied via NetworkManager (Ubuntu/Pi) or dhcpcd (older Pi OS). Applied live on the Ubuntu box (192.168.1.96 → static).
- Added: DNS self-repair after switching to a static IP — if the systemd-resolved stub stops resolving, resolv.conf is repointed at the real upstream servers so the box keeps working.

## [1.9.0] - 2026-07-05
- Added: `deploy-rpi5.sh` — a separate, beginner-friendly installer for Raspberry Pi 5 (Raspberry Pi OS / ARM64). Compatibility checks (ARM64 arch + correct sing-box build, Pi model, Debian/Pi OS, kernel TProxy support with a live probe), interactive Wi-Fi setup when there's no internet, NetworkManager and dhcpcd support for the static LAN IP, reboot-resilient dnsmasq, and the same leak protection (TProxy TCP+UDP, FakeIP, MSS clamp, IPv6 block). Topology: Wi-Fi (`wlan0`) = WAN, Ethernet (`eth0`) = LAN.
- Hardened: `deploy.sh` and `deploy-rpi5.sh` guard pipe-based command substitutions (`grep … | head` for interface/version detection) with `|| true` so a no-match doesn't abort the script under `set -euo pipefail` before the friendly error is shown.

## [1.8.2] - 2026-07-05
- Fixed: dnsmasq (LAN DHCP/DNS) died after reboot with "unknown interface" because it started before the LAN interface was up. Added a systemd drop-in (`Restart=on-failure`, `RestartSec=5s`, `StartLimitIntervalSec=0`, `After/Wants=network-online.target`) so dnsmasq retries indefinitely until the interface appears. Applied to the live server and baked into `deploy.sh` for new installs.

## [1.8.1] - 2026-06-26
- Hardened: explicit Linux capabilities in `sing-box.service` (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`) via `AmbientCapabilities` + `CapabilityBoundingSet`. Guarantees UDP/QUIC TProxy works (same path as TCP) even if sing-box is not run as root, and applies least-privilege instead of full root caps.
- Verified: UDP TProxy redirect rule matches TCP (all UDP, incl. QUIC :443, sent to sing-box), TPROXY kernel modules loaded, policy routing (fwmark→table 100) intact, and the active proxy's SOCKS5 UDP ASSOCIATE relay forwards. Conclusion: the Ubuntu UDP/Android path is correct; "nothing loads" is caused by the upstream proxy stalling on bulk transfer.

## [1.8] - 2026-06-26
- Fixed: Russian text leaking into the client log in EN mode. Server endpoints (/proxy_health, /current_ip) now return a machine-readable `error_code` with English text; the client localizes errors by code (handshake, auth, connect, timeout, TLS, no-proxy, geo).

## [1.7] - 2026-06-26
- Added: server `GET /proxy_health` endpoint — honest bulk throughput test of the active proxy via the real path (downloads 512 KB from Ubuntu through the proxy over SOCKS5+TLS). Detects "dead" proxies that accept connections and small requests but stall after ~17 KB on bulk transfer.
- Added: "Bulk test" (⚡) button in the client banner — runs the server-side health test and reports CLEAN/STALLED with downloaded KB, time and KB/s. Catches proxies the client-side speed test misses (client tests a different network path).

## [1.6] - 2026-06-26
- Changed: Redesigned client UI — modern card-based dark layout (Catppuccin), custom rounded Canvas buttons with hover states, accent strips, segmented RU/EN language toggle, section cards (Server / Proxy / Log), refined typography and spacing. No new dependencies.

## [1.5] - 2026-06-26
- Added: "Broadcasting" banner in the client showing the exit IP currently served to the router's devices and its geo (country / city / ISP), with a ⟳ refresh button and auto-refresh after Route / Check server.
- Added: server `GET /current_ip` endpoint — resolves the exit IP/geo by querying ip-api.com through the active proxy (using the credentials from config.json). Client falls back to local resolution if the endpoint is absent.

## [1.4] - 2026-06-25
- Added: Check cleanliness button in the Windows client — checks exit IP reputation via open sources (ip-api.com `proxy` / `hosting` / `mobile` flags) with a CLEAN / Datacenter / DIRTY verdict.
- Added: Speed & latency measurement (Cloudflare speed endpoint) reported on cleanliness check; last speed is stored in proxy history.

## [1.3] - 2026-06-25
- Added: Proxy history tab in the Windows client — stores used proxies with geo info (country, city, ISP, flag), colored status icons (✓/⚠/✗), and actions: Load, Check, Delete.
- Added: Auto-save to history on Route apply and on proxy check (with geo data).
- Added: Double-click on a history row loads the proxy into the main field.

## [1.2] - 2026-06-24
- Added: Check UDP button in the Windows client — tests SOCKS5 UDP ASSOCIATE support before routing.
- Added: UDP TProxy — QUIC/HTTP3 traffic is now proxied through SOCKS5 UDP ASSOCIATE instead of being dropped. Reduces fraud score on antidetect systems.
- Added: FakeIP mode via sing-box — DNS queries return fake IPs (198.18.0.0/15), hostname is sent to the proxy directly (no IP leaks through DNS).
- Added: DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) blocking — forces devices to use plain UDP DNS, which FakeIP intercepts.
- Added: MSS clamp 1280 and GRO/GSO/TSO offload disable on LAN interface.

## [1.1] - 2026-06-24
- Added: Support for UDP traffic when the upstream proxy supports UDP forwarding. If the configured proxy supports UDP relay, UDP traffic will be proxied; otherwise the project continues to handle TCP only.
