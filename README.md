# JackalRouter

**Zero-leak transparent SOCKS5 proxy gateway via Ubuntu + Technical Router**

[English](#english) · [Русский](#русский)

---

## English

### What is this?

JackalRouter turns an Ubuntu laptop into a **transparent proxy gateway** for any device connected to a secondary Wi-Fi router. Once deployed, every device on the router's network — phone, tablet, PC — routes all traffic through a SOCKS5 proxy with **no configuration required on the device itself**.

All known leak vectors are plugged:

| Traffic type | Without JackalRouter | With JackalRouter |
|---|---|---|
| TCP (HTTP, HTTPS…) | Real IP | Proxy IP |
| UDP DNS `:53` | Real IP + ISP DNS | sing-box FakeIP → domain sent to proxy |
| UDP QUIC/HTTP3 `:443` | Real IP | Proxy IP (via UDP ASSOCIATE) |
| WebRTC STUN `:3478` / `:19302` | Real IP (browser leak) | Proxy IP (via UDP ASSOCIATE) |
| Any other UDP | Real IP | Proxy IP (via UDP ASSOCIATE) |
| IPv6 | Real IPv6 address | **Blocked** |

### Architecture

```
Internet
   │
   ▼
Ubuntu Laptop  ◄──────── LAN ──────────  Windows PC
│  wlp2s0 (WAN, WiFi/LAN to internet)   (JackalRouter GUI client)
│
│  enp3s0 (LAN, 10.0.0.1/24)
│    │
│    ▼
Technical Router  (WAN = DHCP from 10.0.0.1)
│
├── Wi-Fi Device 1  (phone, tablet…)
├── Wi-Fi Device 2
└── …
```

**Traffic flow:**
1. Device sends any DNS query → `iptables PREROUTING` TProxy → **sing-box** intercepts and answers with a **FakeIP** (198.18.x.x), stores the FakeIP↔domain mapping
2. Device connects to FakeIP via TCP/UDP → `iptables PREROUTING` TProxy → **sing-box** maps FakeIP back to the real domain, dials the SOCKS5 proxy **by hostname** (no IP leaks through DNS)
3. For TCP: sing-box opens a SOCKS5 CONNECT tunnel to the proxy
4. For UDP (QUIC, STUN, etc.): sing-box uses **SOCKS5 UDP ASSOCIATE** — the proxy forwards UDP datagrams, so QUIC/HTTP3 reaches the destination through the proxy IP
5. IPv6 → `ip6tables FORWARD DROP`

### How FakeIP works

Standard transparent proxies must resolve DNS to get an IP, then connect by IP — which leaks the real hostname to the proxy only if the proxy supports hostname resolution. JackalRouter uses sing-box's **FakeIP** mode:

1. Device asks "what is google.com?" → sing-box intercepts and replies "198.18.0.1" (a fake, internal IP)
2. Device opens a TCP/UDP connection to 198.18.0.1
3. sing-box sees the connection, looks up its FakeIP table → finds "google.com"
4. sing-box tells the SOCKS5 proxy: **connect to google.com** (not to an IP)

This means the proxy always receives the real hostname. DNS queries never leave the machine unencrypted. HTTPS/SVCB DNS record types (64/65) are rejected to prevent Cloudflare and other CDNs from bypassing FakeIP via `ipv4hint`.

### How UDP proxying works

Most transparent proxies drop UDP (except DNS) because UDP cannot be reliably redirected through a TCP-only SOCKS5 proxy. JackalRouter uses SOCKS5 **UDP ASSOCIATE**:

1. All UDP from LAN devices is TProxy'd into sing-box (same as TCP)
2. sing-box establishes a **UDP ASSOCIATE** session with the upstream SOCKS5 proxy
3. The proxy allocates a UDP relay socket and returns its address
4. sing-box forwards each UDP datagram to the relay, which forwards it to the real destination
5. The destination sees the proxy IP, not the real IP

This means QUIC/HTTP3, WebRTC STUN, and all other UDP traffic is proxied — not blocked. Blocking UDP raises the fraud score on antidetect systems (a real residential IP always has working QUIC).

The client includes a **Check UDP** button that tests whether the upstream proxy supports UDP ASSOCIATE before routing.

### Components

| File | Description |
|---|---|
| `server/server.py` | FastAPI server running on Ubuntu as root. Generates sing-box config with FakeIP, manages iptables TProxy rules. |
| `server/sing-box.service` | systemd unit for sing-box auto-start |
| `server/jackalrouter.service` | systemd unit for the API server auto-start |
| `client/client.py` | Windows Tkinter GUI — applies proxy, checks TCP + geo, UDP ASSOCIATE, IP cleanliness (open-source reputation) + speed, proxy history |
| `deploy.sh` | Full automated deployment script for Ubuntu |
| `deploy-rpi5.sh` | Pi 5 deploy — Wi-Fi = WAN, Ethernet = LAN (to a technical router), mirrors Ubuntu |
| `deploy-rpi5-ap.sh` | Pi 5 deploy — Ethernet = WAN (cable), Wi-Fi = own access point (standalone router, no technical router) |
| `deploy-ubuntu-wifi-ap.sh` | Ubuntu deploy — Wi-Fi #1 = WAN (reuses the already-connected network), Wi-Fi #2 = own access point (standalone router). Needs two Wi-Fi adapters. |
| `deploy.py` | Client-side remote installer: enter server IP → check → set up NOPASSWD sudo → pick deploy type → auto copy + run over SSH |
| `deploy.bat` / `deploy.command` | Double-click launchers for `deploy.py` (Windows / macOS) |
| `update.py` | Updates an already-deployed box from GitHub — pulls the latest `server.py`, diffs it against what's on the box, applies it with automatic backup/health-check/rollback, and re-generates `config.json` for the currently active proxy. Does **not** touch Wi-Fi/DHCP/network settings. |
| `update.bat` / `update.command` | Double-click launchers for `update.py` (Windows / macOS) |

### Requirements

**Ubuntu side:**
- Ubuntu 20.04+ (tested on 20.04 LTS)
- Two network interfaces: WAN (internet) + LAN (to secondary router)
- `sudo` access (deployment runs as root)

**Windows side:**
- Python 3.8+ with `pip`
- Packages auto-installed on first run (`requests[socks]`, `PySocks`)
- Network access to Ubuntu's local IP

**Router:**
- Any Wi-Fi router with a WAN port
- WAN connection type set to **DHCP** (automatic IP)
- Connected to Ubuntu's LAN port via Ethernet cable

**Upstream SOCKS5 proxy:**
- Must support **UDP ASSOCIATE** for full UDP proxying (QUIC, WebRTC)
- Use the **Check UDP** button in the client to verify before routing

### Deployment

**Recommended — one command from the client (no manual file copying):**

```bash
# From the project folder on the client:
python deploy.py            # Windows        (or double-click deploy.bat)
python3 deploy.py           # macOS / Linux  (or double-click deploy.command on macOS)
```

> On macOS the command is `python3` (there is no `python`). If double-clicking
> `deploy.command` is blocked by Gatekeeper, right-click it → **Open**, or run
> `chmod +x deploy.command && ./deploy.command`.

`deploy.py` asks for the server IP + SSH login, checks the connection, sets up
passwordless `sudo` (NOPASSWD), lets you pick the deploy type by a simple name, then
**copies the files and runs the right installer on the server automatically**:

| Choice | Runs | Topology |
|---|---|---|
| **UBUNTU + ROUTER** | `deploy.sh` | Ubuntu; Wi-Fi = WAN, Ethernet = LAN (technical router) |
| **RASPBERRY + ROUTER** | `deploy-rpi5.sh` | Pi; Wi-Fi = WAN, Ethernet = LAN (technical router) |
| **RASPBERRY + WIFI** | `deploy-rpi5-ap.sh` | Pi as its own Wi-Fi router; Ethernet = WAN, Wi-Fi = access point |
| **UBUNTU + WIFI** | `deploy-ubuntu-wifi-ap.sh` | Ubuntu as its own Wi-Fi router (2 adapters); Wi-Fi = WAN, Wi-Fi = access point |

Requires the OpenSSH client (`ssh`/`scp`) — built into Windows 10/11 and Linux/Mac. An
SSH key is recommended (otherwise you'll enter the password a few times).

**Manual (run directly on the server) — same installers:**

```bash
# On Ubuntu — run once:
sudo bash deploy.sh

# On a Raspberry Pi 5 (Raspberry Pi OS) — pick ONE of the two topologies:
sudo bash deploy-rpi5.sh       # internet via Wi-Fi, distribute via Ethernet+router
sudo bash deploy-rpi5-ap.sh    # internet via Ethernet cable, Pi broadcasts its own Wi-Fi

# On Ubuntu with two Wi-Fi adapters (standalone Wi-Fi router, no technical router):
sudo bash deploy-ubuntu-wifi-ap.sh   # internet via Wi-Fi, broadcasts its own Wi-Fi
```

**`deploy-ubuntu-wifi-ap.sh`** — also selectable from `deploy.py` (**UBUNTU + WIFI**) or run
directly on the box. Needs **two separate Wi-Fi adapters** (e.g. built-in + USB dongle): one
takes the internet (WAN), the other broadcasts its own access point (LAN, WPA2) that
phones/laptops join — same TProxy leak protection, dnsmasq DHCP and sing-box setup as the
other installers. Notable behaviours:

- **Bands are not hardcoded.** WAN connects on whatever band its network actually uses; the
  AP band is chosen in a prompt (2.4 GHz by default for range, 5 GHz optional).
- **An already-connected WAN adapter is reused as-is** — no SSID/password prompt, and the
  connection is never torn down. This matters when you run the deploy over SSH through that
  same adapter: re-creating the connection would kill your own session.
- **The Wi-Fi regulatory domain is auto-detected** from the kernel; you're only asked if it
  can't be determined, and the answer is validated as a 2-letter ISO code.
- **NAT/forwarding are not bound to the WAN interface name**, so swapping the upstream Wi-Fi
  network, adapter or moving to a cable keeps clients online.

**Raspberry Pi 5 — two beginner-friendly installers** (compatibility checks: ARM64
arch + correct sing-box build, Pi model, kernel TProxy probe; reboot-resilient dnsmasq;
same leak protection):

- **`deploy-rpi5.sh`** — mirrors the Ubuntu setup: **Wi-Fi (`wlan0`) = WAN (home
  internet)**, **Ethernet (`eth0`) = LAN (cable to a technical router)**. Interactive
  Wi-Fi client setup if there's no internet.
- **`deploy-rpi5-ap.sh`** — Pi is a **standalone Wi-Fi router (no technical router
  needed)**: **Ethernet (`eth0`) = WAN (internet from the cable)**, **Wi-Fi (`wlan0`) =
  its own access point (WPA2)** that phones connect to. Asks for the SSID/password to
  broadcast; uses NetworkManager AP mode + our dnsmasq for DHCP.

The script will:
1. Check internet and system requirements
2. Auto-detect WAN and LAN interfaces
3. Install packages: `python3`, `dnsmasq`, `iptables-persistent`, `ethtool`, `curl`, `wget`
4. Assign static IP `10.0.0.1/24` to LAN interface (NetworkManager)
5. Configure `dnsmasq` as DHCP server (range `10.0.0.100–200`)
6. Apply MSS clamp 1280 on LAN interface (both directions)
7. Disable GRO/GSO/TSO offload on LAN interface (`ethtool`)
8. Apply iptables TProxy rules: all TCP+UDP from LAN → sing-box port 7893
9. Install sing-box, write FakeIP config, register and start systemd services

### Updating an already-deployed box

For a box that's already running (Wi-Fi/DHCP/network already configured — you don't want
to re-answer those questions or risk breaking a working setup) but is behind on fixes:

```bash
python update.py            # Windows        (or double-click update.bat)
python3 update.py           # macOS / Linux  (or double-click update.command on macOS)

python update.py --check    # only show whether an update is available, change nothing
```

It asks for the box's IP, SSH login, and which deploy type is installed (informational —
the corresponding script is *not* re-run, network settings are untouched). It then:

1. Fetches the latest `server/server.py` from GitHub (`raw.githubusercontent.com`; falls
   back to the local copy next to `update.py` if GitHub is unreachable)
2. Diffs it against what's on the box, ignoring the box-specific `INT_IFACE` line
3. If different: shows the diff, backs up the current file, applies the new one, restarts
   `jackalrouter`, and verifies the service **and** the `/status` API respond — automatic
   rollback to the backup if either check fails
4. Re-generates `/etc/sing-box/config.json` for whatever proxy is *currently* configured
   on the box (so a fix like the QUIC/DNS one takes effect immediately, not only the next
   time someone hits **Route** in the client) and restarts `sing-box`
5. Creates the `jackal-policy-routing` systemd unit if it's missing (older deploys didn't
   have it — without it, policy routing for TProxy doesn't survive a reboot)

### Router configuration (one-time)

1. Connect cable: `Ubuntu LAN port → Router WAN port`
2. Connect phone/PC to the router's Wi-Fi
3. Open router admin panel (usually `192.168.0.1` or `192.168.1.1`)
4. Go to **WAN / Internet / Connection type** → set to **DHCP (Dynamic IP)**
5. Save and wait 15 seconds

### Client usage (Windows)

```bash
python client/client.py
```

Or run the standalone `.exe` (no Python needed on the target machine) — build it with:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name JackalRouter --distpath client/dist --workpath client/build --specpath client client/client.py
```

The result is `client/dist/JackalRouter.exe`. It keeps its state (proxy history, last used
server IP) in `proxy_history.json` / `client_config.json` next to the `.exe` itself — the
server IP field is never hardcoded; it starts empty and remembers the last IP you used.

1. Enter Ubuntu's local IP address
2. Paste a SOCKS5 proxy string in one of these formats:
   - `ip:port:username:password`
   - `username:password@ip:port`
   - `socks5://username:password@ip:port`
3. Click **Check proxy** — verifies TCP connectivity, shows IP / city / ISP
4. Click **Check UDP** — verifies SOCKS5 UDP ASSOCIATE support (required for QUIC)
5. Click **Check cleanliness** — checks the exit IP reputation via open sources
   (ip-api.com `proxy` / `hosting` / `mobile` flags) and measures speed + latency:
   - **CLEAN** — residential IP, not flagged
   - **Datacenter** — hosting IP, raises antidetect fraud-score
   - **DIRTY** — flagged as proxy/VPN/Tor
6. Click **Route** — applies the proxy; all traffic on the router's network is now proxied

The **Broadcasting** banner at the top shows the exit IP currently served to the
router's devices and its geo (country / city / ISP). It refreshes automatically after
Route / Check server, or on demand via the ⟳ button. The value is resolved
authoritatively by the server (it queries ip-api.com through the active proxy); if the
server lacks the `/current_ip` endpoint, the client falls back to resolving it locally.

The **History** tab stores every used/checked proxy with its geo, status icon and last
measured speed; you can reload, re-check or delete entries there.

### API

The server exposes a simple REST API on port `8000`:

```
POST /set_proxy     {"proxy_string": "ip:port:user:pass"}
GET  /status        → {"sing_box": "active", "dnsmasq": "active", "iptables": "ok", "proxy": "1.2.3.4:1080"}
GET  /current_ip    → {"ok": true, "exit_ip": "5.6.7.8", "countryCode": "US", "city": "...", "isp": "..."}
GET  /proxy_health  → {"ok": true, "stalled": false, "got_bytes": 524288, "elapsed": 2.1, "kbps": 243.0}
```

---

## Русский

### Что это?

JackalRouter превращает Ubuntu-ноутбук в **прозрачный прокси-шлюз** для всех устройств, подключённых к второму (техническому) Wi-Fi роутеру. После деплоя телефон, планшет, ноутбук — всё что подключится к этому роутеру — автоматически направляет трафик через SOCKS5 прокси **без каких-либо настроек на самом устройстве**.

Все известные каналы утечки IP закрыты:

| Тип трафика | Без JackalRouter | С JackalRouter |
|---|---|---|
| TCP (HTTP, HTTPS…) | Реальный IP | IP прокси |
| UDP DNS `:53` | Реальный IP + DNS провайдера | sing-box FakeIP → домен отправляется в прокси |
| UDP QUIC/HTTP3 `:443` | Реальный IP | IP прокси (через UDP ASSOCIATE) |
| WebRTC STUN `:3478` / `:19302` | Реальный IP (утечка в браузере) | IP прокси (через UDP ASSOCIATE) |
| Любой другой UDP | Реальный IP | IP прокси (через UDP ASSOCIATE) |
| IPv6 | Реальный IPv6-адрес | **Заблокирован** |

### Архитектура

```
Интернет
   │
   ▼
Ubuntu-ноутбук  ◄──────── LAN ──────────  ПК на Windows
│  wlp2s0 (WAN — Wi-Fi/LAN в интернет)   (GUI-клиент JackalRouter)
│
│  enp3s0 (LAN, 10.0.0.1/24)
│    │
│    ▼
Технический роутер  (WAN = DHCP от 10.0.0.1)
│
├── Wi-Fi устройство 1  (телефон, планшет…)
├── Wi-Fi устройство 2
└── …
```

**Путь трафика:**
1. Устройство отправляет DNS-запрос → `iptables PREROUTING` TProxy → **sing-box** перехватывает и отвечает **FakeIP** (198.18.x.x), сохраняя маппинг FakeIP↔домен
2. Устройство подключается к FakeIP по TCP/UDP → `iptables PREROUTING` TProxy → **sing-box** находит домен по FakeIP и дозванивается в SOCKS5 прокси **по имени хоста** (не по IP — утечка исключена)
3. Для TCP: sing-box открывает SOCKS5 CONNECT тоннель к прокси
4. Для UDP (QUIC, STUN и др.): sing-box использует **SOCKS5 UDP ASSOCIATE** — прокси транзитирует UDP-датаграммы, QUIC/HTTP3 доходит до назначения через IP прокси
5. IPv6 → `ip6tables FORWARD DROP`

### Как работает FakeIP

Стандартные прозрачные прокси резолвят DNS чтобы получить IP, затем подключаются по IP. JackalRouter использует режим **FakeIP** в sing-box:

1. Устройство спрашивает «какой IP у google.com?» → sing-box перехватывает и отвечает «198.18.0.1» (фиктивный внутренний IP)
2. Устройство открывает TCP/UDP соединение на 198.18.0.1
3. sing-box видит соединение, смотрит в таблицу FakeIP → находит «google.com»
4. sing-box говорит SOCKS5 прокси: **подключись к google.com** (не к IP)

DNS-запросы не покидают машину в открытом виде. DNS-типы HTTPS/SVCB (64/65) отклоняются, чтобы Cloudflare и другие CDN не могли обойти FakeIP через `ipv4hint`.

### Как работает проксирование UDP

JackalRouter использует **SOCKS5 UDP ASSOCIATE**:

1. Весь UDP от устройств LAN попадает в TProxy → sing-box (так же как TCP)
2. sing-box устанавливает сессию **UDP ASSOCIATE** с upstream SOCKS5 прокси
3. Прокси выделяет UDP-релей и возвращает его адрес
4. sing-box пересылает каждую UDP-датаграмму на релей, который доставляет её по назначению
5. Назначение видит IP прокси, а не реальный IP

Это означает что QUIC/HTTP3, WebRTC STUN и весь остальной UDP проксируется, а не блокируется. Блокировка UDP повышает fraud-score в антидетект-системах (у настоящего резидентного IP всегда работает QUIC).

Клиент содержит кнопку **Проверить UDP**, которая тестирует поддержку UDP ASSOCIATE у прокси перед применением.

### Состав проекта

| Файл | Описание |
|---|---|
| `server/server.py` | FastAPI-сервер на Ubuntu (от root). Генерирует конфиг sing-box с FakeIP, управляет правилами iptables TProxy. |
| `server/sing-box.service` | Юнит systemd для автозапуска sing-box |
| `server/jackalrouter.service` | Юнит systemd для автозапуска API-сервера |
| `client/client.py` | GUI-клиент на Windows (Tkinter) — применяет прокси, проверяет TCP + гео, UDP ASSOCIATE, чистоту IP (репутация из открытых баз) + скорость, история прокси |
| `deploy.sh` | Скрипт полного автоматического деплоя на Ubuntu |
| `deploy-rpi5.sh` | Деплой Pi 5 — Wi-Fi = WAN, Ethernet = LAN (в технический роутер), как на Ubuntu |
| `deploy-rpi5-ap.sh` | Деплой Pi 5 — Ethernet = WAN (кабель), Wi-Fi = своя точка доступа (самостоятельный роутер, без техроутера) |
| `deploy-ubuntu-wifi-ap.sh` | Деплой Ubuntu — Wi-Fi #1 = WAN (переиспользует уже подключённую сеть), Wi-Fi #2 = своя точка доступа (самостоятельный роутер). Нужны два Wi-Fi адаптера. |
| `deploy.py` | Удалённый установщик с клиента: ввёл IP → проверка → NOPASSWD sudo → выбрал вид деплоя → сам копирует и запускает по SSH |
| `deploy.bat` / `deploy.command` | Лаунчеры для двойного клика по `deploy.py` (Windows / macOS) |
| `update.py` | Обновляет уже развёрнутую коробку с GitHub — тянет актуальный `server.py`, сверяет с тем, что на коробке, применяет с бэкапом/health-check/автооткатом и перегенерирует `config.json` под уже настроенный прокси. Wi-Fi/DHCP/сеть **не трогает**. |
| `update.bat` / `update.command` | Лаунчеры для двойного клика по `update.py` (Windows / macOS) |

### Требования

**Ubuntu:**
- Ubuntu 20.04+ (протестировано на 20.04 LTS)
- Два сетевых интерфейса: WAN (интернет) + LAN (к роутеру)
- Доступ к `sudo` (деплой запускается от root)

**Windows:**
- Python 3.8+ с `pip`
- Пакеты устанавливаются автоматически при первом запуске (`requests[socks]`, `PySocks`)
- Сетевой доступ к локальному IP Ubuntu

**Роутер:**
- Любой Wi-Fi роутер с WAN-портом
- Тип подключения WAN — **DHCP** (автоматически)
- Кабель: WAN-порт роутера → LAN-порт ноутбука

**Upstream SOCKS5 прокси:**
- Должен поддерживать **UDP ASSOCIATE** для полного UDP-проксирования (QUIC, WebRTC)
- Используйте кнопку **Проверить UDP** в клиенте для проверки перед применением

### Деплой

**Рекомендуется — одной командой с клиента (без ручного копирования файлов):**

```bash
# Из папки проекта на клиенте:
python deploy.py            # Windows        (или двойной клик по deploy.bat)
python3 deploy.py           # macOS / Linux  (или двойной клик по deploy.command на macOS)
```

> На macOS команда — `python3` (команды `python` там нет). Если двойной клик по
> `deploy.command` блокирует Gatekeeper — правый клик → **Открыть**, либо в терминале:
> `chmod +x deploy.command && ./deploy.command`.

`deploy.py` спросит IP сервера и SSH-логин, проверит связь, отключит пароль `sudo`
(NOPASSWD), даст выбрать вид деплоя простым названием, затем **сам скопирует файлы и
запустит нужный установщик на сервере**:

| Выбор | Запускает | Схема |
|---|---|---|
| **UBUNTU + ROUTER** | `deploy.sh` | Ubuntu; Wi-Fi = WAN, Ethernet = LAN (тех. роутер) |
| **RASPBERRY + ROUTER** | `deploy-rpi5.sh` | Pi; Wi-Fi = WAN, Ethernet = LAN (тех. роутер) |
| **RASPBERRY + WIFI** | `deploy-rpi5-ap.sh` | Pi = свой Wi-Fi роутер; Ethernet = WAN, Wi-Fi = точка доступа |
| **UBUNTU + WIFI** | `deploy-ubuntu-wifi-ap.sh` | Ubuntu = свой Wi-Fi роутер (2 адаптера); Wi-Fi = WAN, Wi-Fi = точка доступа |

Нужен клиент OpenSSH (`ssh`/`scp`) — встроен в Windows 10/11 и Linux/Mac. Желателен
SSH-ключ (иначе пароль спросит несколько раз).

**Вручную (прямо на сервере) — те же установщики:**

```bash
# На Ubuntu — один раз:
sudo bash deploy.sh

# На Raspberry Pi 5 (Raspberry Pi OS) — выберите ОДНУ из двух схем:
sudo bash deploy-rpi5.sh       # интернет по Wi-Fi, раздача по кабелю через роутер
sudo bash deploy-rpi5-ap.sh    # интернет по кабелю, Pi раздаёт свой Wi-Fi

# На Ubuntu с двумя Wi-Fi адаптерами (самостоятельный Wi-Fi роутер, без техроутера):
sudo bash deploy-ubuntu-wifi-ap.sh   # интернет по Wi-Fi, коробка раздаёт свой Wi-Fi
```

**`deploy-ubuntu-wifi-ap.sh`** — доступен и через `deploy.py` (**UBUNTU + WIFI**), и
запуском вручную прямо на коробке. Нужны **два разных Wi-Fi адаптера** (например,
встроенный + USB-свисток): один берёт интернет (WAN), второй раздаёт свою точку
доступа (LAN, WPA2), к которой подключаются телефоны/ноутбуки — та же защита от
утечек через TProxy, DHCP на dnsmasq и установка sing-box, что и в остальных
установщиках. Важные особенности поведения:

- **Диапазоны не зашиты.** WAN подключается на том диапазоне, на котором реально
  вещает сеть; диапазон раздачи выбирается в диалоге (по умолчанию 2.4 ГГц для
  дальности, опционально 5 ГГц).
- **Уже подключённый WAN-адаптер переиспользуется как есть** — SSID/пароль не
  спрашиваются, соединение не разрывается. Это важно при запуске деплоя по SSH
  через этот же адаптер: пересоздание соединения оборвало бы вашу же сессию.
- **Регуляторный домен Wi-Fi определяется автоматически** из ядра; спрашивается,
  только если определить не удалось, и ответ валидируется как ISO-код из 2 букв.
- **NAT/форвардинг не привязаны к имени WAN-интерфейса**, поэтому смена сети,
  адаптера или переход на кабель не оставляют клиентов без интернета.

**Raspberry Pi 5 — два установщика для новичка** (проверки совместимости: ARM64 +
правильная сборка sing-box, модель Pi, проба TProxy в ядре; reboot-устойчивый dnsmasq;
та же защита от утечек):

- **`deploy-rpi5.sh`** — как на Ubuntu: **Wi-Fi (`wlan0`) = WAN (домашний интернет)**,
  **Ethernet (`eth0`) = LAN (кабель в технический роутер)**. Если интернета нет —
  интерактивно настроит Wi-Fi.
- **`deploy-rpi5-ap.sh`** — Pi = **самостоятельный Wi-Fi роутер (техроутер не нужен)**:
  **Ethernet (`eth0`) = WAN (интернет по кабелю)**, **Wi-Fi (`wlan0`) = своя точка
  доступа (WPA2)**, к которой подключаются телефоны. Спросит имя/пароль сети; использует
  AP-режим NetworkManager + наш dnsmasq для DHCP.

Скрипт выполнит:
1. Проверку интернета и системных требований
2. Автоопределение WAN и LAN интерфейсов
3. Установку пакетов: `python3`, `dnsmasq`, `iptables-persistent`, `ethtool`, `curl`, `wget`
4. Назначение статического IP `10.0.0.1/24` на LAN-интерфейс (через NetworkManager)
5. Настройку `dnsmasq` как DHCP-сервера (диапазон `10.0.0.100–200`)
6. MSS clamp 1280 на LAN-интерфейсе (оба направления)
7. Отключение GRO/GSO/TSO offload на LAN-интерфейсе (`ethtool`)
8. Применение правил iptables TProxy: весь TCP+UDP из LAN → sing-box порт 7893
9. Установку sing-box, запись FakeIP-конфига, регистрацию и запуск systemd-сервисов

### Обновление уже развёрнутой коробки

Для коробки, которая уже работает (Wi-Fi/DHCP/сеть уже настроены — переотвечать на эти
вопросы или рисковать сломать рабочую установку не хочется), но отстала по фиксам:

```bash
python update.py            # Windows        (или двойной клик update.bat)
python3 update.py           # macOS / Linux  (или двойной клик update.command на macOS)

python update.py --check    # только показать, есть ли обновление, ничего не менять
```

Спросит IP коробки, SSH-логин и какой вид деплоя на ней стоит (справочно —
соответствующий скрипт **не** перезапускается, сетевые настройки не трогаются). Дальше:

1. Тянет актуальный `server/server.py` с GitHub (`raw.githubusercontent.com`; если GitHub
   недоступен — берёт локальную копию рядом с `update.py`)
2. Сверяет с тем, что реально на коробке, игнорируя специфичную для неё строку `INT_IFACE`
3. Если отличается — показывает diff, делает бэкап, накатывает новую версию, перезапускает
   `jackalrouter`, проверяет что сервис жив **и** API `/status` отвечает — при провале
   любой из проверок автоматически откатывает бэкап
4. Перегенерирует `/etc/sing-box/config.json` под **уже настроенный** на коробке прокси
   (чтобы фикс вроде QUIC/DNS применился сразу, а не только при следующем нажатии
   **Route** в клиенте) и перезапускает `sing-box`
5. Создаёт systemd-юнит `jackal-policy-routing`, если его ещё нет (в старых деплоях его
   не было — без него policy routing для TProxy не переживает перезагрузку)

### Настройка роутера (один раз)

1. Подключите кабель: `LAN-порт ноутбука → WAN-порт роутера`
2. Подключите телефон/ПК к Wi-Fi роутера
3. Откройте веб-интерфейс роутера (обычно `192.168.0.1` или `192.168.1.1`)
4. Найдите **WAN / Интернет / Тип подключения** → выберите **DHCP (Динамический IP)**
5. Сохраните, подождите 15 секунд

### Клиент (Windows)

```bash
python client/client.py
```

Либо запустите отдельный `.exe` (Python на целевой машине не нужен) — соберите его:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name JackalRouter --distpath client/dist --workpath client/build --specpath client client/client.py
```

Результат — `client/dist/JackalRouter.exe`. Своё состояние (историю прокси, последний
использованный IP сервера) хранит в `proxy_history.json` / `client_config.json` рядом с
самим `.exe` — IP сервера нигде не захардкожен: поле стартует пустым и запоминает
последний введённый IP.

1. Введите локальный IP Ubuntu
2. Вставьте строку SOCKS5 прокси в одном из форматов:
   - `ip:port:логин:пароль`
   - `логин:пароль@ip:port`
   - `socks5://логин:пароль@ip:port`
3. Нажмите **Проверить прокси** — проверка TCP, показывает IP / город / ISP
4. Нажмите **Проверить UDP** — проверка поддержки SOCKS5 UDP ASSOCIATE (нужна для QUIC)
5. Нажмите **Проверить чистоту** — проверка репутации exit-IP через открытые источники
   (флаги `proxy` / `hosting` / `mobile` от ip-api.com) + замер скорости и задержки:
   - **ЧИСТЫЙ** — резидентный IP, без меток
   - **Datacenter** — хостинговый IP, повышает fraud-score антидетектов
   - **ГРЯЗНЫЙ** — помечен как proxy/VPN/Tor
6. Нажмите **Route** — весь трафик устройств на роутере идёт через прокси

Баннер **Раздаётся** вверху показывает exit-IP, который сейчас раздаётся устройствам
роутера, и его гео (страна / город / ISP). Обновляется автоматически после Route /
Проверки сервера или по кнопке ⟳. Значение определяет сам сервер (запрос к ip-api.com
через активный прокси); если у сервера нет эндпоинта `/current_ip`, клиент определяет
IP сам (по сохранённой учётке прокси).

Вкладка **История** хранит каждый применённый/проверенный прокси с гео, иконкой статуса
и последней замеренной скоростью; оттуда можно загрузить, перепроверить или удалить запись.

### API сервера

Сервер слушает на порту `8000`:

```
POST /set_proxy     {"proxy_string": "ip:port:user:pass"}
GET  /status        → {"sing_box": "active", "dnsmasq": "active", "iptables": "ok", "proxy": "1.2.3.4:1080"}
GET  /current_ip    → {"ok": true, "exit_ip": "5.6.7.8", "countryCode": "US", "city": "...", "isp": "..."}
GET  /proxy_health  → {"ok": true, "stalled": false, "got_bytes": 524288, "elapsed": 2.1, "kbps": 243.0}
```

### Управление сервисом

```bash
sudo systemctl status jackalrouter
sudo systemctl status sing-box
sudo journalctl -u sing-box -f
sudo journalctl -u jackalrouter -f
```

# Contributors

- [@MorganWeistling](https://github.com/MorganWeistling)

---

## License

https://t.me/Carl0s_Jackal
