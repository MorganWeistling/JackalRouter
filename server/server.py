#!/usr/bin/env python3
"""
JackalRouter — FastAPI-сервер для Ubuntu
Управляет sing-box (TProxy) и правилами iptables.
Запускать от root: sudo python3 server.py
"""

import subprocess
import json
import re
import os
import socket
import ssl
import time
import logging
import ipaddress
from typing import Tuple
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# ── Настройки ─────────────────────────────────────────────────────────────────
INT_IFACE    = "enp3s0"                   # LAN-интерфейс (к техническому роутеру)
SINGBOX_PORT = 7893                        # TProxy inbound port
SINGBOX_CONF = "/etc/sing-box/config.json"
SERVER_PORT  = 8000
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Стартовая инициализация. Раньше это был @app.on_event("startup") —
    его выпилят в будущих версиях FastAPI, поэтому используем lifespan
    (поддерживается начиная с FastAPI 0.93, наш нижний порог — 0.111).
    apply_iptables объявлена ниже по файлу: тело выполняется при старте,
    а не в момент определения, поэтому прямая ссылка тут корректна."""
    if os.geteuid() != 0:
        log.warning("Сервер запущен НЕ от root — правила iptables могут не примениться!")
    apply_iptables()
    yield


app = FastAPI(title="JackalRouter Server", lifespan=lifespan)


class ProxyRequest(BaseModel):
    proxy_string: str


def run(cmd: str, check: bool = False) -> Tuple[int, str, str]:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"CMD failed: {cmd}\n{r.stderr.strip()}")
    return r.returncode, r.stdout.strip(), r.stderr.strip()


# ── sing-box конфиг ───────────────────────────────────────────────────────────

def _is_ip_literal(value: str) -> bool:
    """Адрес прокси — это уже IP, или его ещё надо резолвить?"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def make_singbox_conf(ip: str, port: int, user: str, password: str) -> dict:
    # Адрес прокси часто задают доменом (например geo.iproyal.com). Такой домен
    # НЕЛЬЗЯ резолвить через сам прокси: чтобы подключиться к прокси, надо
    # сначала узнать его адрес, а чтобы узнать адрес — надо подключиться к
    # прокси. sing-box ловит это и рвёт соединение с ошибкой
    #   "lookup <домен>: DNS query loopback in transport[proxy-dns]"
    # — наружу при этом не уходит вообще ничего.
    # Поэтому для домена прокси добавляем direct-dns (без detour) и правила,
    # которые резолвят и маршрутизируют именно его напрямую. Весь остальной
    # трафик по-прежнему идёт через прокси, утечек это не добавляет.
    proxy_is_domain = not _is_ip_literal(ip)

    # ВАЖНО: одних dns.rules тут НЕ хватает. route.default_domain_resolver
    # задаёт DNS-сервер для резолва адресов исходящих соединений напрямую,
    # минуя dns.rules — проверено на живой коробке: правило в dns.rules есть,
    # а ошибка loopback остаётся. Рабочий способ — per-outbound override
    # "domain_resolver" на самом socks-outbound (см. ниже). dns.rules
    # оставляем как второй рубеж.
    dns_rules = []
    if proxy_is_domain:
        # ОБЯЗАТЕЛЬНО раньше правила fakeip — иначе домен прокси получит
        # фейковый адрес 198.18.x.x, и подключиться к прокси будет невозможно.
        dns_rules.append({"domain": [ip], "server": "direct-dns"})
    dns_rules += [
        {"query_type": ["A"], "server": "fakeip"},
        {"query_type": [64, 65], "action": "reject"},
    ]

    route_rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    if proxy_is_domain:
        # Трафик к самому прокси не должен заворачиваться в прокси.
        route_rules.append({"domain": [ip], "outbound": "direct"})
    route_rules += [
        # Блокируем DoH (DNS-over-HTTPS) и DoT (DNS-over-TLS):
        # телефон получит отказ → упадёт на plain UDP DNS :53 →
        # sing-box перехватит hijack-dns → ответит FakeIP (нет утечки IP)
        {"domain": ["dns.google", "one.one.one.one", "cloudflare-dns.com", "doh.pub", "doh.360.cn"], "outbound": "block"},
        {"port": 853, "outbound": "block"},
    ]

    socks_out = {
        "type": "socks",
        "tag": "proxy",
        "server": ip,
        "server_port": port,
        "version": "5",
        "username": user,
        "password": password,
    }
    if proxy_is_domain:
        # Тот самый рабочий фикс: адрес самого прокси резолвим напрямую,
        # а не через прокси. Без него sing-box падает с
        # "DNS query loopback in transport[proxy-dns]" и наружу не идёт НИЧЕГО.
        # Поле проверено `sing-box check` на 1.13 — конфиг принимается.
        socks_out["domain_resolver"] = "direct-dns"

    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"},
                {"type": "tcp", "tag": "proxy-dns", "server": "8.8.8.8", "detour": "proxy"},
                # Без detour — используется только для адреса самого прокси
                {"type": "tcp", "tag": "direct-dns", "server": "8.8.8.8"},
            ],
            "rules": dns_rules,
            "final": "proxy-dns",
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "0.0.0.0",
            "listen_port": SINGBOX_PORT,
        }],
        "outbounds": [
            socks_out,
            {"type": "direct", "tag": "direct"},
            {"type": "block",  "tag": "block"},
        ],
        "route": {
            "default_domain_resolver": "proxy-dns",
            "rules": route_rules,
            "final": "proxy",
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "store_fakeip": True,
                "path": "/var/lib/sing-box/cache.db",
            }
        },
    }


def write_singbox_conf(ip: str, port: int, user: str, password: str):
    os.makedirs(os.path.dirname(SINGBOX_CONF), exist_ok=True)
    conf = make_singbox_conf(ip, port, user, password)
    with open(SINGBOX_CONF, "w") as f:
        json.dump(conf, f, indent=2)
    log.info(f"Записан {SINGBOX_CONF}  [{ip}:{port}]")


# ── iptables (TProxy) ─────────────────────────────────────────────────────────

def apply_iptables():
    log.info(f"Настраиваю iptables TProxy на интерфейсе {INT_IFACE}…")

    steps = [
        # Форвардинг
        "sysctl -w net.ipv4.ip_forward=1",

        # Policy routing: пакеты с меткой 1 → lo (локальная доставка для TProxy)
        "ip rule del fwmark 1 table 100 2>/dev/null || true",
        "ip rule add fwmark 1 table 100",
        "ip route del local default dev lo table 100 2>/dev/null || true",
        "ip route add local default dev lo table 100",

        # Убираем старую цепочку redsocks (nat), если осталась с прошлой версии
        f"iptables -t nat -D PREROUTING -i {INT_IFACE} -p tcp -j REDSOCKS 2>/dev/null || true",
        "iptables -t nat -F REDSOCKS 2>/dev/null || true",
        "iptables -t nat -X REDSOCKS 2>/dev/null || true",

        # MSS clamp 1280 — фиксим PMTUD через туннель (обе стороны enp3s0)
        f"iptables -t mangle -D PREROUTING -i {INT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280 2>/dev/null || true",
        f"iptables -t mangle -A PREROUTING -i {INT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280",
        f"iptables -t mangle -D POSTROUTING -o {INT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280 2>/dev/null || true",
        f"iptables -t mangle -A POSTROUTING -o {INT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280",

        # Mangle цепочка SING_BOX
        "iptables -t mangle -N SING_BOX 2>/dev/null || true",
        "iptables -t mangle -F SING_BOX",
        # DNS клиентов перехватываем ПЕРВЫМ делом — до RETURN'ов для приватных
        # сетей ниже. Иначе запросы на 10.0.0.1:53 (а именно этот адрес выдаёт
        # dnsmasq от NetworkManager в режиме shared) попадают под
        # "-d 10.0.0.0/8 -j RETURN", уходят мимо sing-box и резолвятся напрямую
        # — это утечка DNS в обход прокси. Проверено на живой коробке.
        f"iptables -t mangle -A SING_BOX -p udp --dport 53 -j TPROXY --on-port {SINGBOX_PORT} --tproxy-mark 1",
        f"iptables -t mangle -A SING_BOX -p tcp --dport 53 -j TPROXY --on-port {SINGBOX_PORT} --tproxy-mark 1",
        "iptables -t mangle -A SING_BOX -d 0.0.0.0/8 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 10.0.0.0/8 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 127.0.0.0/8 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 169.254.0.0/16 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 172.16.0.0/12 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 192.168.0.0/16 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 224.0.0.0/4 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 240.0.0.0/4 -j RETURN",
        # Весь UDP (DNS :53 → FakeIP, QUIC :443, STUN…) → TProxy → sing-box →
        # SOCKS5 UDP ASSOCIATE. QUIC проксируется, а не блокируется: отсутствие
        # рабочего UDP/QUIC у "резидентного" IP повышает fraud-score антидетектов.
        f"iptables -t mangle -A SING_BOX -p udp -j TPROXY --on-port {SINGBOX_PORT} --tproxy-mark 1",
        # Весь TCP → TProxy → sing-box → SOCKS5 (domain отправляет по FakeIP-маппингу)
        f"iptables -t mangle -A SING_BOX -p tcp -j TPROXY --on-port {SINGBOX_PORT} --tproxy-mark 1",
        # Привязка к LAN-интерфейсу
        f"iptables -t mangle -D PREROUTING -i {INT_IFACE} -j SING_BOX 2>/dev/null || true",
        f"iptables -t mangle -A PREROUTING -i {INT_IFACE} -j SING_BOX",

        # MASQUERADE
        "iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || "
        "iptables -t nat -A POSTROUTING -j MASQUERADE",

        # IPv6 полностью блокируем
        f"ip6tables -D FORWARD -i {INT_IFACE} -j DROP 2>/dev/null || true",
        f"ip6tables -A FORWARD -i {INT_IFACE} -j DROP",
        f"ip6tables -D FORWARD -o {INT_IFACE} -j DROP 2>/dev/null || true",
        f"ip6tables -A FORWARD -o {INT_IFACE} -j DROP",

        # Каталог для fakeip cache
        "mkdir -p /var/lib/sing-box",

        # Отключаем GRO/GSO/TSO: предотвращаем сборку сегментов больше MSS на enp3s0
        f"ethtool -K {INT_IFACE} gro off gso off tso off lro off 2>/dev/null || true",
    ]

    for cmd in steps:
        code, out, err = run(cmd)
        if code != 0 and err:
            log.warning(f"  [{code}] {cmd}  =>  {err}")

    log.info("iptables TProxy правила применены.")


# ── Утилиты ───────────────────────────────────────────────────────────────────

def parse_proxy(proxy_string: str) -> dict:
    s = proxy_string.strip()
    # Убираем схему: socks5h://, socks5://, http:// и т.п.
    s = re.sub(r'^[a-zA-Z0-9+.\-]+://', '', s)
    m = re.match(r'^([^:@]+):(.+)@([\d.]+):(\d+)$', s)
    if m:
        return {"ip": m.group(3), "port": int(m.group(4)),
                "user": m.group(1), "password": m.group(2)}
    parts = s.split(":", 3)
    if len(parts) == 4 and re.match(r'^\d{1,5}$', parts[1]):
        return {"ip": parts[0], "port": int(parts[1]),
                "user": parts[2], "password": parts[3]}
    raise ValueError(
        f"Неверный формат прокси: '{s}'. "
        "Ожидается 'ip:port:user:pass' или 'user:pass@ip:port'."
    )


def err_code(msg: str) -> str:
    """Классифицирует текст ошибки в машинный код — клиент локализует по нему."""
    m = str(msg).lower()
    if "no proxy" in m:                               return "no_proxy"
    if "auth failed" in m:                            return "socks_auth"
    if "auth methods" in m or "bad socks5" in m:      return "socks_handshake"
    if "connect failed" in m:                         return "socks_connect"
    if "timed out" in m or "timeout" in m:            return "timeout"
    if "ssl" in m or "certificate" in m or "tls" in m: return "tls"
    return "other"


def read_active_proxy() -> dict:
    """Достаёт активный прокси (ip/port/user/pass) из текущего config.json sing-box."""
    conf = json.load(open(SINGBOX_CONF))
    for ob in conf.get("outbounds", []):
        if ob.get("tag") == "proxy":
            return {
                "ip":       ob["server"],
                "port":     int(ob["server_port"]),
                "user":     ob.get("username", ""),
                "password": ob.get("password", ""),
            }
    raise RuntimeError("no proxy outbound (tag=proxy) in config.json")


def http_get_via_socks(host: str, port: int, user: str, password: str,
                       target_host: str, target_port: int, path: str,
                       timeout: int = 15) -> bytes:
    """Простой HTTP GET через SOCKS5-прокси (raw, без сторонних зависимостей).
    Используем HTTP/1.0 + Connection: close — ответ без chunked, читаем до EOF."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.settimeout(timeout)
        has_auth = bool(user and password)
        methods = b"\x02" if has_auth else b"\x00"
        s.sendall(b"\x05" + bytes([len(methods)]) + methods)
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            raise RuntimeError("bad SOCKS5 response")
        if resp[1] == 0xFF:
            raise RuntimeError("proxy refused auth methods")
        if resp[1] == 2:
            u, p = user.encode(), password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            resp = s.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                raise RuntimeError("proxy auth failed")
        d = target_host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d
                  + target_port.to_bytes(2, "big"))
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            raise RuntimeError("proxy CONNECT failed")
        req = (f"GET {path} HTTP/1.0\r\n"
               f"Host: {target_host}\r\n"
               f"User-Agent: JackalRouter\r\n"
               f"Accept: application/json\r\n\r\n")
        s.sendall(req.encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        sep = buf.find(b"\r\n\r\n")
        return buf[sep + 4:] if sep >= 0 else buf
    finally:
        s.close()


def socks5_connect(host: str, port: int, user: str, password: str,
                   target_host: str, target_port: int, timeout: int = 12) -> socket.socket:
    """SOCKS5 рукопожатие + CONNECT к target. Возвращает открытый сокет."""
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    has_auth = bool(user and password)
    methods = b"\x02" if has_auth else b"\x00"
    s.sendall(b"\x05" + bytes([len(methods)]) + methods)
    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 5:
        s.close(); raise RuntimeError("bad SOCKS5 response")
    if resp[1] == 0xFF:
        s.close(); raise RuntimeError("proxy refused auth methods")
    if resp[1] == 2:
        u, p = user.encode(), password.encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        resp = s.recv(2)
        if len(resp) < 2 or resp[1] != 0:
            s.close(); raise RuntimeError("proxy auth failed")
    d = target_host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + target_port.to_bytes(2, "big"))
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0:
        s.close(); raise RuntimeError("proxy CONNECT failed")
    return s


# Параметры health-теста пропускной способности
HEALTH_HOST  = "speed.cloudflare.com"
HEALTH_BYTES = 524288        # 512 КБ — реальная bulk-передача (мёртвый прокси встаёт ~17 КБ)
HEALTH_TOTAL_TIMEOUT = 25    # общий лимит на скачивание
HEALTH_IDLE_TIMEOUT  = 8     # если прокси не шлёт данные дольше — считаем «затык»


def proxy_health_test(proxy: dict) -> dict:
    """Качает HEALTH_BYTES через активный прокси (HTTPS, SOCKS5+TLS) и проверяет,
    что данные реально докачались, а не встали после первого буфера.
    Отличает рабочий прокси от «мёртвого», который отдаёт ~17 КБ и виснет."""
    t0 = time.time()
    raw = socks5_connect(proxy["ip"], proxy["port"], proxy["user"],
                         proxy["password"], HEALTH_HOST, 443, timeout=12)
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(raw, server_hostname=HEALTH_HOST)
    try:
        req = (f"GET /__down?bytes={HEALTH_BYTES} HTTP/1.1\r\n"
               f"Host: {HEALTH_HOST}\r\n"
               f"User-Agent: JackalRouter\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        s.sendall(req.encode())
        s.settimeout(HEALTH_IDLE_TIMEOUT)
        buf = b""
        header_done = False
        body = 0
        stalled = False
        while True:
            if time.time() - t0 > HEALTH_TOTAL_TIMEOUT:
                stalled = True
                break
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                stalled = True          # данные перестали идти — прокси завис
                break
            if not chunk:
                break                   # EOF (Connection: close) — докачали
            if not header_done:
                buf += chunk
                sep = buf.find(b"\r\n\r\n")
                if sep >= 0:
                    header_done = True
                    body += len(buf) - (sep + 4)
            else:
                body += len(chunk)
            if body >= HEALTH_BYTES:
                break
        elapsed = time.time() - t0
        ok = (body >= HEALTH_BYTES * 0.95) and not stalled
        return {
            "ok":         ok,
            "stalled":    stalled,
            "got_bytes":  body,
            "want_bytes": HEALTH_BYTES,
            "elapsed":    round(elapsed, 2),
            "kbps":       round(body / 1024 / elapsed, 1) if elapsed > 0 else 0,
        }
    finally:
        try:
            s.close()
        except Exception:
            pass


# ── Эндпоинты ─────────────────────────────────────────────────────────────────

@app.post("/set_proxy")
async def set_proxy(req: ProxyRequest):
    try:
        proxy = parse_proxy(req.proxy_string)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        write_singbox_conf(
            ip=proxy["ip"], port=proxy["port"],
            user=proxy["user"], password=proxy["password"],
        )
        code, _, err = run("systemctl restart sing-box")
        if code != 0:
            raise RuntimeError(f"systemctl restart sing-box: {err}")
        log.info("sing-box перезапущен успешно.")
        return {
            "status": "ok",
            "message": "Прокси применён, sing-box перезапущен.",
            "proxy": f"{proxy['ip']}:{proxy['port']}",
        }
    except Exception as e:
        log.error(f"Ошибка применения прокси: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status")
async def status():
    def svc(name: str) -> str:
        _, out, _ = run(f"systemctl is-active {name}")
        return out.strip()

    iptables_ok = run("iptables -t mangle -L SING_BOX -n")[0] == 0

    proxy = None
    try:
        conf = json.load(open(SINGBOX_CONF))
        for ob in conf.get("outbounds", []):
            if ob.get("tag") == "proxy":
                proxy = f"{ob['server']}:{ob['server_port']}"
                break
    except Exception:
        pass

    return {
        "sing_box": svc("sing-box"),
        "dnsmasq":  svc("dnsmasq"),
        "iptables": "ok" if iptables_ok else "error",
        "iface":    INT_IFACE,
        "port":     SINGBOX_PORT,
        "proxy":    proxy,
    }


@app.get("/current_ip")
async def current_ip():
    """Возвращает exit-IP и гео того прокси, что сейчас раздаётся в сеть.
    Запрос к ip-api.com идёт ЧЕРЕЗ активный прокси (по его учётке из config.json),
    поэтому показывает ровно тот IP, под которым выходят устройства роутера."""
    try:
        proxy = read_active_proxy()
    except Exception as e:
        return {"ok": False, "error": f"no proxy configured: {e}", "error_code": "no_proxy"}

    proxy_str = f"{proxy['ip']}:{proxy['port']}"
    try:
        body = http_get_via_socks(
            proxy["ip"], proxy["port"], proxy["user"], proxy["password"],
            "ip-api.com", 80,
            "/json/?fields=status,message,country,countryCode,regionName,city,isp,query",
        )
        data = json.loads(body.decode("utf-8", "ignore"))
        if data.get("status") != "success":
            return {"ok": False, "proxy": proxy_str, "error_code": "geo",
                    "error": data.get("message", "geo lookup failed")}
        return {
            "ok":          True,
            "proxy":       proxy_str,
            "exit_ip":     data.get("query"),
            "country":     data.get("country"),
            "countryCode": data.get("countryCode"),
            "region":      data.get("regionName"),
            "city":        data.get("city"),
            "isp":         data.get("isp"),
        }
    except Exception as e:
        return {"ok": False, "proxy": proxy_str,
                "error": str(e), "error_code": err_code(e)}


@app.get("/proxy_health")
def proxy_health():
    """Честный тест пропускной способности активного прокси РЕАЛЬНЫМ путём
    (с Ubuntu через прокси). Качает 512 КБ и проверяет, что докачалось.
    Синхронный def — FastAPI выполнит его в threadpool, не блокируя сервер."""
    try:
        proxy = read_active_proxy()
    except Exception as e:
        return {"ok": False, "error": f"no proxy configured: {e}", "error_code": "no_proxy"}

    proxy_str = f"{proxy['ip']}:{proxy['port']}"
    try:
        r = proxy_health_test(proxy)
        r["proxy"] = proxy_str
        return r
    except Exception as e:
        return {"ok": False, "proxy": proxy_str,
                "error": str(e), "error_code": err_code(e)}


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT)
