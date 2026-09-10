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
import sys
import shutil
import tempfile
import socket
import ssl
import struct
import time
import threading
import concurrent.futures as cf
import logging
import ipaddress
import urllib.request
from typing import Tuple
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# ── Настройки ─────────────────────────────────────────────────────────────────
INT_IFACE    = "enp3s0"                   # LAN-интерфейс (к техническому роутеру)
SINGBOX_PORT = 7893                        # TProxy inbound port
SINGBOX_CONF = "/etc/sing-box/config.json"
# Каталог создают все четыре деплой-скрипта и apply_iptables, поэтому отдельный
# шаг установки под этот файл не нужен.
STATE_FILE   = "/var/lib/sing-box/jackal_state.json"
SERVER_PORT  = 8000
GITHUB_REPO  = "MorganWeistling/JackalRouter"   # источник для кнопки Update в клиенте
GITHUB_REF   = "main"

# Резолвер, которым sing-box резолвит ВЕСЬ клиентский трафик — ходит через прокси.
# Только IP-литералы: у сертификатов 8.8.8.8 и 1.1.1.1 адрес прописан в IP SAN,
# поэтому режим DoH работает с полной проверкой сертификата и без bootstrap-
# резолва самого резолвера (иначе получили бы ту же DNS-петлю, что и с доменом
# прокси). ALT пробуется, только если основной недоступен через прокси.
PROXY_DNS_IP   = "8.8.8.8"
PROXY_DNS_ALT  = "1.1.1.1"
PROBE_TIMEOUT  = 5    # лимит на ОДНУ пробу апстрима
PROBE_DEADLINE = 9    # лимит на ВСЕ пробы разом: клиент ждёт /set_proxy 15 с
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


def _is_ipv4_literal(value: str) -> bool:
    """Строгая проверка на IPv4 — для выбора ATYP в SOCKS5-запросе, где v6
    потребовал бы ATYP=4 и другой упаковки адреса. Весь тракт всё равно ipv4_only."""
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _dns_query(name: str = "example.com") -> bytes:
    """Минимальный DNS-запрос A-записи (без длины — её добавляет транспорт)."""
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in name.encode().split(b"."):
        q += bytes([len(part)]) + part
    return q + b"\x00\x00\x01\x00\x01"


def _recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes:
    """recv() возвращает столько, сколько пришло, а не сколько попросили.
    Для SOCKS5-ответа это обычно сходит с рук, но если сразу за ним идёт
    TLS-хендшейк (DoH-проба), недочитанный хвост ломает поток. Дочитываем ровно n."""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("connection closed")
        buf += chunk
    return buf


def check_udp_associate(ip: str, port: int, user: str, password: str,
                        timeout: int = 6) -> bool:
    """Проверяет, поддерживает ли апстрим-прокси SOCKS5 UDP ASSOCIATE.

    Обнаружено на живой коробке: часть мобильных/резидентных прокси отклоняет
    команду ASSOCIATE кодом 7 ("Command not supported"). Без этой проверки
    sing-box всё равно пытается пускать QUIC через такой прокси — relay
    падает, и TPROXY молча роняет пакеты. С точки зрения телефона это выглядит
    как "сайты не открываются": браузер зависает в ожидании QUIC-хендшейка
    вместо мгновенного отката на TCP. Результат идёт в make_singbox_conf(),
    чтобы либо разрешить QUIC через прокси (когда реально работает — не
    роняет fraud-score резидентного IP), либо явно заблокировать его (когда
    прокси всё равно не может его релеить — быстрый и чистый отказ лучше
    тихого зависания)."""
    t = u = None
    try:
        t = socket.create_connection((ip, port), timeout=timeout)
        t.settimeout(timeout)
        has_auth = bool(user and password)
        methods = b"\x02" if has_auth else b"\x00"
        t.sendall(b"\x05" + bytes([len(methods)]) + methods)
        resp = t.recv(2)
        if len(resp) < 2 or resp[0] != 5 or resp[1] == 0xFF:
            return False
        if resp[1] == 2:
            uu, pp = user.encode(), password.encode()
            t.sendall(b"\x01" + bytes([len(uu)]) + uu + bytes([len(pp)]) + pp)
            resp = t.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                return False
        t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        resp = t.recv(10)
        if len(resp) < 10 or resp[1] != 0:
            return False  # code=7 (Command not supported) и подобные — сюда
        bnd_ip = socket.inet_ntoa(resp[4:8])
        bnd_port = struct.unpack("!H", resp[8:10])[0]
        if bnd_ip in ("0.0.0.0", "127.0.0.1"):
            bnd_ip = ip
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton(PROXY_DNS_IP) \
            + struct.pack("!H", 53) + _dns_query()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(timeout)
        u.sendto(pkt, (bnd_ip, bnd_port))
        data, _ = u.recvfrom(2048)
        return len(data) > 10
    except Exception:
        return False
    finally:
        for sk in (u, t):
            try:
                if sk:
                    sk.close()
            except Exception:
                pass


def make_singbox_conf(ip: str, port: int, user: str, password: str,
                      udp_supported: bool = True, block_quic: bool = False,
                      dns_mode: str = "tcp53", dns_server: str = PROXY_DNS_IP) -> dict:
    # Если upstream-прокси не поддерживает SOCKS5 UDP ASSOCIATE, QUIC/HTTP3
    # нельзя безопасно запускать через него: это гарантированно приводит к
    # зависанию/залипанию QUIC-хендшейка. Делаем явный запрет QUIC не только
    # когда пользователь вручную включил флаг, но и когда proxy не умеет UDP.
    effective_block_quic = block_quic or not udp_supported

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

    # Транспорт резолвера, который ходит ЧЕРЕЗ прокси. Тег "proxy-dns" одинаков
    # в обоих режимах, поэтому dns.final, route.default_domain_resolver и правило
    # "resolve" ссылаются на него как раньше — меняется только способ доставки.
    # Оба варианта идут внутри туннеля, так что на утечки выбор не влияет.
    # ВАЖНО: только "https" (HTTP/2 поверх TCP), но НЕ "h3" — h3 это QUIC поверх
    # UDP, а он тут либо заблокирован правилом, либо не релеится прокси вообще.
    if dns_mode == "doh":
        proxy_dns_server = {"type": "https", "tag": "proxy-dns",
                            "server": dns_server, "detour": "proxy"}
    else:
        proxy_dns_server = {"type": "tcp", "tag": "proxy-dns",
                            "server": dns_server, "detour": "proxy"}

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
    ]
    if effective_block_quic:
        # Явная блокировка QUIC: используется для улучшения детекта резидентного IP
        # и избежания медленных соединений когда QUIC не поддерживается прокси.
        # Но это ломает приложения вроде Bet365 которые требуют QUIC/HTTP3.
        route_rules.append({"protocol": "quic", "outbound": "block"})
    route_rules.append({"ip_is_private": True, "outbound": "direct"})
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
    # ВАЖНО, проверено на живой коробке: SOCKS5 умеет принимать домен нативно
    # (ATYP=domain), и sing-box по умолчанию просто передаёт домен прокси как
    # есть — резолвит его САМ ПРОКСИ, на своей стороне. У части провайдеров
    # (особенно резидентных/мобильных) инфраструктура, которая резолвит домены,
    # топологически НЕ совпадает с точкой выхода трафика: реальные HTTP(S)-
    # соединения уходили корректно через residential-exit (США), а тест
    # определения DNS-резолвера показывал совсем другую страну. "domain_strategy"
    # на самом outbound здесь НЕ помогает — по документированному поведению
    # sing-box он не действует для протоколов, которые умеют резолвить домены
    # сами (SOCKS5 — из их числа); проверено эмпирически, эффекта не было.
    # Рабочий способ — явный "resolve" ПОСЛЕДНИМ правилом: резолвит домен ДО
    # выбора аутбаунда (через default_domain_resolver, то есть тем же прокси-
    # туннелем, но уже IP-запросом на 8.8.8.8, а не доменным ATYP), и до прокси
    # долетает уже готовый IP. Стоит последним, чтобы все правила выше
    # (direct/block по домену) успели отработать на оригинальном домене.
    route_rules.append({"action": "resolve", "strategy": "ipv4_only"})

    socks_out = {
        "type": "socks",
        "tag": "proxy",
        "server": ip,
        "server_port": port,
        "version": "5",
        "username": user,
        "password": password,
        # ПРИМЕЧАНИЕ: "domain_strategy" тут намеренно НЕ ставим — проверено
        # эмпирически на живой коробке, что для SOCKS5 (умеет ATYP=domain
        # нативно) это поле не действует и никак не влияет на резолв домена.
        # Настоящий фикс той же проблемы — правило "resolve" в route.rules
        # (см. ниже), которое резолвит домен ДО выбора аутбаунда.
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
                proxy_dns_server,
                # Без detour — используется только для адреса самого прокси
                {"type": "tcp", "tag": "direct-dns", "server": PROXY_DNS_IP},
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


def make_singbox_bypass_conf() -> dict:
    """Конфиг для режима БЕЗ прокси — весь трафик идёт напрямую через WAN.
    DNS перехватывается TPROXY (iptables), но резолвится напрямую без FakeIP."""
    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"type": "tcp", "tag": "direct-dns", "server": "8.8.8.8"},
            ],
            "rules": [
                {"query_type": [64, 65], "action": "reject"},
            ],
            "final": "direct-dns",
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "0.0.0.0",
            "listen_port": SINGBOX_PORT,
        }],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block",  "tag": "block"},
        ],
        "route": {
            "default_domain_resolver": "direct-dns",
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": "direct",
        },
        "experimental": {
            "cache_file": {
                "enabled": False,
            }
        },
    }


def read_state() -> dict:
    """Состояние коробки, которое НЕЛЬЗЯ вывести из config.json. Всё выводимое
    (режим DNS, наличие блокировки QUIC) по-прежнему читается из самого конфига —
    единственный источник истины, чтобы нечему было рассинхронизироваться."""
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def write_state(**values) -> None:
    st = read_state()
    st.update(values)
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(st, f, indent=2)
    except Exception as e:
        log.warning(f"Не удалось записать {STATE_FILE}: {e}")


def read_quic_pref() -> bool:
    """Галка «блокировать QUIC» — это ВЫБОР пользователя, и вывести его из
    конфига нельзя: правило блокировки выглядит одинаково и когда галку
    поставили руками, и когда QUIC заблокирован автоматически, потому что прокси
    не умеет UDP ASSOCIATE (effective_block_quic). Без отдельного хранения
    /status возвращал бы автоблокировку как выбор пользователя, и галка в
    клиенте прыгала бы обратно сама. Поэтому храним отдельно."""
    st = read_state()
    if "block_quic" in st:
        return bool(st["block_quic"])
    # Коробка ещё не знает про state-файл (сразу после обновления) — ведём себя
    # как раньше и выводим значение из конфига.
    try:
        conf = json.load(open(SINGBOX_CONF))
        for rule in conf.get("route", {}).get("rules", []):
            if rule.get("protocol") == "quic" and rule.get("outbound") == "block":
                return True
    except Exception:
        pass
    return False


def write_singbox_conf(ip: str, port: int, user: str, password: str,
                       udp_supported: bool = True, block_quic: bool = False,
                       dns_mode: str = "tcp53", dns_server: str = PROXY_DNS_IP):
    os.makedirs(os.path.dirname(SINGBOX_CONF), exist_ok=True)
    conf = make_singbox_conf(ip, port, user, password, udp_supported=udp_supported,
                             block_quic=block_quic, dns_mode=dns_mode, dns_server=dns_server)
    with open(SINGBOX_CONF, "w") as f:
        json.dump(conf, f, indent=2)
    # Запоминаем именно ВЫБОР пользователя, а не итоговую блокировку.
    write_state(block_quic=bool(block_quic))
    log.info(f"Записан {SINGBOX_CONF}  [{ip}:{port}]  udp_supported={udp_supported}  "
             f"block_quic={block_quic}  effective_block_quic={block_quic or not udp_supported}  "
             f"dns={dns_mode}:{dns_server}")


def write_singbox_bypass_conf():
    """Пишет bypass-конфиг (без прокси, весь трафик прямо)."""
    os.makedirs(os.path.dirname(SINGBOX_CONF), exist_ok=True)
    conf = make_singbox_bypass_conf()
    with open(SINGBOX_CONF, "w") as f:
        json.dump(conf, f, indent=2)
    log.info(f"Записан {SINGBOX_CONF}  (bypass режим, прокси отключен)")


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
    """Достаёт активный прокси (ip/port/user/pass) из текущего config.json sing-box,
    плюс режим резолвера. Источник истины — сам конфиг, отдельного файла состояния
    нет: он бы рассинхронизировался. Режим однозначно читается по типу транспорта
    proxy-dns, и это важно для /set_quic — он перезаписывает конфиг целиком и без
    этого сбросил бы DoH обратно на :53, положив прокси, которым :53 недоступен."""
    conf = json.load(open(SINGBOX_CONF))

    dns_mode, dns_server = "tcp53", PROXY_DNS_IP
    for srv in conf.get("dns", {}).get("servers", []):
        if srv.get("tag") == "proxy-dns":
            dns_mode = "doh" if srv.get("type") == "https" else "tcp53"
            dns_server = srv.get("server", PROXY_DNS_IP)
            break

    for ob in conf.get("outbounds", []):
        if ob.get("tag") == "proxy":
            return {
                "ip":         ob["server"],
                "port":       int(ob["server_port"]),
                "user":       ob.get("username", ""),
                "password":   ob.get("password", ""),
                "dns_mode":   dns_mode,
                "dns_server": dns_server,
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
    if _is_ipv4_literal(target_host):
        # ATYP=1 — ровно так адресует и sing-box: правило "resolve" разворачивает
        # домен в IP ДО выбора аутбаунда, и до прокси долетает уже IP. Пробы
        # обязаны повторять этот путь, иначе проверят не то, что поедет в бою.
        req = b"\x05\x01\x00\x01" + socket.inet_aton(target_host)
    else:
        d = target_host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(d)]) + d
    s.sendall(req + target_port.to_bytes(2, "big"))
    # Ответ читаем по длине ATYP, а не фиксированными 10 байтами: при ATYP=3
    # (домен) хвост остаётся в сокете и портит следующий за ним TLS-хендшейк.
    try:
        resp = _recv_exact(s, 4, timeout)
        if resp[1] != 0:
            raise RuntimeError("rejected")
        atyp = resp[3]
        if atyp == 1:
            _recv_exact(s, 6, timeout)
        elif atyp == 3:
            _recv_exact(s, _recv_exact(s, 1, timeout)[0] + 2, timeout)
        elif atyp == 4:
            _recv_exact(s, 18, timeout)
    except Exception:
        s.close(); raise RuntimeError("proxy CONNECT failed")
    return s


def probe_dns_tcp53(ip: str, port: int, user: str, password: str,
                    server: str = PROXY_DNS_IP, timeout: int = PROBE_TIMEOUT) -> bool:
    """Проверяет plain DNS-over-TCP :53 через прокси — ровно тот транспорт,
    которым резолвит sing-box в режиме dns_mode="tcp53".

    Обнаружено на живой коробке: резидентные шлюзы (nsocks.com) отбивают CONNECT
    на ЛЮБОЙ адрес с портом 53 и 853 кодом 2 ("not allowed by ruleset") — типовой
    антиабуз против DNS-туннелей. Порты 80/443 при этом открыты. Для нас это
    фатально: на proxy-dns завязаны и dns.final, и route.default_domain_resolver,
    и правило "resolve", которое дёргается на КАЖДОЕ соединение. Резолв не
    проходит — устройства просто виснут, «сайты не открываются»."""
    s = None
    try:
        s = socks5_connect(ip, port, user, password, server, 53, timeout=timeout)
        q = _dns_query()
        s.sendall(struct.pack("!H", len(q)) + q)          # DNS-over-TCP: префикс длины
        n = struct.unpack("!H", _recv_exact(s, 2, timeout))[0]
        return 12 <= n <= 4096 and len(_recv_exact(s, n, timeout)) == n
    except Exception:
        return False
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def probe_dns_doh(ip: str, port: int, user: str, password: str,
                  server: str = PROXY_DNS_IP, timeout: int = PROBE_TIMEOUT) -> bool:
    """Проверяет DoH (RFC 8484) по :443 через прокси — запасной транспорт для
    резолвера, когда апстрим режет :53. Проверка сертификата НЕ ослаблена:
    server всегда IP-литерал, а он есть в IP SAN сертификатов 8.8.8.8 и 1.1.1.1."""
    s = None
    try:
        s = socks5_connect(ip, port, user, password, server, 443, timeout=timeout)
        s = ssl.create_default_context().wrap_socket(s, server_hostname=server)
        q = _dns_query()
        s.sendall(b"POST /dns-query HTTP/1.1\r\nHost: " + server.encode()
                  + b"\r\nContent-Type: application/dns-message\r\n"
                    b"Accept: application/dns-message\r\nContent-Length: "
                  + str(len(q)).encode() + b"\r\nConnection: close\r\n\r\n" + q)
        s.settimeout(timeout)
        buf = b""
        while len(buf) < 65536:
            head, _, body = buf.partition(b"\r\n\r\n")
            if head != buf and len(body) >= 12:      # заголовки дочитаны и тело есть
                break
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        return head.startswith(b"HTTP/1.1 200") and len(body) >= 12
    except Exception:
        return False
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def probe_proxy(ip: str, port: int, user: str, password: str) -> dict:
    """Один заход всех проверок апстрима: что он умеет — то и включаем в конфиге.

    Пробы идут ПАРАЛЛЕЛЬНО и с общим дедлайном: клиент ждёт /set_proxy не дольше
    TIMEOUT=15 с, а последовательно (UDP + :53 + DoH) в этот бюджет не влезть.
    Кто не уложился — считается неподдержанным: консервативный ответ безопаснее."""
    t_end = time.time() + PROBE_DEADLINE
    ex = cf.ThreadPoolExecutor(max_workers=3)
    try:
        f_udp   = ex.submit(check_udp_associate, ip, port, user, password, PROBE_TIMEOUT)
        f_tcp53 = ex.submit(probe_dns_tcp53, ip, port, user, password, PROXY_DNS_IP, PROBE_TIMEOUT)
        f_doh   = ex.submit(probe_dns_doh,   ip, port, user, password, PROXY_DNS_IP, PROBE_TIMEOUT)

        def got(fut) -> bool:
            try:
                return bool(fut.result(timeout=max(0.0, t_end - time.time())))
            except Exception:
                return False

        udp_ok, tcp53_ok, doh_ok = got(f_udp), got(f_tcp53), got(f_doh)
    finally:
        # wait=False: не держим ответ ради «опоздавших» проб, их сокеты закроются сами.
        ex.shutdown(wait=False)

    if tcp53_ok:
        # Приоритет у plain :53 намеренно: это ровно тот конфиг, который уже
        # работает на всём текущем парке прокси. DoH включаем только там, где
        # без него не поедет вообще — так фикс не меняет поведение остальных.
        dns_mode, dns_server = "tcp53", PROXY_DNS_IP
    elif doh_ok:
        dns_mode, dns_server = "doh", PROXY_DNS_IP
    elif probe_dns_doh(ip, port, user, password, PROXY_DNS_ALT, PROBE_TIMEOUT):
        dns_mode, dns_server = "doh", PROXY_DNS_ALT
    else:
        # Ни :53, ни DoH. На direct-dns НЕ откатываемся ни при каких условиях:
        # резолв мимо туннеля — это утечка DNS через реальный IP коробки, ровно
        # то, ради чего весь проект. Оставляем как было и жалуемся в лог.
        dns_mode, dns_server = "tcp53", PROXY_DNS_IP
        log.warning("Прокси не отдаёт ни DNS :53, ни DoH :443 — оставляю :53. "
                    "Резолв, скорее всего, работать не будет; прокси нерабочий.")

    log.info(f"Прокси умеет: UDP ASSOCIATE={'да' if udp_ok else 'НЕТ (QUIC заблокирую)'}, "
             f"DNS :53={'да' if tcp53_ok else 'НЕТ'}, DoH :443={'да' if doh_ok else 'нет'} "
             f"→ резолвер {dns_mode} через {dns_server}")
    return {"udp_supported": udp_ok, "dns_mode": dns_mode, "dns_server": dns_server}


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
        log.info("Проверяю возможности прокси (UDP ASSOCIATE, транспорт DNS) перед применением…")
        caps = probe_proxy(proxy["ip"], proxy["port"], proxy["user"], proxy["password"])

        write_singbox_conf(
            ip=proxy["ip"], port=proxy["port"],
            user=proxy["user"], password=proxy["password"],
            udp_supported=caps["udp_supported"],
            dns_mode=caps["dns_mode"], dns_server=caps["dns_server"],
        )
        log.info("Конфиг записан, перезапуск sing-box в фоне…")
        def restart_in_bg():
            code, _, err = run("systemctl restart sing-box")
            if code != 0:
                log.error(f"Ошибка перезапуска sing-box: {err}")
            else:
                log.info("sing-box перезапущен успешно.")
        threading.Thread(target=restart_in_bg, daemon=True).start()
        return {
            "status": "ok",
            "message": "Прокси применён, sing-box перезапущен.",
            "proxy": f"{proxy['ip']}:{proxy['port']}",
            "udp_supported": caps["udp_supported"],
            "dns_mode": caps["dns_mode"],
            "dns_server": caps["dns_server"],
        }
    except Exception as e:
        log.error(f"Ошибка применения прокси: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/set_quic")
async def set_quic(block_quic: bool):
    """Включить/отключить блокировку QUIC.
    block_quic=True: блокировать QUIC (лучше для детекта, может ломать Bet365)
    block_quic=False: разрешить QUIC (работает Bet365, может быть медленнее)"""
    try:
        log.info(f"Устанавливаю QUIC блокировку: {block_quic}")
        proxy_data = read_active_proxy()
        # udp_supported перепроверяем, а не подставляем True: с effective_block_quic
        # захардкоженный True на прокси без UDP ASSOCIATE снова разрешил бы QUIC —
        # то самое зависание хендшейка, ради которого блокировка и вводилась.
        udp_ok = check_udp_associate(proxy_data["ip"], proxy_data["port"],
                                     proxy_data["user"], proxy_data["password"],
                                     PROBE_TIMEOUT)
        # dns_mode берём из конфига, а не пробуем заново: разовый сбой пробы
        # сбросил бы DoH на :53 и положил прокси, которому :53 закрыт.
        write_singbox_conf(
            ip=proxy_data["ip"], port=proxy_data["port"],
            user=proxy_data["user"], password=proxy_data["password"],
            udp_supported=udp_ok,
            block_quic=block_quic,
            dns_mode=proxy_data["dns_mode"], dns_server=proxy_data["dns_server"],
        )
        log.info("Конфиг записан, перезапуск sing-box в фоне…")
        def restart_in_bg():
            code, _, err = run("systemctl restart sing-box")
            if code != 0:
                log.error(f"Ошибка перезапуска sing-box: {err}")
            else:
                log.info(f"sing-box перезапущен. QUIC: {'блокирован' if block_quic else 'разрешен'}")
        threading.Thread(target=restart_in_bg, daemon=True).start()
        return {
            "status": "ok",
            "quic_blocked": block_quic,
            # На прокси без UDP ASSOCIATE QUIC остаётся заблокирован независимо
            # от галки — иначе хендшейк зависает. Отдаём это отдельным полем,
            # чтобы расхождение было видно, а не выглядело как игнор настройки.
            "quic_effective": block_quic or not udp_ok,
            "message": f"QUIC: {'блокирован' if block_quic else 'разрешен'}",
        }
    except Exception as e:
        log.error(f"Ошибка при установке QUIC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Самообновление (кнопка Update в клиенте) ────────────────────────────────
# То же самое, что делает update.py по SSH, но выполняется НА САМОЙ коробке —
# клиент не умеет SSH, только HTTP к этому серверу. INT_IFACE_RE тот же
# формат, что использует update.py на удалённой стороне.
INT_IFACE_RE = re.compile(r'^INT_IFACE\s*=\s*"[^"]*"', re.MULTILINE)


_GETADDRINFO_LOCK = threading.Lock()


def urlopen_ipv4(url: str, timeout: int = 15) -> bytes:
    """urlopen, принудительно по IPv4.

    raw.githubusercontent.com отдаёт и A, и AAAA. У коробки IPv6-адрес обычно
    есть, а рабочего маршрута наружу нет, и socket.create_connection перебирает
    адреса ПОСЛЕДОВАТЕЛЬНО — Happy Eyeballs в stdlib нет. Поэтому первая же
    AAAA-попытка съедает таймаут целиком, и только после неё идёт IPv4.
    Замерено на живой коробке: 15.3 с против 0.9 с за тот же файл с ноутбука,
    то есть ровно timeout=15 в никуда. Из-за этого клиент отваливался по своему
    30-секундному таймауту раньше, чем сервер успевал применить обновление.

    Резолв сужаем до AF_INET только на время запроса и под локом. Для этой
    коробки IPv4-only и так штатный режим: ip6tables рубит форвардинг, sing-box
    работает в ipv4_only."""
    with _GETADDRINFO_LOCK:
        orig = socket.getaddrinfo

        def ipv4_only(host, port, family=0, *args, **kwargs):
            return orig(host, port, socket.AF_INET, *args, **kwargs)

        socket.getaddrinfo = ipv4_only
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read()
        finally:
            socket.getaddrinfo = orig


def fetch_github_server_py() -> str:
    url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_REF}/server/server.py"
    content = urlopen_ipv4(url, timeout=15).decode("utf-8")
    if "def make_singbox_conf" not in content:
        raise ValueError("похоже на не тот файл (нет make_singbox_conf)")
    return content


def normalize_int_iface(new_content: str, cur_content: str) -> str:
    """INT_IFACE — своя для каждой коробки, тянуть чужую с GitHub нельзя."""
    m = INT_IFACE_RE.search(cur_content)
    if not m:
        return new_content
    return INT_IFACE_RE.sub(m.group(0), new_content, count=1)


def validate_new_server_py(content: str) -> Tuple[bool, str]:
    """Компилирует и делает лёгкий import-smoke-test НОВОГО файла в отдельном
    подпроцессе, не трогая текущий работающий процесс. На self-update-рестарте
    (в отличие от update.py по SSH) откатывать уже некому, если новый код не
    взлетит — процесс, который мог бы это заметить, сам будет убит рестартом.
    Поэтому здесь всё проверяем ДО замены файла, а не после."""
    fd, tmp_path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)

        r = subprocess.run([sys.executable, "-m", "py_compile", tmp_path],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return False, f"Синтаксическая ошибка: {r.stderr.strip()[:500]}"

        check_code = (
            "import importlib.util\n"
            f"spec = importlib.util.spec_from_file_location('_selfupdate_check', {tmp_path!r})\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
        )
        r2 = subprocess.run([sys.executable, "-c", check_code],
                            capture_output=True, text=True, timeout=15)
        if r2.returncode != 0:
            return False, f"Ошибка импорта: {r2.stderr.strip()[-500:]}"
        return True, ""
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def ensure_policy_routing_unit():
    """Тот же юнит, что создаёт update.py по SSH — без него ip rule/ip route
    для TProxy не переживают перезагрузку."""
    unit_path = "/etc/systemd/system/jackal-policy-routing.service"
    if os.path.exists(unit_path):
        return
    with open(unit_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(
            "[Unit]\n"
            "Description=JackalRouter: policy routing for TProxy (fwmark 1 -> table 100)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "Before=sing-box.service\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "RemainAfterExit=yes\n"
            "ExecStart=/bin/sh -c 'ip rule add fwmark 1 table 100 2>/dev/null; "
            "ip route add local default dev lo table 100 2>/dev/null; exit 0'\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
    run("systemctl daemon-reload")
    run("systemctl enable jackal-policy-routing -q")
    run("ip rule add fwmark 1 table 100")
    run("ip route add local default dev lo table 100")


@app.get("/self_update/check")
async def self_update_check():
    """Ничего не меняет — только сообщает, есть ли обновление на GitHub."""
    try:
        new_content = fetch_github_server_py()
    except Exception as e:
        return {"status": "error", "error": f"GitHub недоступен: {e}"}

    cur_content = open(os.path.abspath(__file__), "r", encoding="utf-8").read()
    new_content = normalize_int_iface(new_content, cur_content)
    return {"status": "ok", "update_available": new_content != cur_content}


@app.post("/self_update")
async def self_update():
    """Тянет актуальный server.py с GitHub и применяет его прямо на коробке —
    кнопка Update в клиенте, SSH не требуется. Config.json перегенерируется
    под уже настроенный прокси СРАЗУ (старым, ещё не заменённым кодом —
    новые функции для этого не нужны), а сам процесс (jackalrouter)
    перезапускается последним, в фоне, чтобы ответ успел уйти клиенту."""
    try:
        new_content = fetch_github_server_py()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub недоступен: {e}")

    cur_path = os.path.abspath(__file__)
    cur_content = open(cur_path, "r", encoding="utf-8").read()
    new_content = normalize_int_iface(new_content, cur_content)

    if new_content == cur_content:
        return {"status": "uptodate", "message": "Уже последняя версия."}

    log.info("self_update: проверяю новый server.py перед применением…")
    valid, err = validate_new_server_py(new_content)
    if not valid:
        log.error(f"self_update: новая версия не прошла проверку: {err}")
        raise HTTPException(status_code=500,
                            detail=f"Новая версия не прошла проверку, НЕ применена: {err}")

    backup_path = f"{cur_path}.bak-{time.strftime('%Y%m%d%H%M%S')}"
    shutil.copy2(cur_path, backup_path)
    with open(cur_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(new_content)
    log.info(f"self_update: server.py обновлён (бэкап {backup_path})")

    # Всё, что осталось, уводим в фон: клиент ждёт ответа 30 с, а перегенерация
    # конфига (проба апстрима) плюс два systemctl restart в этот бюджет уже не
    # помещаются. Для клиента обновление СЧИТАЕТСЯ применённым в момент, когда
    # новый файл записан — это уже произошло выше; остальное к ответу не
    # относится и всё равно завершается рестартом самого процесса, исход
    # которого клиент увидеть не может. Порядок прежний: конфиг → sing-box →
    # сам сервис.
    def apply_rest():
        time.sleep(1.5)  # дать HTTP-ответу уйти клиенту до тяжёлой части
        # Конфиг под текущий прокси перегенерируем НОВЫМ кодом — подпроцессом,
        # который импортирует уже записанный файл. В памяти этого процесса живёт
        # старая версия, и она не знает про возможности, добавленные обновлением:
        # коробка на прокси с закрытым :53 получила бы от старого кода конфиг с
        # plain-DNS и осталась бы нерабочей до следующего нажатия Route в клиенте.
        # Файл только что прошёл import-smoke-test в validate_new_server_py, так
        # что импортировать его безопасно. Если новая версия таких функций не знает
        # (откат на старую) — тихо падаем обратно на старый путь.
        regen_code = (
            "import importlib.util, json\n"
            f"spec = importlib.util.spec_from_file_location('_regen', {cur_path!r})\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            "p = m.read_active_proxy()\n"
            "pref = m.read_quic_pref()\n"
            "caps = m.probe_proxy(p['ip'], p['port'], p['user'], p['password'])\n"
            "m.write_singbox_conf(p['ip'], p['port'], p['user'], p['password'],\n"
            "                     udp_supported=caps['udp_supported'], block_quic=pref,\n"
            "                     dns_mode=caps['dns_mode'], dns_server=caps['dns_server'])\n"
            "print(json.dumps(caps))\n"
        )
        try:
            r = subprocess.run([sys.executable, "-c", regen_code],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip()[-300:])
            run("systemctl restart sing-box")
            log.info(f"self_update: конфиг перегенерирован новым кодом: {r.stdout.strip()}")
        except Exception as e:
            log.warning(f"self_update: перегенерация новым кодом не удалась ({e}); пробую старым…")
            try:
                proxy = read_active_proxy()
                udp_ok = check_udp_associate(proxy["ip"], proxy["port"],
                                             proxy["user"], proxy["password"])
                write_singbox_conf(proxy["ip"], proxy["port"], proxy["user"], proxy["password"],
                                   udp_supported=udp_ok)
                run("systemctl restart sing-box")
                log.info(f"self_update: конфиг перегенерирован (udp_supported={udp_ok})")
            except Exception as e2:
                log.warning(f"self_update: перегенерировать конфиг прокси не удалось "
                            f"(нет активного прокси?): {e2}")

        ensure_policy_routing_unit()
        code, _, err = run("systemctl restart jackalrouter")
        if code != 0:
            log.error(f"self_update: не удалось перезапустить jackalrouter: {err}")
    threading.Thread(target=apply_rest, daemon=True).start()

    return {
        "status": "updated",
        "message": "Обновление применено, сервис перезапускается…",
        "backup": backup_path,
    }


@app.post("/stop_proxy")
async def stop_proxy():
    """Отключает прокси-туннель и возвращает DNS в прямой режим.
    Конфиг sing-box переписывается на bypass: весь трафик идёт напрямую,
    DNS перехватывается TPROXY (iptables) но резолвится напрямую без FakeIP.
    Перезапуск sing-box происходит асинхронно в фоне (не ждём ответа)."""
    try:
        log.info("Отключаю прокси-туннель…")
        write_singbox_bypass_conf()
        log.info("Конфиг записан, перезапуск sing-box в фоне…")
        def restart_in_bg():
            code, _, err = run("systemctl restart sing-box")
            if code != 0:
                log.error(f"Ошибка перезапуска sing-box: {err}")
            else:
                log.info("sing-box перезапущен в bypass-режиме.")
        threading.Thread(target=restart_in_bg, daemon=True).start()
        return {
            "status": "ok",
            "message": "Прокси отключен, весь трафик идёт напрямую.",
            "mode": "bypass",
        }
    except Exception as e:
        log.error(f"Ошибка отключения прокси: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status")
async def status():
    def svc(name: str) -> str:
        _, out, _ = run(f"systemctl is-active {name}")
        return out.strip()

    iptables_ok = run("iptables -t mangle -L SING_BOX -n")[0] == 0

    proxy = None
    mode = "bypass"
    quic_effective = False
    dns_mode = None
    try:
        conf = json.load(open(SINGBOX_CONF))
        for srv in conf.get("dns", {}).get("servers", []):
            if srv.get("tag") == "proxy-dns":
                dns_mode = "doh" if srv.get("type") == "https" else "tcp53"
                break
        for ob in conf.get("outbounds", []):
            if ob.get("tag") == "proxy":
                proxy = f"{ob['server']}:{ob['server_port']}"
                mode = "proxy"
                break
        # Есть ли правило блокировки QUIC в маршрутах — это ФАКТ, а не выбор
        # пользователя: правило могло появиться и автоматически, из-за прокси
        # без UDP ASSOCIATE.
        for rule in conf.get("route", {}).get("rules", []):
            if rule.get("protocol") == "quic" and rule.get("outbound") == "block":
                quic_effective = True
                break
    except Exception:
        pass

    return {
        "sing_box": svc("sing-box"),
        "dnsmasq":  svc("dnsmasq"),
        "iptables": "ok" if iptables_ok else "error",
        "iface":    INT_IFACE,
        "port":     SINGBOX_PORT,
        "mode":     mode,
        "proxy":    proxy,
        # quic_blocked — под ним стоит галка в клиенте, поэтому это выбор
        # пользователя. quic_effective — что реально в конфиге: на прокси без
        # UDP ASSOCIATE QUIC заблокирован независимо от галки.
        "quic_blocked":   read_quic_pref(),
        "quic_effective": quic_effective,
        "dns_mode": dns_mode,
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
