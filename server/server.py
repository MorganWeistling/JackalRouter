#!/usr/bin/env python3
"""
JackalRouter — FastAPI-сервер для Ubuntu
Управляет sing-box (TProxy) и правилами iptables.
Запускать от root: sudo python3 server.py
"""

import asyncio
import collections
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
from typing import Optional, Tuple
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
# Только IP-литералы: у сертификатов 1.1.1.1 и 8.8.8.8 адрес прописан в IP SAN,
# поэтому режим DoH работает с полной проверкой сертификата и без bootstrap-
# резолва самого резолвера (иначе получили бы ту же DNS-петлю, что и с доменом
# прокси). ALT пробуется, только если основной недоступен через прокси.
#
# Основной — Cloudflare, не Google: сайты умеют по «DNS-утечке» проверять, что
# страна резолверов совпадает со страной IP (whoer.net снимает за несовпадение
# 30% «маскировки»). Замерено на живой коробке с прокси в Испании: резолверы
# Google для такого клиента — США/Бельгия (AS15169), а Cloudflare отвечает с
# ближайшего PoP выходной ноды — Испания (AS13335). У Google мало площадок и
# рекурсивные запросы уходят с адресов, которые почти везде геолоцируются в США.
PROXY_DNS_IP   = "1.1.1.1"
PROXY_DNS_ALT  = "8.8.8.8"
# Резолвер для адреса самого прокси (мимо туннеля, см. direct-dns): на детект не
# влияет, поэтому остаётся прежним — то, что уже работает на всём парке.
DIRECT_DNS_IP  = "8.8.8.8"
PROBE_TIMEOUT  = 5    # лимит на ОДНУ пробу апстрима
PROBE_DEADLINE = 9    # лимит на ВСЕ пробы разом: клиент ждёт /set_proxy 15 с
# Локальный ускоритель SOCKS5-рукопожатия (см. FastRelay). Только loopback.
FAST_RELAY_HOST = "127.0.0.1"
FAST_RELAY_PORT = 7894
GITHUB_FETCH_DEADLINE = 15   # лимит на загрузку с GitHub: клиент ждёт /self_update 30 с
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
    ensure_singbox_conf_compat()
    # Свой поток и свой event loop: часть эндпоинтов блокирующая (пробы до 9 с,
    # health-тест до 25 с), в общем цикле uvicorn они замораживали бы весь трафик.
    threading.Thread(target=FAST_RELAY.serve_forever, name="fast-relay", daemon=True).start()
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


_SO_MARK = getattr(socket, "SO_MARK", 36)   # 36 — значение из linux/socket.h


def routing_mark_of(outbound: dict) -> int:
    mark = outbound.get("routing_mark") or 0
    return int(mark, 0) if isinstance(mark, str) else int(mark)


def proxy_routing_mark() -> int:
    """routing_mark пути до прокси: метка AmneziaWG, если туннель включён, иначе
    routing_mark outbound'а "proxy" из текущего config.json (0, если его нет).

    Пробы и тесты обязаны ходить к прокси тем же маршрутом, что sing-box и
    FastRelay. На коробке с маршрутизацией по метке (локальный патч ставит 100 →
    VPN-туннель) прямой путь ведёт себя совсем иначе: проверено — без метки
    /proxy_health вставал на ~17 КБ и показывал «мёртвый прокси», хотя трафик
    устройств через тот же прокси шёл нормально."""
    mark = awg_routing_mark()
    if mark:
        return mark
    try:
        with open(SINGBOX_CONF) as f:
            conf = json.load(f)
        for ob in conf.get("outbounds", []):
            if ob.get("tag") == "proxy":
                return routing_mark_of(ob)
    except Exception:
        pass
    return 0


def apply_proxy_mark(sock: socket.socket, mark: int) -> None:
    if mark and sys.platform.startswith("linux"):
        sock.setsockopt(socket.SOL_SOCKET, _SO_MARK, mark)


def connect_to_proxy(host: str, port: int, timeout: float) -> socket.socket:
    """socket.create_connection, но с routing_mark прокси (см. proxy_routing_mark)."""
    mark = proxy_routing_mark()
    if not mark:
        return socket.create_connection((host, port), timeout=timeout)
    err = None
    for af, kind, proto, _, addr in socket.getaddrinfo(host, port, socket.AF_INET,
                                                       socket.SOCK_STREAM):
        s = socket.socket(af, kind, proto)
        try:
            apply_proxy_mark(s, mark)
            s.settimeout(timeout)
            s.connect(addr)
            return s
        except OSError as e:
            s.close()
            err = e
    raise err or OSError(f"не удалось подключиться к {host}:{port}")


SOCKS5_ASSOCIATE_ANY = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"   # «слать буду с любого адреса»


def socks5_hello(user: str, password: str) -> bytes:
    """Приветствие SOCKS5 и, если есть логин, авторизация — одним куском.
    Метод предлагаем ровно один, как и sing-box: иначе сервер мог бы выбрать
    «без авторизации», и отправленные следом логин/пароль он прочитал бы как
    CONNECT."""
    if user and password:
        u, p = user.encode(), password.encode()
        return b"\x05\x01\x02\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p
    return b"\x05\x01\x00"


SINGBOX_BIN = "/usr/local/bin/sing-box"
_singbox_version_cache = {}


def singbox_version() -> tuple:
    """Версия установленного sing-box, (1, 14, 1); () если не удалось узнать.
    Кэш привязан к mtime бинарника — после его замены версия перечитается."""
    try:
        mtime = os.stat(SINGBOX_BIN).st_mtime_ns
        if mtime not in _singbox_version_cache:
            out = subprocess.run([SINGBOX_BIN, "version"], capture_output=True,
                                 text=True, timeout=10).stdout
            m = re.search(r"version (\d+)\.(\d+)\.(\d+)", out)
            _singbox_version_cache.clear()
            _singbox_version_cache[mtime] = tuple(int(x) for x in m.groups()) if m else ()
        return _singbox_version_cache[mtime]
    except Exception:
        return ()


def singbox_has_dns_optimistic() -> bool:
    return singbox_version() >= (1, 14, 0)


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
                        timeout: int = 6, pipelined: bool = False) -> bool:
    """Проверяет, поддерживает ли апстрим-прокси SOCKS5 UDP ASSOCIATE.

    pipelined=True — то же, но приветствие + логин + ASSOCIATE одним пакетом,
    как это делает FastRelay: только при успехе UDP пускается через него.

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
        t = connect_to_proxy(ip, port, timeout)
        t.settimeout(timeout)
        has_auth = bool(user and password)
        if pipelined:
            t.sendall(socks5_hello(user, password) + SOCKS5_ASSOCIATE_ANY)
            g = _recv_exact(t, 2, timeout)
            if g[0] != 5 or g[1] != (2 if has_auth else 0):
                return False
            if has_auth and _recv_exact(t, 2, timeout)[1] != 0:
                return False
            resp = _recv_exact(t, 10, timeout)
            if resp[1] != 0 or resp[3] != 1:
                return False
        else:
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
            t.sendall(SOCKS5_ASSOCIATE_ANY)
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
        apply_proxy_mark(u, proxy_routing_mark())     # UDP sing-box идёт с той же меткой
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
                      dns_mode: str = "tcp53", dns_server: str = PROXY_DNS_IP,
                      fast_relay: bool = False, fast_udp: bool = False,
                      dns_optimistic: bool = False, routing_mark: int = 0) -> dict:
    # fast_udp — UDP тоже через ретранслятор. Только поверх fast_relay и только
    # для прокси, у которого UDP ASSOCIATE вообще работает.
    fast_udp = fast_udp and fast_relay and udp_supported
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

    # Весь TCP (включая резолвер) идёт через локальный ускоритель рукопожатия,
    # если апстрим его выдерживает (probe_socks_pipelining). UDP — через него же
    # только при fast_udp, иначе остаётся на обычном socks-outbound "proxy".
    tcp_out = "proxy-fast" if fast_relay else "proxy"

    # Транспорт резолвера, который ходит ЧЕРЕЗ прокси. Тег "proxy-dns" одинаков
    # в обоих режимах, поэтому dns.final, route.default_domain_resolver и правило
    # "resolve" ссылаются на него как раньше — меняется только способ доставки.
    # Оба варианта идут внутри туннеля, так что на утечки выбор не влияет.
    # ВАЖНО: только "https" (HTTP/2 поверх TCP), но НЕ "h3" — h3 это QUIC поверх
    # UDP, а он тут либо заблокирован правилом, либо не релеится прокси вообще.
    if dns_mode == "doh":
        proxy_dns_server = {"type": "https", "tag": "proxy-dns",
                            "server": dns_server, "detour": tcp_out}
    else:
        proxy_dns_server = {"type": "tcp", "tag": "proxy-dns",
                            "server": dns_server, "detour": tcp_out}

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
    if fast_relay and not fast_udp:
        route_rules.append({"network": "udp", "outbound": "proxy"})

    socks_out = {
        "type": "socks",
        "tag": "proxy",
        "server": ip,
        "server_port": port,
        "version": "5",
        "username": user,
        "password": password,
        # TCP Fast Open до прокси: SOCKS5-приветствие уходит прямо в SYN, минус
        # 1 RTT на каждое новое соединение (и на каждый DNS-запрос через proxy-dns).
        # Работает, только если TFO включён на стороне прокси; если нет — ядро
        # молча делает обычный хендшейк, данные в SYN не шлются без cookie.
        # Путь трафика и DNS не меняется: в SYN только методы авторизации,
        # логин/пароль идут следующим шагом, как и раньше.
        "tcp_fast_open": True,
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
    if routing_mark:
        # Путь до прокси — через AmneziaWG (см. awg_*). Ретранслятор и пробы
        # берут метку отсюда же.
        socks_out["routing_mark"] = routing_mark

    # "proxy" остаётся первым и с настоящим адресом апстрима: его читают
    # read_active_proxy, /status, update.py и локальные патчи (routing_mark).
    outbounds = [socks_out]
    if fast_relay:
        fast_out = {"type": "socks", "tag": "proxy-fast", "server": FAST_RELAY_HOST,
                    "server_port": FAST_RELAY_PORT, "version": "5"}
        if user and password:
            fast_out.update(username=user, password=password)
        outbounds.append(fast_out)
    outbounds += [
        {"type": "direct", "tag": "direct"},
        {"type": "block",  "tag": "block"},
    ]

    dns = {
        "servers": [
            {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"},
            proxy_dns_server,
            # Без detour — используется только для адреса самого прокси
            {"type": "tcp", "tag": "direct-dns", "server": DIRECT_DNS_IP},
        ],
        "rules": dns_rules,
        "final": "proxy-dns",
        "strategy": "ipv4_only",
    }
    if dns_optimistic:
        # sing-box >= 1.14: просроченный ответ отдаётся сразу, обновление — в
        # фоне. Правило "resolve" перед каждым соединением перестаёт ждать
        # резолвер на повторных визитах. Кэш только в памяти (store_dns не
        # включаем), а sing-box перезапускается при каждой смене прокси —
        # адреса, полученные через прошлый прокси, не переживают смену.
        dns["optimistic"] = True

    return {
        "log": {"level": "info"},
        "dns": dns,
        "inbounds": [{
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "0.0.0.0",
            "listen_port": SINGBOX_PORT,
        }],
        "outbounds": outbounds,
        "route": {
            "default_domain_resolver": "proxy-dns",
            "rules": route_rules,
            "final": tcp_out,
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
                       dns_mode: str = "tcp53", dns_server: str = PROXY_DNS_IP,
                       fast_relay=None, fast_udp=None):
    # None — решаем пробой здесь же. Так ускоритель включается и там, где
    # вызывающий про него не знает: код перегенерации в update.py и в
    # /self_update ПРЕДЫДУЩЕЙ версии (он исполняется старым процессом).
    if fast_relay is None:
        fast_relay = probe_socks_pipelining(ip, port, user, password)
    if fast_udp is None:
        fast_udp = bool(fast_relay and udp_supported and check_udp_associate(
            ip, port, user, password, PROBE_TIMEOUT, pipelined=True))
    dns_optimistic = singbox_has_dns_optimistic()
    routing_mark = awg_routing_mark()
    os.makedirs(os.path.dirname(SINGBOX_CONF), exist_ok=True)
    conf = make_singbox_conf(ip, port, user, password, udp_supported=udp_supported,
                             block_quic=block_quic, dns_mode=dns_mode, dns_server=dns_server,
                             fast_relay=fast_relay, fast_udp=fast_udp,
                             dns_optimistic=dns_optimistic, routing_mark=routing_mark)
    with open(SINGBOX_CONF, "w") as f:
        json.dump(conf, f, indent=2)
    # Запоминаем именно ВЫБОР пользователя, а не итоговую блокировку.
    write_state(block_quic=bool(block_quic))
    log.info(f"Записан {SINGBOX_CONF}  [{ip}:{port}]  udp_supported={udp_supported}  "
             f"block_quic={block_quic}  effective_block_quic={block_quic or not udp_supported}  "
             f"dns={dns_mode}:{dns_server}  fast_relay={fast_relay}  "
             f"fast_udp={bool(fast_udp and fast_relay and udp_supported)}  "
             f"dns_optimistic={dns_optimistic}  awg_mark={routing_mark}")


def ensure_singbox_conf_compat() -> None:
    """Конфиг с полем, которого не знает установленный sing-box, не загрузится
    вовсе — это полный простой. Такое бывает после отката бинарника (например,
    деплой-скрипт взял запасную версию). При старте убираем такие поля."""
    try:
        with open(SINGBOX_CONF) as f:
            conf = json.load(f)
    except Exception:
        return
    dns = conf.get("dns", {})
    if "optimistic" in dns and not singbox_has_dns_optimistic():
        dns.pop("optimistic")
        with open(SINGBOX_CONF, "w") as f:
            json.dump(conf, f, indent=2)
        log.warning(f"sing-box {singbox_version()} не знает dns.optimistic — убрал из "
                    f"конфига, перезапускаю sing-box")
        run("systemctl restart sing-box")


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


def config_fast_paths(conf: dict) -> Tuple[bool, bool]:
    """(TCP через ретранслятор, UDP через ретранслятор) — прямо из конфига.
    UDP идёт через него, если есть proxy-fast, а отдельного правила
    «UDP → proxy» нет."""
    fast = any(ob.get("tag") == "proxy-fast" for ob in conf.get("outbounds", []))
    udp_to_proxy = any(r.get("network") == "udp" and r.get("outbound") == "proxy"
                       for r in conf.get("route", {}).get("rules", []))
    return fast, fast and not udp_to_proxy


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

    outbounds = conf.get("outbounds", [])
    fast_relay, fast_udp = config_fast_paths(conf)
    for ob in outbounds:
        if ob.get("tag") == "proxy":
            return {
                "ip":         ob["server"],
                "port":       int(ob["server_port"]),
                "user":       ob.get("username", ""),
                "password":   ob.get("password", ""),
                "dns_mode":   dns_mode,
                "dns_server": dns_server,
                "fast_relay": fast_relay,
                "fast_udp":   fast_udp,
            }
    raise RuntimeError("no proxy outbound (tag=proxy) in config.json")


def http_get_via_socks(host: str, port: int, user: str, password: str,
                       target_host: str, target_port: int, path: str,
                       timeout: int = 15) -> bytes:
    """Простой HTTP GET через SOCKS5-прокси (raw, без сторонних зависимостей).
    Используем HTTP/1.0 + Connection: close — ответ без chunked, читаем до EOF."""
    s = connect_to_proxy(host, port, timeout)
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
    s = connect_to_proxy(host, port, timeout)
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
    """Проверяет DoH (RFC 8484) по :443 через прокси — основной транспорт
    резолвера (быстрее :53, см. probe_proxy). Проверка сертификата НЕ ослаблена:
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


def probe_socks_pipelining(ip: str, port: int, user: str, password: str,
                           timeout: int = PROBE_TIMEOUT) -> bool:
    """Выдерживает ли апстрим рукопожатие одним пакетом — ровно то, что делает
    FastRelay: приветствие + логин + CONNECT + первые данные клиента разом.

    Первые данные — настоящий TLS ClientHello к PROXY_DNS_IP:443 (тот же адрес,
    что у DoH-пробы). Хендшейк завершается, только если сервер не выбросил
    байты, пришедшие вместе с CONNECT: наивная реализация SOCKS5, читающая
    каждый шаг в свежий буфер, на этом и сломается — такой прокси остаётся на
    обычном последовательном рукопожатии sing-box. Сертификат проверяется."""
    s = None
    try:
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ssl.create_default_context().wrap_bio(incoming, outgoing,
                                                    server_hostname=PROXY_DNS_IP)
        try:
            tls.do_handshake()
        except ssl.SSLWantReadError:
            pass
        has_auth = bool(user and password)
        s = connect_to_proxy(ip, port, timeout)
        s.sendall(socks5_hello(user, password)
                  + b"\x05\x01\x00\x01" + socket.inet_aton(PROXY_DNS_IP) + struct.pack("!H", 443)
                  + outgoing.read())
        g = _recv_exact(s, 2, timeout)
        if g[0] != 5 or g[1] != (2 if has_auth else 0):
            return False
        if has_auth and _recv_exact(s, 2, timeout)[1] != 0:
            return False
        r = _recv_exact(s, 4, timeout)
        if r[1] != 0:
            return False
        if r[3] == 1:
            _recv_exact(s, 6, timeout)
        elif r[3] == 3:
            _recv_exact(s, _recv_exact(s, 1, timeout)[0] + 2, timeout)
        elif r[3] == 4:
            _recv_exact(s, 18, timeout)
        while True:
            data = s.recv(16384)
            if not data:
                return False
            incoming.write(data)
            try:
                tls.do_handshake()
                return True
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    s.sendall(pending)
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
    ex = cf.ThreadPoolExecutor(max_workers=5)
    try:
        f_udp   = ex.submit(check_udp_associate, ip, port, user, password, PROBE_TIMEOUT)
        f_tcp53 = ex.submit(probe_dns_tcp53, ip, port, user, password, PROXY_DNS_IP, PROBE_TIMEOUT)
        f_doh   = ex.submit(probe_dns_doh,   ip, port, user, password, PROXY_DNS_IP, PROBE_TIMEOUT)
        f_pipe  = ex.submit(probe_socks_pipelining, ip, port, user, password, PROBE_TIMEOUT)
        f_upipe = ex.submit(check_udp_associate, ip, port, user, password, PROBE_TIMEOUT, True)

        def got(fut) -> bool:
            try:
                return bool(fut.result(timeout=max(0.0, t_end - time.time())))
            except Exception:
                return False

        udp_ok, tcp53_ok, doh_ok, pipe_ok = got(f_udp), got(f_tcp53), got(f_doh), got(f_pipe)
        # UDP через ретранслятор — только если прокси умеет UDP вообще и принимает
        # ASSOCIATE одним пакетом. Прокси без UDP остаётся на прежнем пути.
        udp_pipe_ok = udp_ok and pipe_ok and got(f_upipe)
    finally:
        # wait=False: не держим ответ ради «опоздавших» проб, их сокеты закроются сами.
        ex.shutdown(wait=False)

    if doh_ok:
        # Приоритет у DoH — ради задержки. Транспорт "tcp" в sing-box открывает
        # НОВОЕ соединение на каждый запрос (dns/transport/tcp.go, v1.13.13), то
        # есть полный SOCKS5-хендшейк через прокси: ~5 RTT на каждый некэшированный
        # домен, а правило "resolve" гоняет резолв перед КАЖДЫМ новым соединением.
        # DoH держит HTTP/2-соединение открытым — на тёплом канале ~1 RTT.
        # Утечек это не добавляет: оба транспорта идут через detour=proxy на тот
        # же резолвер, а DoH ещё и прячет домены от самого прокси-провайдера.
        dns_mode, dns_server = "doh", PROXY_DNS_IP
    elif tcp53_ok:
        dns_mode, dns_server = "tcp53", PROXY_DNS_IP
    elif probe_dns_doh(ip, port, user, password, PROXY_DNS_ALT, PROBE_TIMEOUT):
        dns_mode, dns_server = "doh", PROXY_DNS_ALT
    elif probe_dns_tcp53(ip, port, user, password, PROXY_DNS_ALT, PROBE_TIMEOUT):
        # Провайдер закрыл основной резолвер целиком, но пускает запасной по :53 —
        # так работал весь парк, пока основным был 8.8.8.8.
        dns_mode, dns_server = "tcp53", PROXY_DNS_ALT
    else:
        # Ни :53, ни DoH. На direct-dns НЕ откатываемся ни при каких условиях:
        # резолв мимо туннеля — это утечка DNS через реальный IP коробки, ровно
        # то, ради чего весь проект. Оставляем как было и жалуемся в лог.
        dns_mode, dns_server = "tcp53", PROXY_DNS_IP
        log.warning("Прокси не отдаёт ни DNS :53, ни DoH :443 — оставляю :53. "
                    "Резолв, скорее всего, работать не будет; прокси нерабочий.")

    log.info(f"Прокси умеет: UDP ASSOCIATE={'да' if udp_ok else 'НЕТ (QUIC заблокирую)'}, "
             f"DNS :53={'да' if tcp53_ok else 'НЕТ'}, DoH :443={'да' if doh_ok else 'нет'}, "
             f"рукопожатие одним пакетом={'да' if pipe_ok else 'нет'}, "
             f"UDP через ускоритель={'да' if udp_pipe_ok else 'нет'} "
             f"→ резолвер {dns_mode} через {dns_server}")
    return {"udp_supported": udp_ok, "dns_mode": dns_mode, "dns_server": dns_server,
            "pipelining": pipe_ok, "udp_pipelining": udp_pipe_ok}


# ── Ускоритель SOCKS5-рукопожатия ────────────────────────────────────────────

FAST_EARLY_WAIT      = 0.03   # сколько ещё ждать первых данных клиента, когда TCP до прокси уже готов
FAST_CONNECT_TIMEOUT = 10
FAST_REPLY_TIMEOUT   = 15
FAST_IDLE_HALF_OPEN  = 300    # после EOF с одной стороны: закрыть, если другая молчит столько секунд
FAST_CHUNK           = 65536
FAST_UDP_BUFFER      = 256    # датаграмм sing-box, которые держим, пока ассоциация у прокси не готова
FAST_UDP_SOCKBUF     = 4 << 20   # буферы UDP-сокетов: QUIC приходит пачками быстрее, чем их разбирает Python


def grow_udp_buffers(sock) -> None:
    """Дефолтные ~200 КБ — это ~170 датаграмм QUIC: пачка переполняет буфер,
    пока event loop занят. От root net.core.rmem_max обходится *BUFFORCE."""
    force = {socket.SO_RCVBUF: 33, socket.SO_SNDBUF: 32}      # SO_RCVBUFFORCE / SO_SNDBUFFORCE
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            if sys.platform.startswith("linux") and os.geteuid() == 0:
                sock.setsockopt(socket.SOL_SOCKET, force[opt], FAST_UDP_SOCKBUF)
            else:
                sock.setsockopt(socket.SOL_SOCKET, opt, FAST_UDP_SOCKBUF)
        except (OSError, AttributeError):
            pass


class NoUpstream(RuntimeError):
    """В config.json нет outbound proxy (режим bypass или конфига нет)."""


class UpstreamSilent(Exception):
    """Прокси закрыл соединение, не прислав ни байта ответа."""


class _Warm:
    """Заранее открытое TCP-соединение с прокси, в которое ещё ничего не отправлено."""
    __slots__ = ("born", "reader", "writer")

    def __init__(self, reader, writer):
        self.born = time.monotonic()
        self.reader, self.writer = reader, writer

    def usable(self, max_age: float) -> bool:
        return (time.monotonic() - self.born < max_age and not self.reader.at_eof()
                and self.reader.exception() is None and not self.writer.transport.is_closing())

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass


class _Assoc:
    """UDP ASSOCIATE у прокси: управляющее TCP и UDP-сокет, из которого шлём на BND."""
    __slots__ = ("born", "reader", "writer", "bnd", "udp", "on_reply")

    def __init__(self, reader, writer, bnd):
        self.born = time.monotonic()
        self.reader, self.writer, self.bnd = reader, writer, bnd
        self.udp = None
        self.on_reply = None          # сессия sing-box, которой отдавать ответы прокси

    def usable(self, max_age: float) -> bool:
        return (time.monotonic() - self.born < max_age and not self.reader.at_eof()
                and self.reader.exception() is None and not self.writer.transport.is_closing()
                and self.udp is not None and not self.udp.is_closing())

    def close(self) -> None:
        for closer in (self.writer, self.udp):
            try:
                if closer is not None:
                    closer.close()
            except Exception:
                pass


class _FastUdp:
    """UDP-сокет, который вычитывается пачками. Датаграммы пересылаются как есть:
    заголовок SOCKS5 UDP уже внутри, его понимают обе стороны — sing-box и прокси.

    Не asyncio-транспорт: тот забирает одну датаграмму за итерацию цикла, и на
    потоке QUIC упирается в Python раньше, чем в сеть. Отправка — сразу в сокет;
    если буфер ядра полон, датаграмма теряется, как потерялась бы в сети."""
    BATCH = 256

    def __init__(self, loop, sock, on_datagram):
        self.loop, self.sock, self.on_datagram = loop, sock, on_datagram
        self.closed = False
        self.dropped = 0
        sock.setblocking(False)
        loop.add_reader(sock.fileno(), self._read)

    def _read(self) -> None:
        for _ in range(self.BATCH):
            try:
                data, addr = self.sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                continue              # ICMP unreachable и т.п. — датаграмма просто потерялась
            self.on_datagram(data, addr)

    def sendto(self, data: bytes, addr) -> None:
        try:
            self.sock.sendto(data, addr)
        except (BlockingIOError, InterruptedError):
            self.dropped += 1
        except OSError:
            pass

    def is_closing(self) -> bool:
        return self.closed

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.loop.remove_reader(self.sock.fileno())
            self.sock.close()


class FastRelay:
    """Локальный SOCKS5-ретранслятор между sing-box и апстрим-прокси.

    Клиент SOCKS5 в sing-box ждёт ответа на каждом шаге: TCP, приветствие,
    логин, CONNECT — 4 RTT до прокси на КАЖДОЕ новое соединение (sing
    protocol/socks/handshake.go). Здесь sing-box проходит эти шаги по loopback
    мгновенно, а к прокси уходит один пакет: приветствие + логин + CONNECT +
    первые данные клиента (обычно TLS ClientHello).

    Сверху — два запаса, оба подстраиваются под конкретный прокси:
      * TCP: заранее открытые соединения, в которые ещё ничего не отправлено.
        Экономят TCP-хендшейк, остаётся один обмен. Сколько такое соединение
        живёт у прокси, меряет probe_idle; запас обновляется раньше. Если
        соединение из запаса всё же умерло к моменту использования — повтор на
        свежем (данные клиента ещё у нас), а срок жизни запаса сокращается.
      * UDP: готовые ассоциации. sing-box получает ответ на ASSOCIATE сразу —
        адрес нашего локального UDP-сокета, — а первые датаграммы (QUIC
        Initial) уходят к прокси без ожидания. Без готовой ассоциации она
        создаётся одним пакетом, датаграммы до её готовности буферизуются.
        UDP идёт через ретранслятор, только если прокси это умеет
        (check_udp_associate(pipelined=True)); иначе sing-box шлёт UDP сам.

    CONNECT/ASSOCIATE подтверждаются sing-box сразу, до ответа прокси. Если
    прокси потом откажет, клиент получит RST (или тишину для UDP) вместо кода
    ошибки — sing-box со своим TProxy-входом ведёт себя так же.

    Апстрим (адрес, логин, routing_mark) берётся из outbound "proxy" текущего
    config.json и перечитывается при его изменении — /set_proxy перезапускает
    только sing-box, а не этот процесс."""

    IDLE_CHECKPOINTS = (3, 6, 10, 15, 25)   # секунды простоя, которые проверяет probe_idle
    POOL_MIN_AGE  = 2.0      # короче — запас TCP не держим: пересоздавать слишком часто
    POOL_MAX_AGE  = 15.0
    POOL_IDLE_OFF = 120      # столько секунд без новых TCP — запас не пополняем
    POOL_REPROBE  = 600      # запас выключился из-за умершего соединения — перемерить через
    UDP_POOL_AGE  = 30.0     # готовая ассоциация у провайдера жила >60 с без трафика
    UDP_IDLE_OFF  = 300
    MAINTAIN_EVERY = 0.5

    def __init__(self):
        self.stats = {"active": 0, "total": 0, "failed": 0, "early_data": 0,
                      "pool_hits": 0, "pool_retries": 0,
                      "udp_sessions": 0, "udp_pool_hits": 0, "udp_failed": 0}
        self.listening = False
        self._upstream = None        # (mtime_ns, dict)
        self._resolved = {}          # домен прокси -> (ip, годен_до)
        self._last_log = {}
        self.pool_key = None
        self.tcp_pool = []
        self.tcp_opening = 0
        self.tcp_max_age = 0.0       # 0 — запас TCP выключен (ещё не измерен или не годится)
        self.tcp_takes = collections.deque(maxlen=64)
        self.last_tcp_use = 0.0
        self.reprobe_at = 0.0
        self.pool_deaths = collections.deque(maxlen=8)
        self.udp_pool = []
        self.udp_opening = 0
        self.udp_takes = collections.deque(maxlen=64)
        self.last_udp_use = 0.0

    # ── апстрим ──
    def upstream(self) -> dict:
        try:
            mtime = os.stat(SINGBOX_CONF).st_mtime_ns
        except OSError as e:
            raise NoUpstream(str(e))
        if self._upstream and self._upstream[0] == mtime:
            return self._upstream[1]
        with open(SINGBOX_CONF) as f:
            conf = json.load(f)
        fast, fast_udp = config_fast_paths(conf)
        for ob in conf.get("outbounds", []):
            if ob.get("tag") == "proxy":
                up = {
                    "server":   ob["server"],
                    "port":     int(ob["server_port"]),
                    "user":     ob.get("username", ""),
                    "password": ob.get("password", ""),
                    # Метку пути к прокси уважаем так же, как sing-box: без неё
                    # трафик ушёл бы другим маршрутом, чем у самого sing-box.
                    "mark":     routing_mark_of(ob),
                    "fast":     fast,
                    "udp":      fast_udp,
                }
                self._upstream = (mtime, up)
                return up
        raise NoUpstream("в config.json нет outbound proxy")

    async def resolve(self, host: str) -> str:
        # Домен самого прокси sing-box резолвит напрямую (direct-dns), мимо
        # туннеля — иначе петля. Здесь то же самое, системным резолвером.
        if _is_ip_literal(host):
            return host
        now = time.time()
        hit = self._resolved.get(host)
        if hit and hit[1] > now:
            return hit[0]
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        ip = infos[0][4][0]
        self._resolved[host] = (ip, now + 60)
        return ip

    async def open_upstream(self, up: dict):
        ip = await self.resolve(up["server"])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            apply_proxy_mark(s, up["mark"])
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setblocking(False)
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(s, (ip, up["port"])),
                                   FAST_CONNECT_TIMEOUT)
        except BaseException:
            s.close()
            raise
        return await asyncio.open_connection(sock=s, limit=FAST_CHUNK)

    @staticmethod
    async def read_replies(reader, has_auth: bool):
        """Ответы прокси на приветствие, логин и команду; возвращает BND (host, port)."""
        try:
            g = await reader.readexactly(2)
        except asyncio.IncompleteReadError as e:
            if e.partial:
                raise
            raise UpstreamSilent("прокси закрыл соединение, не ответив") from e
        except ConnectionError as e:
            raise UpstreamSilent(f"прокси сбросил соединение, не ответив ({type(e).__name__})") from e
        if g[0] != 5 or g[1] != (2 if has_auth else 0):
            raise RuntimeError(f"прокси выбрал метод авторизации {g[1]}")
        if has_auth and (await reader.readexactly(2))[1] != 0:
            raise RuntimeError("прокси отверг логин/пароль")
        head = await reader.readexactly(4)
        if head[1] != 0:
            raise RuntimeError(f"прокси отклонил команду, код {head[1]}")
        if head[3] == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif head[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        elif head[3] == 3:
            host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
        else:
            raise RuntimeError(f"неизвестный ATYP {head[3]} в ответе прокси")
        return host, struct.unpack("!H", await reader.readexactly(2))[0]

    async def upstream_handshake(self, up: dict, command: bytes, early: bytes, conn, pooled):
        """Всё рукопожатие одним пакетом. Соединение из запаса могло умереть ровно
        к моменту использования — тогда повтор на свежем: данные клиента ещё у
        нас, до цели они не дошли. При любой ошибке соединение закрыто."""
        has_auth = bool(up["user"] and up["password"])
        payload = socks5_hello(up["user"], up["password"]) + command + early
        for attempt in (0, 1):
            reader, writer = conn
            try:
                writer.write(payload)
                await writer.drain()
                bnd = await asyncio.wait_for(self.read_replies(reader, has_auth),
                                             FAST_REPLY_TIMEOUT)
                return reader, writer, bnd
            except (UpstreamSilent, ConnectionError):
                writer.close()
                if attempt or pooled is None:
                    raise
                self.stats["pool_retries"] += 1
                self.pool_died(time.monotonic() - pooled.born)
            except BaseException:
                writer.close()
                raise
            conn = await self.open_upstream(up)

    # ── запасы ──
    def take_tcp(self, demand: bool = True):
        now = time.monotonic()
        if demand:
            self.last_tcp_use = now
            self.tcp_takes.append(now)
        while self.tcp_pool:
            w = self.tcp_pool.pop(0)
            if w.usable(self.tcp_max_age):
                return w
            w.close()
        return None

    def take_assoc(self):
        now = time.monotonic()
        self.last_udp_use = now
        self.udp_takes.append(now)
        while self.udp_pool:
            a = self.udp_pool.pop(0)
            if a.usable(self.UDP_POOL_AGE):
                return a
            a.close()
        return None

    def pool_died(self, age: float) -> None:
        """Соединение из запаса оказалось мёртвым. Похоже на тайм-аут простоя —
        сокращаем срок запаса; умерло совсем молодым — это разовый сбой, и только
        серия таких сбоев выключает запас до повторного замера."""
        now = time.monotonic()
        self.pool_deaths.append(now)
        new = 0.7 * age
        if new >= self.POOL_MIN_AGE:
            if new < self.tcp_max_age:
                self.tcp_max_age = new
                log.info(f"fast-relay: соединение из запаса умерло в {age:.1f} с — "
                         f"срок жизни запаса теперь {new:.1f} с")
        elif sum(1 for t in self.pool_deaths if now - t < 60) >= 3 and self.tcp_max_age:
            self.tcp_max_age = 0.0
            self.reprobe_at = now + self.POOL_REPROBE
            log.info(f"fast-relay: соединения из запаса умирают сразу — запас TCP выключен, "
                     f"перемерю через {self.POOL_REPROBE} с")

    def _target(self, takes, last_use, idle_off, now, base, cap) -> int:
        if not last_use or now - last_use > idle_off:
            return 0
        burst = sum(1 for t in takes if now - t < 10)
        return min(cap, max(base, burst // 2))

    async def open_assoc(self, up: dict, demand: bool) -> "_Assoc":
        """ASSOCIATE одним пакетом, по возможности на соединении из запаса TCP."""
        pooled = self.take_tcp(demand)
        conn = (pooled.reader, pooled.writer) if pooled else await self.open_upstream(up)
        reader, writer, (host, port) = await self.upstream_handshake(
            up, SOCKS5_ASSOCIATE_ANY, b"", conn, pooled)
        assoc = _Assoc(reader, writer, None)
        try:
            if host in ("0.0.0.0", "::"):
                host = await self.resolve(up["server"])
            assoc.bnd = (host, port)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                apply_proxy_mark(s, up["mark"])
                grow_udp_buffers(s)
                s.bind(("0.0.0.0", 0))
            except BaseException:
                s.close()
                raise

            def from_proxy(data, addr, a=assoc):
                if addr[:2] == a.bnd and a.on_reply is not None:
                    a.on_reply(data)

            assoc.udp = _FastUdp(asyncio.get_running_loop(), s, from_proxy)
            return assoc
        except BaseException:
            assoc.close()
            raise

    async def warm_tcp(self, up: dict, key) -> None:
        self.tcp_opening += 1
        try:
            reader, writer = await self.open_upstream(up)
        except Exception as e:
            self.log_failure("pool", e)
            return
        finally:
            self.tcp_opening -= 1
        if key != self.pool_key or not self.tcp_max_age:
            writer.close()
            return
        self.tcp_pool.append(_Warm(reader, writer))

    async def warm_assoc(self, up: dict, key) -> None:
        self.udp_opening += 1
        try:
            assoc = await self.open_assoc(up, demand=False)
        except Exception as e:
            self.log_failure("udp-pool", e)
            return
        finally:
            self.udp_opening -= 1
        if key != self.pool_key:
            assoc.close()
            return
        self.udp_pool.append(assoc)

    async def probe_idle(self, up: dict, key) -> None:
        """Сколько прокси держит TCP-соединение, в которое ничего не прислали.
        Проверка — настоящее рукопожатие после простоя, а не просто «не пришёл
        FIN»: часть серверов закрывает молча."""
        has_auth = bool(up["user"] and up["password"])
        command = b"\x05\x01\x00\x01" + socket.inet_aton(PROXY_DNS_IP) + struct.pack("!H", 443)

        async def survives(sec) -> bool:
            try:
                reader, writer = await self.open_upstream(up)
            except Exception:
                return False
            try:
                await asyncio.sleep(sec)
                if reader.at_eof():
                    return False
                writer.write(socks5_hello(up["user"], up["password"]) + command)
                await writer.drain()
                await asyncio.wait_for(self.read_replies(reader, has_auth), FAST_REPLY_TIMEOUT)
                return True
            except Exception:
                return False
            finally:
                writer.close()

        results = await asyncio.gather(*(survives(s) for s in self.IDLE_CHECKPOINTS))
        lifetime = 0
        for sec, ok in zip(self.IDLE_CHECKPOINTS, results):
            if not ok:
                break
            lifetime = sec
        if key != self.pool_key:
            return
        age = min(0.7 * lifetime, self.POOL_MAX_AGE)
        self.tcp_max_age = age if age >= self.POOL_MIN_AGE else 0.0
        log.info(f"fast-relay: пустое соединение живёт у прокси ≥{lifetime} с → "
                 + (f"запас TCP со сроком {age:.1f} с" if self.tcp_max_age else "запас TCP выключен"))

    def reset_pools(self, key) -> None:
        for item in self.tcp_pool + self.udp_pool:
            item.close()
        self.tcp_pool, self.udp_pool = [], []
        self.pool_key = key
        self.tcp_max_age = 0.0
        self.reprobe_at = 0.0

    @staticmethod
    def _prune(items, max_age: float) -> list:
        keep = []
        for item in items:
            if item.usable(max_age):
                keep.append(item)
            else:
                item.close()
        return keep

    def maintain_once(self) -> None:
        try:
            up = self.upstream()
        except NoUpstream:
            if self.pool_key is not None:
                self.reset_pools(None)
            return
        key = (up["server"], up["port"], up["mark"], up["user"], up["password"],
               up["fast"], up["udp"])
        now = time.monotonic()
        if key != self.pool_key:
            self.reset_pools(key)
            if up["fast"]:
                asyncio.ensure_future(self.probe_idle(up, key))
        elif up["fast"] and self.reprobe_at and now >= self.reprobe_at:
            self.reprobe_at = 0.0
            asyncio.ensure_future(self.probe_idle(up, key))

        self.tcp_pool = self._prune(self.tcp_pool, self.tcp_max_age)
        want = self._target(self.tcp_takes, self.last_tcp_use, self.POOL_IDLE_OFF, now, 2, 8) \
            if up["fast"] and self.tcp_max_age else 0
        for _ in range(want - len(self.tcp_pool) - self.tcp_opening):
            asyncio.ensure_future(self.warm_tcp(up, key))

        self.udp_pool = self._prune(self.udp_pool, self.UDP_POOL_AGE)
        want = self._target(self.udp_takes, self.last_udp_use, self.UDP_IDLE_OFF, now, 1, 4) \
            if up["udp"] else 0
        for _ in range(want - len(self.udp_pool) - self.udp_opening):
            asyncio.ensure_future(self.warm_assoc(up, key))

    async def maintain(self) -> None:
        while True:
            try:
                self.maintain_once()
            except Exception as e:
                self.log_failure("pool", e)
            await asyncio.sleep(self.MAINTAIN_EVERY)

    # ── соединение ──
    async def handle(self, creader, cwriter):
        self.stats["active"] += 1
        self.stats["total"] += 1
        stage = "local"
        uwriter = None
        connect = None
        tasks = []
        try:
            up = self.upstream()
            has_auth = bool(up["user"] and up["password"])

            # 1. Рукопожатие с sing-box по loopback.
            ver, n = await asyncio.wait_for(creader.readexactly(2), 10)
            methods = await creader.readexactly(n)
            method = 2 if has_auth else 0
            if ver != 5 or method not in methods:
                cwriter.write(b"\x05\xff")
                return
            cwriter.write(bytes([5, method]))
            if has_auth:
                ulen = (await creader.readexactly(2))[1]
                user = await creader.readexactly(ulen)
                pw = await creader.readexactly((await creader.readexactly(1))[0])
                if user != up["user"].encode() or pw != up["password"].encode():
                    cwriter.write(b"\x01\x01")
                    return
                cwriter.write(b"\x01\x00")
            head = await creader.readexactly(4)
            if head[3] == 1:
                addr = await creader.readexactly(4)
            elif head[3] == 4:
                addr = await creader.readexactly(16)
            elif head[3] == 3:
                alen = await creader.readexactly(1)
                addr = alen + await creader.readexactly(alen[0])
            else:
                return
            addr += await creader.readexactly(2)
            if head[0] == 5 and head[1] == 3 and up["udp"]:
                stage = "udp"
                await self.handle_udp(cwriter, creader, up)
                return
            if head[0] != 5 or head[1] != 1:
                cwriter.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            # 2. Подтверждаем CONNECT сразу; параллельно берём соединение из
            #    запаса (или открываем новое) и ждём первые данные клиента:
            #    sing-box отдаёт их сразу за ответом.
            cwriter.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await cwriter.drain()
            stage = "connect"
            pooled = self.take_tcp()
            if pooled is not None:
                self.stats["pool_hits"] += 1
                connect = asyncio.get_running_loop().create_future()
                connect.set_result((pooled.reader, pooled.writer))
            else:
                connect = asyncio.ensure_future(self.open_upstream(up))
            first = asyncio.ensure_future(creader.read(FAST_CHUNK))
            tasks += [connect, first]
            await asyncio.wait({connect, first}, return_when=asyncio.FIRST_COMPLETED)
            if not first.done():
                # TCP готов раньше данных: ещё чуть-чуть, потом шлём без них
                # (протоколы, где первым говорит сервер: SMTP, SSH…).
                await asyncio.wait({first}, timeout=FAST_EARLY_WAIT)
            if not first.done():
                first.cancel()
                try:
                    await first
                except asyncio.CancelledError:
                    pass
            early = b""
            if not first.cancelled():
                early = first.result()
                if not early:
                    return          # клиент закрылся, ничего не прислав
                self.stats["early_data"] += 1
            conn = await connect

            # 3. Всё рукопожатие с прокси — одним пакетом.
            stage = "handshake"
            ureader, uwriter, _ = await self.upstream_handshake(
                up, b"\x05\x01\x00" + head[3:4] + addr, early, conn, pooled)

            stage = "relay"
            await self.pipe(creader, cwriter, ureader, uwriter)
        except Exception as e:
            if stage == "udp":
                self.stats["udp_failed"] += 1
                self.log_failure(stage, e)
            elif stage != "relay":
                self.stats["failed"] += 1
                self.log_failure(stage, e)
            self.abort(cwriter)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            if (uwriter is None and connect is not None and connect.done()
                    and not connect.cancelled() and connect.exception() is None):
                connect.result()[1].close()      # соединение не пригодилось
            for w in (cwriter, uwriter):
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass
            self.stats["active"] -= 1

    async def handle_udp(self, cwriter, creader, up: dict) -> None:
        """UDP ASSOCIATE от sing-box. Отвечаем сразу адресом своего локального
        UDP-сокета; датаграммы до готовности ассоциации у прокси копим."""
        loop = asyncio.get_running_loop()
        self.stats["udp_sessions"] += 1
        state = {"peer": None, "assoc": None}
        pending = []

        def from_singbox(data, addr):
            # Сокет слушает только loopback, так что пишут в него только локальные
            # процессы. Адрес источника при этом не обязательно 127.0.0.1:
            # MASQUERADE из apply_iptables (без -o) переписывает и loopback —
            # на коробке датаграммы приходят «от 10.0.0.1». Поэтому сессия просто
            # привязывается к первому отправителю.
            if state["peer"] is None:
                state["peer"] = addr
            elif addr != state["peer"]:
                return
            assoc = state["assoc"]
            if assoc is not None:
                assoc.udp.sendto(data, assoc.bnd)
            elif len(pending) < FAST_UDP_BUFFER:
                pending.append(data)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            grow_udp_buffers(s)
            s.bind(("127.0.0.1", 0))
        except BaseException:
            s.close()
            raise
        local = _FastUdp(loop, s, from_singbox)
        assoc = None
        try:
            port = s.getsockname()[1]
            cwriter.write(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", port))
            await cwriter.drain()
            assoc = self.take_assoc()
            if assoc is not None:
                self.stats["udp_pool_hits"] += 1
            else:
                assoc = await self.open_assoc(up, demand=True)

            def to_singbox(data):
                if state["peer"] is not None:
                    local.sendto(data, state["peer"])

            assoc.on_reply = to_singbox
            state["assoc"] = assoc
            for data in pending:
                assoc.udp.sendto(data, assoc.bnd)
            pending.clear()
            # Сессия живёт, пока открыты обе управляющие TCP-связи.
            await self.wait_closed(creader, assoc.reader)
        finally:
            local.close()
            if assoc is not None:
                assoc.close()

    @staticmethod
    async def wait_closed(*readers) -> None:
        async def until_eof(reader):
            try:
                while await reader.read(4096):
                    pass
            except (ConnectionError, OSError):
                pass

        tasks = [asyncio.ensure_future(until_eof(r)) for r in readers]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()

    async def pipe(self, creader, cwriter, ureader, uwriter) -> None:
        moved = {"up": 0, "down": 0}

        async def copy(src, dst, key):
            while True:
                data = await src.read(FAST_CHUNK)
                if not data:
                    break
                moved[key] += len(data)
                dst.write(data)
                await dst.drain()
            if dst.can_write_eof():
                try:
                    dst.write_eof()
                except OSError:
                    pass

        t_up = asyncio.ensure_future(copy(creader, uwriter, "up"))
        t_down = asyncio.ensure_future(copy(ureader, cwriter, "down"))
        try:
            done, pending = await asyncio.wait({t_up, t_down},
                                               return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                t.result()          # ошибка одной стороны рвёт обе
            if pending:
                # Полузакрытое соединение: держим, пока в оставшуюся сторону
                # что-то идёт, и закрываем после долгой тишины.
                other = pending.pop()
                key = "down" if other is t_down else "up"
                last = -1
                while not other.done() and moved[key] != last:
                    last = moved[key]
                    await asyncio.wait({other}, timeout=FAST_IDLE_HALF_OPEN)
                if other.done():
                    other.result()
        except Exception:
            self.abort(cwriter)
            self.abort(uwriter)
        finally:
            for t in (t_up, t_down):
                if not t.done():
                    t.cancel()

    @staticmethod
    def abort(writer) -> None:
        """Закрыть с RST, а не FIN: клиент должен увидеть обрыв, а не
        «сервер вежливо закрыл соединение»."""
        if writer is None:
            return
        try:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            writer.transport.abort()
        except Exception:
            pass

    def log_failure(self, stage: str, e: Exception) -> None:
        key = f"{stage}:{type(e).__name__}"
        now = time.time()
        if now - self._last_log.get(key, 0) >= 10:
            self._last_log[key] = now
            log.warning(f"fast-relay: сбой на шаге {stage}: {type(e).__name__}: {e} "
                        f"(сбоев TCP {self.stats['failed']}, UDP {self.stats['udp_failed']})")

    @staticmethod
    def raise_fd_limit() -> None:
        """systemd даёт сервису мягкий лимит 1024 дескриптора (проверено на коробке:
        1024/524288), а ретранслятор тратит по два на соединение — со всех
        устройств сети это ~500 одновременных TCP, дальше «Too many open files».
        Юнит на уже развёрнутых коробках Update не обновляет, поэтому поднимаем
        мягкий лимит до жёсткого сами — для этого привилегии не нужны."""
        try:
            import resource
        except ImportError:
            return                      # не Linux (локальные тесты)
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
        if soft < target:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
                log.info(f"fast-relay: лимит дескрипторов {soft} → {target}")
            except (ValueError, OSError) as e:
                log.warning(f"fast-relay: не удалось поднять лимит дескрипторов ({soft}): {e}")

    def serve_forever(self) -> None:
        self.raise_fd_limit()
        while True:
            loop = asyncio.SelectorEventLoop()
            try:
                asyncio.set_event_loop(loop)
                loop.run_until_complete(asyncio.start_server(
                    self.handle, FAST_RELAY_HOST, FAST_RELAY_PORT, backlog=1024))
                loop.create_task(self.maintain())
                self.listening = True
                log.info(f"fast-relay: слушаю {FAST_RELAY_HOST}:{FAST_RELAY_PORT}")
                loop.run_forever()
            except Exception as e:
                log.error(f"fast-relay: остановился ({type(e).__name__}: {e}), перезапуск через 2 с")
            finally:
                self.listening = False
                loop.close()
            time.sleep(2)


FAST_RELAY = FastRelay()


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


# ── AmneziaWG: туннель от коробки до прокси ──────────────────────────────────
# Провайдер коробки может душить прямой путь до прокси (на живой коробке — обрыв
# после ~17 КБ). Тогда трафик sing-box к прокси (и ретранслятора, и проб) идёт
# через AmneziaWG: у outbound "proxy" routing_mark AWG_MARK, правило
# fwmark AWG_MARK → таблица AWG_TABLE → default dev awg0. Остальной трафик
# коробки (SSH, GitHub, API) туннель не трогает: Table = off.
#
# Профили — конфиги из Amnezia (экспорт AmneziaWG) в AWG_PROFILES_DIR. Активный
# копируется в AWG_DIR/awg0.conf после нормализации (awg_normalize): имя
# интерфейса всегда awg0, поэтому маршрут не зависит от профиля.

AWG_DIR          = "/etc/amnezia/amneziawg"
AWG_PROFILES_DIR = AWG_DIR + "/profiles"
AWG_IFACE        = "awg0"
AWG_UNIT         = f"awg-quick@{AWG_IFACE}"
AWG_MARK         = 100
AWG_TABLE        = 200
AWG_RULE_PREF    = 200
AWG_MAX_CONF     = 16384
AWG_CONNECT_TIMEOUT = 8        # проверка «прокси доступен через туннель» после включения
AWG_NAME_RE      = re.compile(r"^\w[\w.-]{0,31}$")
# Ключи [Interface], которые из профиля выбрасываются. DNS — системный резолвер
# коробки не должен уходить в туннель (при Table = off он там и недоступен), а в
# экспортах Amnezia бывают неподставленные "$PRIMARY_DNS". Хуки — это команды,
# которые awg-quick выполняет от root, а профиль приходит по HTTP без авторизации.
AWG_DROP_KEYS    = {"dns", "table", "preup", "postup", "predown", "postdown", "saveconfig"}
AWG_POSTUP  = (f"ip rule show pref {AWG_RULE_PREF} | grep -q 'lookup {AWG_TABLE}' || "
               f"ip rule add pref {AWG_RULE_PREF} fwmark {AWG_MARK} table {AWG_TABLE}; "
               f"ip route replace default dev %i table {AWG_TABLE}")
AWG_PREDOWN = f"ip route del default dev %i table {AWG_TABLE} 2>/dev/null || true"

_awg_lock = threading.Lock()


def awg_installed() -> bool:
    return bool(shutil.which("awg") and shutil.which("awg-quick"))


def awg_service_active() -> bool:
    return run(f"systemctl is-active {AWG_UNIT}")[1].strip() == "active"


def awg_enabled() -> bool:
    """Включён ли туннель — выбор пользователя из панели. Пока из панели ни разу
    не переключали, считаем как настроено руками: сервис запущен — включён."""
    st = read_state()
    if "awg_enabled" in st:
        return bool(st["awg_enabled"])
    return awg_installed() and awg_service_active()


def awg_routing_mark() -> int:
    return AWG_MARK if awg_enabled() else 0


def awg_parse(text: str) -> list:
    """INI в стиле WireGuard → [(секция, [(ключ, значение), ...]), ...].
    Порядок и повторы сохраняются: [Peer] может быть несколько."""
    sections = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"\[\s*(\w+)\s*\]", line)
        if m:
            sections.append((m.group(1).lower(), []))
            continue
        if "=" not in line or not sections:
            raise ValueError(f"непонятная строка: {line[:60]!r}")
        key, val = line.split("=", 1)
        sections[-1][1].append((key.strip(), val.strip()))
    return sections


def _awg_get(items: list, key: str) -> str:
    for k, v in items:
        if k.lower() == key:
            return v
    return ""


def awg_summary(text: str) -> dict:
    """Что показать в панели — без ключей."""
    info = {"endpoint": "", "address": ""}
    try:
        for name, items in awg_parse(text):
            if name == "interface" and not info["address"]:
                info["address"] = _awg_get(items, "address")
            elif name == "peer" and not info["endpoint"]:
                info["endpoint"] = _awg_get(items, "endpoint")
    except ValueError:
        pass
    return info


def awg_normalize(text: str, profile: str) -> str:
    out = [f"# Сгенерировано JackalRouter из профиля {profile!r} — не редактировать.",
           f"# Правьте профиль в {AWG_PROFILES_DIR}."]
    for name, items in awg_parse(text):
        out.append("")
        out.append(f"[{'Interface' if name == 'interface' else 'Peer'}]")
        for key, val in items:
            if name == "interface" and key.lower() in AWG_DROP_KEYS:
                continue
            out.append(f"{key} = {val}")
        if name == "interface":
            out += ["Table = off", f"PostUp = {AWG_POSTUP}", f"PreDown = {AWG_PREDOWN}"]
    return "\n".join(out) + "\n"


def awg_validate(text: str) -> None:
    """Бросает ValueError с понятным текстом. Сначала структура, затем — если
    есть модуль ядра — настоящая проверка: временный интерфейс + awg setconf
    (без адресов и маршрутов, сразу удаляется)."""
    if len(text.encode("utf-8")) > AWG_MAX_CONF:
        raise ValueError("файл слишком большой для конфига AmneziaWG")
    sections = awg_parse(text)
    ifaces = [items for name, items in sections if name == "interface"]
    peers = [items for name, items in sections if name == "peer"]
    if len(ifaces) != 1:
        raise ValueError("нужна ровно одна секция [Interface]")
    for key in ("privatekey", "address"):
        if not _awg_get(ifaces[0], key):
            raise ValueError(f"в [Interface] нет {key}")
    if not peers:
        raise ValueError("нет секции [Peer]")
    for peer in peers:
        for key in ("publickey", "endpoint", "allowedips"):
            if not _awg_get(peer, key):
                raise ValueError(f"в [Peer] нет {key}")
    if not awg_installed():
        return
    tmpdir = tempfile.mkdtemp(prefix="jrawg")
    link = f"jrchk{os.getpid() % 10000}"
    try:
        path = os.path.join(tmpdir, f"{link}.conf")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(awg_normalize(text, "check"))
        r = subprocess.run(["awg-quick", "strip", path], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise ValueError(f"awg-quick не принял конфиг: {r.stderr.strip()[-200:]}")
        stripped = os.path.join(tmpdir, "stripped.conf")
        with open(stripped, "w", encoding="utf-8") as f:
            f.write(r.stdout)
        if run(f"ip link add {link} type amneziawg")[0] != 0:
            return                      # userspace-реализация — хватит strip
        try:
            code, _, err = run(f"awg setconf {link} {stripped}")
            if code != 0:
                raise ValueError(f"awg не принял конфиг: {err[-200:]}")
        finally:
            run(f"ip link del {link}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def awg_profile_path(name: str) -> str:
    if not AWG_NAME_RE.fullmatch(name or ""):
        raise ValueError("имя профиля: буквы, цифры, _ . - (до 32 символов)")
    return os.path.join(AWG_PROFILES_DIR, f"{name}.conf")


def awg_profile_names() -> list:
    try:
        return sorted(f[:-5] for f in os.listdir(AWG_PROFILES_DIR)
                      if f.endswith(".conf") and AWG_NAME_RE.fullmatch(f[:-5]))
    except FileNotFoundError:
        return []


def _write_private(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.replace(path + ".tmp", path)


def awg_adopt_existing() -> None:
    """awg0.conf, настроенный руками до появления профилей, становится профилем
    "default" — иначе панель показала бы работающий туннель без профилей."""
    live = os.path.join(AWG_DIR, f"{AWG_IFACE}.conf")
    if awg_profile_names() or not os.path.exists(live):
        return
    try:
        text = open(live, encoding="utf-8").read()
        awg_parse(text)
    except (OSError, ValueError) as e:
        log.warning(f"AWG: {live} не удалось взять профилем: {e}")
        return
    _write_private(awg_profile_path("default"), text)
    if not read_state().get("awg_profile"):
        write_state(awg_profile="default")
    log.info(f"AWG: существующий {live} сохранён профилем 'default'")


def awg_runtime() -> dict:
    """Рукопожатие и трафик живого интерфейса — без ключей пиров."""
    info = {"handshake_age": None, "rx": 0, "tx": 0, "endpoint": ""}
    code, out, _ = run(f"awg show {AWG_IFACE} dump")
    if code != 0:
        return info
    now = time.time()
    for line in out.splitlines()[1:]:          # первая строка — сам интерфейс
        cols = line.split("\t")
        if len(cols) < 7:
            continue
        info["endpoint"] = info["endpoint"] or (cols[2] if cols[2] != "(none)" else "")
        hs = int(cols[4] or 0)
        if hs:
            age = int(now - hs)
            info["handshake_age"] = age if info["handshake_age"] is None else min(age, info["handshake_age"])
        info["rx"] += int(cols[5] or 0)
        info["tx"] += int(cols[6] or 0)
    return info


def awg_status() -> dict:
    installed = awg_installed()
    if installed:
        awg_adopt_existing()
    active = read_state().get("awg_profile", "")
    profiles = []
    for name in awg_profile_names():
        try:
            text = open(awg_profile_path(name), encoding="utf-8").read()
        except OSError:
            continue
        profiles.append(dict(awg_summary(text), name=name, active=name == active))
    service = run(f"systemctl is-active {AWG_UNIT}")[1].strip() if installed else "missing"
    rule_ok = f"lookup {AWG_TABLE}" in run(f"ip rule show pref {AWG_RULE_PREF}")[1]
    route_ok = f"dev {AWG_IFACE}" in run(f"ip route show table {AWG_TABLE}")[1]
    mark_in_config = False
    try:
        mark_in_config = routing_mark_of(next(
            ob for ob in json.load(open(SINGBOX_CONF)).get("outbounds", [])
            if ob.get("tag") == "proxy")) == AWG_MARK
    except Exception:
        pass
    return dict(awg_runtime() if service == "active" else {"handshake_age": None, "rx": 0, "tx": 0, "endpoint": ""},
                installed=installed, enabled=awg_enabled(), service=service, profile=active,
                profiles=profiles, route_ok=rule_ok and route_ok, mark_in_config=mark_in_config)


def awg_reroute_singbox() -> dict:
    """Путь до прокси поменялся — возможности прокси по новому пути перепроверяем,
    как при /set_proxy, и перезапускаем sing-box. В bypass-режиме прокси нет."""
    try:
        p = read_active_proxy()
    except Exception:
        return {"regenerated": False}
    caps = probe_proxy(p["ip"], p["port"], p["user"], p["password"])
    write_singbox_conf(p["ip"], p["port"], p["user"], p["password"],
                       udp_supported=caps["udp_supported"], block_quic=read_quic_pref(),
                       dns_mode=caps["dns_mode"], dns_server=caps["dns_server"],
                       fast_relay=caps["pipelining"], fast_udp=caps["udp_pipelining"])
    code, _, err = run("systemctl restart sing-box")
    if code != 0:
        raise RuntimeError(f"sing-box не перезапустился: {err[-200:]}")
    return {"regenerated": True, "caps": caps}


def _awg_proxy_reachable() -> Tuple[bool, str]:
    """Через поднятый туннель до прокси достучаться можно? Заодно это первый
    трафик в туннель — он и запускает рукопожатие."""
    try:
        p = read_active_proxy()
    except Exception:
        return True, ""                  # прокси не задан — проверять нечего
    try:
        connect_to_proxy(p["ip"], p["port"], AWG_CONNECT_TIMEOUT).close()
        return True, ""
    except OSError as e:
        return False, f"{p['ip']}:{p['port']}: {e}"


def awg_start(profile: str) -> None:
    text = open(awg_profile_path(profile), encoding="utf-8").read()
    _write_private(os.path.join(AWG_DIR, f"{AWG_IFACE}.conf"), awg_normalize(text, profile))
    run(f"systemctl enable {AWG_UNIT} -q")
    code, _, err = run(f"systemctl restart {AWG_UNIT}")
    if code != 0:
        tail = run(f"journalctl -u {AWG_UNIT} -n 5 --no-pager -o cat")[1]
        raise RuntimeError(f"awg-quick не поднял туннель: {(tail or err)[-300:]}")
    # PostUp делает то же самое; повтор на случай, если awg0 уже был поднят.
    run(f"ip rule show pref {AWG_RULE_PREF} | grep -q 'lookup {AWG_TABLE}' || "
        f"ip rule add pref {AWG_RULE_PREF} fwmark {AWG_MARK} table {AWG_TABLE}")
    run(f"ip route replace default dev {AWG_IFACE} table {AWG_TABLE}")


def awg_stop() -> None:
    run(f"systemctl disable --now {AWG_UNIT} -q")


def awg_enable(profile: str = "") -> dict:
    if not awg_installed():
        raise RuntimeError("AmneziaWG не установлен на сервере (нет awg / awg-quick)")
    with _awg_lock:
        awg_adopt_existing()
        profile = profile or read_state().get("awg_profile", "")
        if not profile or not os.path.exists(awg_profile_path(profile)):
            raise ValueError("не выбран профиль AmneziaWG — добавьте его")
        was, prev = awg_enabled(), read_state().get("awg_profile", "")
        awg_start(profile)
        # Метку ставим только сейчас: пробы и проверка ниже должны идти в туннель.
        write_state(awg_enabled=True, awg_profile=profile)
        ok, why = _awg_proxy_reachable()
        if not ok:
            # Сервер AmneziaWG недоступен или профиль не тот — возвращаем как было,
            # иначе весь трафик к прокси ушёл бы в неработающий туннель.
            write_state(awg_enabled=was, awg_profile=prev)
            if was and prev and prev != profile and os.path.exists(awg_profile_path(prev)):
                awg_start(prev)
            elif not was:
                awg_stop()
            raise RuntimeError(f"через туннель с профилем {profile!r} прокси недоступен "
                               f"({why}) — оставлено как было")
        result = awg_reroute_singbox()
    log.info(f"AWG: включён, профиль {profile!r}")
    return dict(result, runtime=awg_runtime())


def awg_disable() -> dict:
    with _awg_lock:
        write_state(awg_enabled=False)
        # Сначала sing-box без метки, потом гасим туннель — без окна, когда
        # трафик прокси помечен, а туннеля уже нет. Гасим в любом случае:
        # помеченный трафик без awg0 просто пойдёт по основной таблице.
        try:
            result = awg_reroute_singbox()
        finally:
            awg_stop()
    log.info("AWG: выключен")
    return result


def awg_add_profile(name: str, text: str) -> dict:
    path = awg_profile_path(name)
    text = text.replace("\r\n", "\n").lstrip("﻿")
    awg_validate(text)
    with _awg_lock:
        if os.path.exists(path):
            raise ValueError(f"профиль {name!r} уже есть — удалите его или выберите другое имя")
        _write_private(path, text)
        if not read_state().get("awg_profile"):
            write_state(awg_profile=name)
    log.info(f"AWG: добавлен профиль {name!r}")
    return awg_summary(text)


def awg_delete_profile(name: str) -> None:
    path = awg_profile_path(name)
    with _awg_lock:
        if not os.path.exists(path):
            raise FileNotFoundError(f"профиля {name!r} нет")
        st = read_state()
        if st.get("awg_profile") == name:
            if awg_enabled():
                raise PermissionError("профиль сейчас используется — выключите AmneziaWG "
                                      "или сделайте активным другой профиль")
            write_state(awg_profile="")
        os.remove(path)
    log.info(f"AWG: удалён профиль {name!r}")


def awg_activate_profile(name: str) -> dict:
    if not os.path.exists(awg_profile_path(name)):
        raise FileNotFoundError(f"профиля {name!r} нет")
    if not awg_enabled():
        write_state(awg_profile=name)
        return {"applied": False}
    return dict(awg_enable(name), applied=True)


class AwgProfileRequest(BaseModel):
    name: str
    config: str


class AwgEnableRequest(BaseModel):
    profile: str = ""


def _awg_http(fn, *args):
    try:
        return dict(fn(*args) or {}, status="ok", awg=awg_status())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        log.error(f"AWG: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Синхронные def: внутри systemctl и пробы на секунды — FastAPI выполнит их в
# пуле потоков, не блокируя остальные запросы.
@app.get("/awg/status")
def awg_status_ep():
    return awg_status()


@app.post("/awg/enable")
def awg_enable_ep(req: Optional[AwgEnableRequest] = None):
    return _awg_http(awg_enable, req.profile if req else "")


@app.post("/awg/disable")
def awg_disable_ep():
    return _awg_http(awg_disable)


@app.post("/awg/profiles")
def awg_add_profile_ep(req: AwgProfileRequest):
    return _awg_http(awg_add_profile, req.name.strip(), req.config)


@app.delete("/awg/profiles/{name}")
def awg_delete_profile_ep(name: str):
    return _awg_http(awg_delete_profile, name)


@app.post("/awg/profiles/{name}/activate")
def awg_activate_profile_ep(name: str):
    return _awg_http(awg_activate_profile, name)


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
            fast_relay=caps["pipelining"], fast_udp=caps["udp_pipelining"],
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
            "fast_relay": caps["pipelining"],
            "fast_udp": caps["udp_pipelining"],
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
        # fast_relay — туда же, по той же причине.
        write_singbox_conf(
            ip=proxy_data["ip"], port=proxy_data["port"],
            user=proxy_data["user"], password=proxy_data["password"],
            udp_supported=udp_ok,
            block_quic=block_quic,
            dns_mode=proxy_data["dns_mode"], dns_server=proxy_data["dns_server"],
            fast_relay=proxy_data["fast_relay"],
            fast_udp=proxy_data["fast_udp"] and udp_ok,
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


def urlopen_ipv4(url, timeout: float = 15) -> bytes:
    """urlopen, принудительно по IPv4.

    Это подстраховка, а НЕ лечение медленного GitHub (причина оказалась другой,
    см. fetch_github_server_py). На конкретной коробке глобального IPv6 нет
    вообще, так что здесь это no-op. Но раз адреса раздаются по-разному в
    зависимости от провайдера, а socket.create_connection перебирает их
    ПОСЛЕДОВАТЕЛЬНО (Happy Eyeballs в stdlib нет), одна мёртвая AAAA-запись
    съела бы весь таймаут до первой же IPv4-попытки. IPv4-only для этого
    проекта штатный режим: ip6tables рубит форвардинг, sing-box в ipv4_only.

    url — строка или urllib.request.Request (нужен для заголовков к API).
    Резолв сужаем до AF_INET только на время запроса и под локом."""
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


def _github_raw_url(timeout: float) -> str:
    """Ссылка на server.py, которую GitHub отдаст СВЕЖЕЙ.

    Ссылка на ВЕТКУ на это не годится: raw.githubusercontent.com отдаёт её с
    "cache-control: max-age=300" и после пуша ещё некоторое время возвращает
    содержимое предыдущего коммита. Проверено на живой коробке: api.github.com
    уже показывает новый коммит, а raw по ветке шесть запросов подряд отдаёт
    хэш прошлого — причём cache-buster в query это НЕ лечит. Из-за этого
    /self_update отвечал "уже последняя версия" сразу после пуша, а однажды,
    наоборот, увидел расхождение и откатил коробку на предыдущую версию.

    Ссылка, привязанная к SHA коммита, неизменяема и всегда актуальна, поэтому
    сначала спрашиваем SHA у API, а файл тянем уже по нему. Если API недоступен
    (в том числе из-за лимита в 60 запросов/час на IP) — откатываемся на ссылку
    по ветке с cache-buster: это прежнее поведение, лучше чем ничего."""
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{GITHUB_REPO}/commits/{GITHUB_REF}",
            headers={"User-Agent": "JackalRouter", "Accept": "application/vnd.github+json"})
        sha = json.loads(urlopen_ipv4(req, timeout=timeout))["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError(f"невалидный sha: {sha[:20]!r}")
        return f"https://raw.githubusercontent.com/{GITHUB_REPO}/{sha}/server/server.py"
    except Exception as e:
        log.warning(f"api.github.com недоступен ({type(e).__name__}), "
                    f"тяну по ветке {GITHUB_REF} — возможна протухшая копия с CDN")
        return (f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_REF}"
                f"/server/server.py?cb={time.time_ns()}")


def fetch_github_server_py() -> str:
    """Тянет актуальный server.py с GitHub напрямую, короткими попытками.

    Замерено на живой коробке (curl, 5 прогонов подряд): dns=0.02…5.1 с, а
    time_connect = 15.6 / 31.7 / 20.4 / 20.4 / 1.1 с — это тайминги
    ретрансмита SYN ядром, то есть провайдер интермиттентно роняет SYN на
    адреса GitHub. Глобального IPv6 на коробке нет вообще (`ip -6 addr show
    scope global` пусто), так что дело не в нём.

    Лечение — НЕ поднимать таймаут, а наоборот. Один urlopen(timeout=15)
    залипал на первом же мёртвом SYN и съедал весь 30-секундный бюджет
    клиента. Короткая попытка вместо этого быстро сдаётся и начинает новую —
    а это новый SYN с новым шансом; внутри одной попытки create_connection
    успевает обойти все четыре A-записи GitHub. Общий дедлайн гарантирует,
    что мы вернём честную ошибку раньше, чем клиент отвалится по таймауту."""
    t_end = time.time() + GITHUB_FETCH_DEADLINE
    attempts, errors = 0, []
    while True:
        attempts += 1
        url = _github_raw_url(min(5.0, max(2.0, t_end - time.time())))
        try:
            content = urlopen_ipv4(url, timeout=min(5.0, max(2.0, t_end - time.time())))
            content = content.decode("utf-8")
            if "def make_singbox_conf" not in content:
                raise ValueError("похоже на не тот файл (нет make_singbox_conf)")
            if attempts > 1:
                log.info(f"server.py получен с GitHub с попытки {attempts}")
            return content
        except Exception as e:
            errors.append(type(e).__name__)
        if time.time() >= t_end:
            raise RuntimeError(f"GitHub недоступен за {GITHUB_FETCH_DEADLINE} с "
                               f"({attempts} попыток: {', '.join(errors[-4:])})")


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
    fast_enabled = fast_udp = False
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
        fast_enabled, fast_udp = config_fast_paths(conf)
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
        # enabled — ускоритель в конфиге; listening — поток в этом процессе жив.
        "fast_relay": dict(FAST_RELAY.stats, enabled=fast_enabled, udp=fast_udp,
                           listening=FAST_RELAY.listening,
                           tcp_pool_max_age=round(FAST_RELAY.tcp_max_age, 1),
                           tcp_pool=len(FAST_RELAY.tcp_pool),
                           udp_pool=len(FAST_RELAY.udp_pool)),
        "sing_box_version": ".".join(map(str, singbox_version())) or None,
        "awg": {"installed": awg_installed(), "enabled": awg_enabled(),
                "service": svc(AWG_UNIT), "profile": read_state().get("awg_profile", "")},
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
