#!/usr/bin/env python3
"""
JackalRouter — Control Panel (Windows, Tkinter)
Features: proxy apply, proxy check + geo, UDP check, EN/RU language, proxy history.
"""

import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
import re
import socket
import struct
import json
import os
import sys
import time
import subprocess
from datetime import datetime
from urllib.parse import quote

try:
    import requests
    requests.get
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests[socks]"])
    import requests

try:
    import socks  # PySocks — needed for SOCKS5 support in requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "PySocks"])

SERVER_PORT  = 8000
TIMEOUT      = 15
# Cloudflare — держит QUIC/HTTP3 на 443 на фиксированном IP (не нужен доп.
# DNS-резолв в теле SOCKS5 UDP-релея). Используется только для проверки
# QUIC-пробы, к реальному трафику пользователя отношения не имеет.
QUIC_TARGET_IP   = "1.1.1.1"
QUIC_TARGET_PORT = 443

# Каталог для файлов состояния (история прокси, последний IP сервера).
# В собранном PyInstaller --onefile .exe __file__ указывает на временную
# папку распаковки (_MEIxxxx), которая удаляется после каждого запуска —
# поэтому в frozen-сборке берём папку рядом с самим .exe (sys.executable),
# а не рядом с распакованным .py.
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(APP_DIR, "proxy_history.json")

# ── Самообновление клиента с GitHub ──────────────────────────────────────────
# Тот же источник, что у server.py/update.py. Собранный .exe не может
# перезаписать сам себя на Windows, поэтому обновляем ИСХОДНИК client.py и
# передаём эстафету update_client.bat — он ждёт закрытия этого процесса,
# пересобирает через PyInstaller и перезапускает уже новую версию.
GITHUB_REPO = "MorganWeistling/JackalRouter"
GITHUB_REF  = "main"


def client_source_path() -> str:
    """Путь к client/client.py: при сборке .exe лежит в client/dist/, сам
    исходник — на уровень выше (client/client.py); в dev-режиме это и есть
    выполняющийся файл."""
    if getattr(sys, "frozen", False):
        return os.path.normpath(os.path.join(APP_DIR, "..", "client.py"))
    return os.path.abspath(__file__)


def project_root_path() -> str:
    """Корень репозитория — там лежит update_client.bat."""
    if getattr(sys, "frozen", False):
        return os.path.normpath(os.path.join(APP_DIR, "..", ".."))
    return os.path.normpath(os.path.join(APP_DIR, ".."))


def fetch_github_client_py() -> str:
    url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_REF}/client/client.py"
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    content = resp.text
    if "class App" not in content:
        raise ValueError("похоже на не тот файл (нет class App)")
    return content


def validate_client_py(content: str) -> tuple:
    """Только синтаксис — тем же compile(), которым сам Python исполняет код,
    без внешнего интерпретатора: работает одинаково что в frozen .exe (там
    нет отдельного python.exe для subprocess), что в dev-режиме. Полного
    import-smoke-теста, как у server.py, здесь нет: он поднял бы настоящее
    окно Tkinter — достаточно поймать самый частый случай поломки (битый
    фетч/синтаксическая ошибка) ДО того, как перезаписывать рабочий файл."""
    try:
        compile(content, "client.py", "exec")
        return True, ""
    except SyntaxError as e:
        return False, f"Синтаксическая ошибка: {e}"
    except Exception as e:
        return False, str(e)
CONFIG_FILE  = os.path.join(APP_DIR, "client_config.json")

GEO_URLS = [
    "http://ip-api.com/json?fields=status,country,countryCode,regionName,city,isp,query",
    "http://ip-api.com/json",
    "http://ipinfo.io/json",
]

# Открытый источник для проверки «чистоты»: ip-api.com отдаёт security-флаги
# proxy / hosting / mobile бесплатно (для некоммерческого использования).
CLEAN_URL = ("http://ip-api.com/json/?fields=status,message,country,countryCode,"
             "regionName,city,isp,org,as,query,proxy,hosting,mobile,reverse")
# Cloudflare speed endpoint — отдаёт N байт мусора, считаем пропускную способность.
SPEED_URL   = "https://speed.cloudflare.com/__down?bytes={bytes}"
SPEED_BYTES = 3_000_000          # 3 МБ — достаточно для оценки, не слишком долго
SPEED_TIMEOUT = 30


def socks5_ping(host: str, port: int, user: str, password: str,
                dest: str = "google.com", dest_port: int = 80,
                timeout: int = 10) -> tuple:
    """Raw SOCKS5 handshake — проверяет доступность и авторизацию без HTTP."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        has_auth = bool(user and password)
        methods = b"\x02" if has_auth else b"\x00"
        s.sendall(b"\x05" + bytes([len(methods)]) + methods)
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            s.close(); return False, "invalid SOCKS5 response"
        if resp[1] == 0xFF:
            s.close(); return False, "proxy refused auth methods"
        if resp[1] == 2:
            u, p = user.encode(), password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            resp = s.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                s.close(); return False, "authentication failed (wrong login/password)"
        d = dest.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d
                  + dest_port.to_bytes(2, "big"))
        resp = s.recv(10)
        s.close()
        if len(resp) < 2:
            return False, "no CONNECT response"
        if resp[1] != 0:
            codes = {1: "server error", 2: "rules forbidden", 3: "network unreachable",
                    4: "host unreachable", 5: "connection refused"}
            return False, f"CONNECT error: {codes.get(resp[1], f'code {resp[1]}')}"
        return True, "ok"
    except socket.timeout:
        return False, f"timeout {timeout}s"
    except ConnectionRefusedError:
        return False, "connection refused"
    except OSError as e:
        return False, str(e)


def socks5_udp_check(host: str, port: int, user: str, password: str,
                     timeout: int = 10) -> tuple:
    """Проверяет поддержку UDP ASSOCIATE у прокси."""
    t = u = None
    try:
        t = socket.create_connection((host, port), timeout=timeout)
        t.settimeout(timeout)
        has_auth = bool(user and password)
        methods = b"\x02" if has_auth else b"\x00"
        t.sendall(b"\x05" + bytes([len(methods)]) + methods)
        resp = t.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            return False, "invalid SOCKS5 response"
        if resp[1] == 0xFF:
            return False, "proxy refused auth methods"
        if resp[1] == 2:
            uu, pp = user.encode(), password.encode()
            t.sendall(b"\x01" + bytes([len(uu)]) + uu + bytes([len(pp)]) + pp)
            resp = t.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                return False, "authentication failed (wrong login/password)"
        t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        resp = t.recv(10)
        if len(resp) < 10 or resp[1] != 0:
            return False, "UDP ASSOCIATE rejected by proxy"
        bnd_ip = socket.inet_ntoa(resp[4:8])
        bnd_port = struct.unpack("!H", resp[8:10])[0]
        if bnd_ip in ("0.0.0.0", "127.0.0.1"):
            bnd_ip = host
        dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for part in b"example.com".split(b"."):
            dns += bytes([len(part)]) + part
        dns += b"\x00\x00\x01\x00\x01"
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") \
            + struct.pack("!H", 53) + dns
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(timeout)
        u.sendto(pkt, (bnd_ip, bnd_port))
        data, _ = u.recvfrom(2048)
        if len(data) > 10:
            return True, "ok"
        return False, "empty UDP response"
    except socket.timeout:
        return False, "UDP relay timeout (associate granted, no forwarding)"
    except ConnectionRefusedError:
        return False, "connection refused"
    except OSError as e:
        return False, str(e)
    finally:
        for sk in (u, t):
            try:
                if sk:
                    sk.close()
            except Exception:
                pass


def quic_udp_check(host: str, port: int, user: str, password: str,
                   timeout: int = 10) -> tuple:
    """Проверяет QUIC именно на порту 443 (реальный порт QUIC-трафика с
    устройств), а не на 53 как socks5_udp_check. Некоторые прокси-провайдеры
    режут UDP выборочно по порту (DNS/53 разрешают, высоконагруженный 443 —
    нет), и тогда "UDP работает" по DNS-тесту было бы ложноположительным.

    Шлём QUIC Initial-пакет с заведомо неподдерживаемой ("greased", см.
    RFC 9000 §15) версией 0x1a2a3a4a на 1.1.1.1:443 (Cloudflare, всегда
    поднят QUIC/HTTP3). Любой сервер, поддерживающий QUIC, обязан ответить
    Version Negotiation пакетом (version=0) — даже не пытаясь провести
    хендшейк, поэтому этого достаточно как честного теста доходимости порта,
    без реализации полного QUIC-стека."""
    t = u = None
    try:
        t = socket.create_connection((host, port), timeout=timeout)
        t.settimeout(timeout)
        has_auth = bool(user and password)
        methods = b"\x02" if has_auth else b"\x00"
        t.sendall(b"\x05" + bytes([len(methods)]) + methods)
        resp = t.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            return False, "invalid SOCKS5 response"
        if resp[1] == 0xFF:
            return False, "proxy refused auth methods"
        if resp[1] == 2:
            uu, pp = user.encode(), password.encode()
            t.sendall(b"\x01" + bytes([len(uu)]) + uu + bytes([len(pp)]) + pp)
            resp = t.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                return False, "authentication failed (wrong login/password)"
        t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        resp = t.recv(10)
        if len(resp) < 10 or resp[1] != 0:
            return False, "UDP ASSOCIATE rejected by proxy"
        bnd_ip = socket.inet_ntoa(resp[4:8])
        bnd_port = struct.unpack("!H", resp[8:10])[0]
        if bnd_ip in ("0.0.0.0", "127.0.0.1"):
            bnd_ip = host

        # Минимальный QUIC long-header пакет: form=1, fixed=1, type=Initial(00).
        # Token/Length/Packet Number можно не добавлять — сервер отклоняет
        # пакет по неизвестной версии ДО попытки разобрать остальное тело.
        dcid, scid = os.urandom(8), os.urandom(8)
        quic_pkt = bytes([0xC0]) + struct.pack("!I", 0x1A2A3A4A) \
            + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        # RFC 9000 §14.1: датаграмму с Initial клиент обязан набить минимум
        # до 1200 байт — часть серверов молча дропает более короткие пакеты
        # как защиту от amplification-атак, и тест ложно провалится.
        if len(quic_pkt) < 1200:
            quic_pkt += b"\x00" * (1200 - len(quic_pkt))

        pkt = b"\x00\x00\x00\x01" + socket.inet_aton(QUIC_TARGET_IP) \
            + struct.pack("!H", QUIC_TARGET_PORT) + quic_pkt
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(timeout)
        u.sendto(pkt, (bnd_ip, bnd_port))
        data, _ = u.recvfrom(2048)

        # Снимаем SOCKS5 UDP-релей заголовок (RFC 1928 §7): RSV(2) FRAG(1)
        # ATYP(1) ADDR(var) PORT(2), дальше — сырые байты от QUIC-сервера.
        if len(data) < 10:
            return False, "empty/short UDP response"
        atyp = data[3]
        if atyp == 1:
            payload = data[10:]
        elif atyp == 4:
            payload = data[22:]
        elif atyp == 3:
            payload = data[5 + data[4] + 2:]
        else:
            return False, f"unknown SOCKS5 ATYP in reply ({atyp})"

        if len(payload) < 5:
            return False, "response too short to be a QUIC packet"
        if (payload[0] & 0x80) == 0:
            return False, "response is not a QUIC long-header packet"
        resp_version = struct.unpack("!I", payload[1:5])[0]
        if resp_version != 0:
            return False, f"unexpected QUIC version 0x{resp_version:08x} (expected Version Negotiation)"
        return True, "ok"
    except socket.timeout:
        return False, "no response on port 443 (UDP ASSOCIATE works, but 443 seems filtered)"
    except ConnectionRefusedError:
        return False, "connection refused"
    except OSError as e:
        return False, str(e)
    finally:
        for sk in (u, t):
            try:
                if sk:
                    sk.close()
            except Exception:
                pass


def measure_speed(proxies: dict) -> tuple:
    """Качает SPEED_BYTES через прокси, возвращает (mbps, kb_per_s, latency_ms)
    или (None, None, None) при ошибке."""
    url = SPEED_URL.format(bytes=SPEED_BYTES)
    try:
        t0 = time.time()
        r = requests.get(url, proxies=proxies, timeout=SPEED_TIMEOUT, stream=True)
        r.raise_for_status()
        total = 0
        first_byte_at = None
        for chunk in r.iter_content(65536):
            if not chunk:
                continue
            if first_byte_at is None:
                first_byte_at = time.time()
            total += len(chunk)
        dt = time.time() - t0
        if total <= 0 or dt <= 0:
            return None, None, None
        bytes_per_s = total / dt
        kb_per_s    = bytes_per_s / 1024
        mbps        = bytes_per_s * 8 / 1_000_000
        latency_ms  = int((first_byte_at - t0) * 1000) if first_byte_at else None
        return mbps, kb_per_s, latency_ms
    except Exception:
        return None, None, None


# ── Строки интерфейса ─────────────────────────────────────────────────────────

S = {
    "ru": {
        "title":          "JackalRouter — Пульт управления",
        "subtitle":       "Управление прокси-маршрутизацией",
        "cur_label":      "Раздаётся:",
        "cur_none":       "— нажмите ⟳ или «Проверить сервер»",
        "cur_loading":    "запрашиваю через активный прокси…",
        "cur_fmt":        "{}  |  {}  |  {}",
        "cur_err":        "не удалось определить ({})",
        "cur_no_proxy":   "прокси не задан — нажмите Route",
        "cur_partial":    "{} активен (вставьте этот прокси в поле для гео)",
        "btn_health":     "⚡  Тест канала",
        "health_checking": "Тест пропускной через сервер…",
        "health_start":   "→  GET /proxy_health  (качаю 512 КБ через активный прокси с Ubuntu)",
        "health_ok":      "✓ Канал жив: докачано {} КБ за {}s ({} КБ/с) — bulk проходит",
        "health_stall":   "✗ Прокси затыкается: отдал лишь {} КБ и встал ({}s). Мёртвый прокси — меняйте.",
        "health_noproxy": "Прокси не задан на сервере — нажмите Route",
        "health_err":     "✗ Тест не выполнен: {}",
        "health_st_ok":   "Канал работает ✓",
        "health_st_fail": "Прокси не тянет ✗",
        "btn_update":     "⬆  Update",
        "update_checking": "Проверяю обновления на сервере…",
        "update_start":   "→  POST http://{}:{}/self_update",
        "update_uptodate": "✓ На сервере уже последняя версия",
        "update_applied": "✓ Обновление применено, сервис перезапускается…",
        "update_verifying": "Проверяю, что сервис поднялся после обновления…",
        "update_done":    "✓ Обновлено и работает — сервис в норме",
        "update_done_slow": "⚠ Обновление применено, но сервис пока не ответил — проверьте сервер",
        "update_err":     "✗ Обновление не выполнено: {}",
        "update_st_checking": "Проверка обновлений…",
        "update_st_uptodate": "Актуально ✓",
        "update_st_done": "Обновлено ✓",
        "update_st_err":  "Ошибка обновления ✗",
        "client_update_banner": "⬆  Доступно обновление клиента — нажмите, чтобы обновить и перезапустить",
        "client_update_applying": "Скачиваю обновление и перезапускаю клиента…",
        "client_update_bad": "✗ Новая версия не прошла проверку, НЕ применена: {}",
        "client_update_no_bat": "✗ update_client.bat не найден рядом — обновите клиента вручную (git pull / скачайте заново).",
        "client_update_check_err": "Проверка обновления клиента не удалась: {}",
        "errc_no_proxy":        "прокси не задан на сервере",
        "errc_socks_handshake": "прокси не отвечает по SOCKS5",
        "errc_socks_auth":      "неверный логин/пароль прокси",
        "errc_socks_connect":   "прокси не смог открыть соединение",
        "errc_timeout":         "таймаут соединения с прокси",
        "errc_tls":             "ошибка TLS через прокси",
        "errc_geo":             "гео-сервис не ответил через прокси",
        "sec_server":     "СЕРВЕР UBUNTU",
        "sec_proxy":      "SOCKS5 ПРОКСИ",
        "ip_label":       "IP Ubuntu:",
        "proxy_label":    "Прокси:",
        "hint":           "Формат: ip:port:user:pass  или  user:pass@ip:port",
        "btn_apply":      "  Route  ",
        "btn_stop":       "  ⊘ Stop  ",
        "chk_quic":       "Блокировать QUIC (лучше для детекта)",
        "btn_check":      "⬡  Проверить прокси",
        "btn_udp":        "⬡  Проверить UDP",
        "btn_server":     "⬡  Проверить сервер",
        "log_header":     "Лог:",
        "ready":          "Готов к работе",
        "sending":        "Отправка на Ubuntu…",
        "checking":       "Проверяю прокси…",
        "srv_checking":   "Проверяю сервер…",
        "err_no_ip":      "Укажите IP-адрес Ubuntu.",
        "err_no_proxy":   "Вставьте строку прокси.",
        "err_format":     "Неверный формат: {}",
        "err_format2":    "Ожидается:  ip:port:user:pass  или  user:pass@ip:port",
        "log_sending":    "→  POST http://{}:{}/set_proxy",
        "log_ok":         "Прокси применён. Роутер раздаёт американский интернет [{}]",
        "log_conn_err":   "Нет связи с {}:{}. Проверьте IP и что сервер запущен.",
        "log_timeout":    "Таймаут {}с — Ubuntu не отвечает.",
        "log_http_err":   "Ошибка сервера {}: {}",
        "log_unk_err":    "Неожиданная ошибка: {}",
        "st_ok":          "Прокси применён ✓",
        "st_err":         "Ошибка",
        "chk_start":      "Проверяю прокси через {}:{} …",
        "chk_ok":         "✓ Рабочий  |  IP: {}  |  {}, {}  |  {}",
        "chk_warn":       "⚠ Работает, но НЕ США: {} ({}, {})",
        "chk_fail":       "✗ Прокси недоступен: {}",
        "chk_st_ok":      "Прокси работает ✓",
        "chk_st_warn":    "Не США ⚠",
        "chk_st_fail":    "Прокси не работает ✗",
        "udp_checking":   "Проверяю UDP…",
        "udp_start":      "Проверяю UDP ASSOCIATE через {}:{} …",
        "udp_assoc_ok":   "✓ UDP ASSOCIATE работает (DNS :53 через релей)",
        "udp_fail":       "✗ UDP ASSOCIATE не поддерживается: {}",
        "udp_note":       "   › QUIC будет заблокирован (DROP). Это повышает fraud-score антидетектов.",
        "quic_start":     "Проверяю QUIC на порту 443 (реальный порт QUIC-трафика с устройств)…",
        "quic_ok":        "✓ QUIC/443 отвечает  |  реальный QUIC-трафик с устройств пойдёт через прокси",
        "quic_fail":      "✗ QUIC/443 не отвечает: {}",
        "quic_note":      "   › UDP в целом работает, но порт 443 у прокси похоже фильтруется отдельно — реальный QUIC с устройств может не проходить, хотя DNS-релей работал.",
        "udp_st_ok":      "UDP + QUIC работают ✓",
        "udp_st_fail":    "UDP не работает ✗",
        "udp_st_quic_fail": "UDP есть, QUIC/443 — нет ⚠",
        "btn_clean":      "⬡  Проверить чистоту",
        "clean_checking": "Проверяю чистоту и скорость…",
        "clean_start":    "Проверяю чистоту/скорость через {}:{} …",
        "clean_geo":      "   IP: {}  |  {}, {}  |  {}",
        "clean_dirty":    "✗ ГРЯЗНЫЙ — IP помечен как proxy/VPN/Tor в открытых базах",
        "clean_host":     "⚠ Datacenter/Hosting — не резидент, ↑ fraud-score антидетектов",
        "clean_ok":       "✓ ЧИСТЫЙ — резидентный IP (не proxy, не hosting)",
        "clean_flags":    "   Флаги:  proxy={}  hosting={}  mobile={}",
        "clean_rdns":     "   rDNS:  {}",
        "clean_speed":    "   Скорость: {}  |  задержка {} мс",
        "clean_speed_na": "   Скорость: измерить не удалось",
        "clean_geo_na":   "   Репутация недоступна (открытый источник не ответил через прокси)",
        "clean_st_ok":    "Чистый ✓",
        "clean_st_warn":  "Datacenter ⚠",
        "clean_st_fail":  "Грязный ✗",
        "srv_up":         "✓  JackalRouter отвечает",
        "srv_warn":       "⚠  Сервер отвечает — есть проблемы",
        "srv_down":       "✗  Сервер не отвечает на {}:{}",
        "srv_hint":       "   → sudo systemctl start jackalrouter",
        "srv_no_proxy":   "   › Прокси не задан — нажмите Route",
        "srv_proxy":      "   › Прокси: {}",
        "srv_ipt_ok":     "настроена",
        "srv_ipt_err":    "НЕ настроена",
        "srv_desc_sb":    "TCP/UDP → sing-box → SOCKS5",
        "srv_desc_dns":   "DHCP-сервер / DNS",
        "srv_st_ok":      "Сервер ✓",
        "srv_st_warn":    "Сервер ⚠",
        "srv_st_down":    "Сервер недоступен ✗",
        # История
        "tab_main":       "Управление",
        "tab_history":    "История",
        "hist_col_proxy": "Прокси",
        "hist_col_geo":   "Страна / Город",
        "hist_col_isp":   "ISP",
        "hist_col_date":  "Когда",
        "hist_col_st":    "Ст.",
        "hist_load":      "⇥  Загрузить",
        "hist_check":     "⬡  Проверить",
        "hist_delete":    "✕  Удалить",
        "hist_nosel":     "Выберите прокси в таблице",
        "hist_dblclick":  "Двойной клик — загрузить прокси в поле выше",
        "hist_loaded":    "Загружен из истории: {}",
        "hist_checking":  "Проверяю прокси из истории…",
    },
    "en": {
        "title":          "JackalRouter — Control Panel",
        "subtitle":       "Proxy routing management",
        "cur_label":      "Broadcasting:",
        "cur_none":       "— click ⟳ or “Check server”",
        "cur_loading":    "querying via active proxy…",
        "cur_fmt":        "{}  |  {}  |  {}",
        "cur_err":        "could not determine ({})",
        "cur_no_proxy":   "no proxy set — click Route",
        "cur_partial":    "{} active (paste this proxy into the field for geo)",
        "btn_health":     "⚡  Bulk test",
        "health_checking": "Bulk test via server…",
        "health_start":   "→  GET /proxy_health  (downloading 512 KB through the active proxy from Ubuntu)",
        "health_ok":      "✓ Channel alive: {} KB in {}s ({} KB/s) — bulk works",
        "health_stall":   "✗ Proxy stalls: only {} KB then froze ({}s). Dead proxy — replace it.",
        "health_noproxy": "No proxy set on server — click Route",
        "health_err":     "✗ Test failed: {}",
        "health_st_ok":   "Channel works ✓",
        "health_st_fail": "Proxy can't pull ✗",
        "btn_update":     "⬆  Update",
        "update_checking": "Checking for updates on the server…",
        "update_start":   "→  POST http://{}:{}/self_update",
        "update_uptodate": "✓ Server already has the latest version",
        "update_applied": "✓ Update applied, service is restarting…",
        "update_verifying": "Checking the service came back up after the update…",
        "update_done":    "✓ Updated and running — service healthy",
        "update_done_slow": "⚠ Update applied, but the service hasn't responded yet — check the server",
        "update_err":     "✗ Update failed: {}",
        "update_st_checking": "Checking for updates…",
        "update_st_uptodate": "Up to date ✓",
        "update_st_done": "Updated ✓",
        "update_st_err":  "Update failed ✗",
        "client_update_banner": "⬆  Client update available — click to update and restart",
        "client_update_applying": "Downloading update and restarting the client…",
        "client_update_bad": "✗ New version failed validation, NOT applied: {}",
        "client_update_no_bat": "✗ update_client.bat not found nearby — update the client manually (git pull / re-download).",
        "client_update_check_err": "Client update check failed: {}",
        "errc_no_proxy":        "no proxy set on server",
        "errc_socks_handshake": "proxy SOCKS5 handshake failed",
        "errc_socks_auth":      "wrong proxy login/password",
        "errc_socks_connect":   "proxy could not open connection",
        "errc_timeout":         "proxy connection timeout",
        "errc_tls":             "TLS error via proxy",
        "errc_geo":             "geo service did not respond via proxy",
        "sec_server":     "UBUNTU SERVER",
        "sec_proxy":      "SOCKS5 PROXY",
        "ip_label":       "Ubuntu IP:",
        "proxy_label":    "Proxy:",
        "hint":           "Format: ip:port:user:pass  or  user:pass@ip:port",
        "btn_apply":      "  Route  ",
        "btn_stop":       "  ⊘ Stop  ",
        "chk_quic":       "Block QUIC (better for detection)",
        "btn_check":      "⬡  Check proxy",
        "btn_udp":        "⬡  Check UDP",
        "btn_server":     "⬡  Check server",
        "log_header":     "Log:",
        "ready":          "Ready",
        "sending":        "Sending to Ubuntu…",
        "checking":       "Checking proxy…",
        "srv_checking":   "Checking server…",
        "err_no_ip":      "Enter Ubuntu IP address.",
        "err_no_proxy":   "Paste proxy string.",
        "err_format":     "Invalid format: {}",
        "err_format2":    "Expected:  ip:port:user:pass  or  user:pass@ip:port",
        "log_sending":    "→  POST http://{}:{}/set_proxy",
        "log_ok":         "Proxy applied. Router is broadcasting US internet [{}]",
        "log_conn_err":   "Cannot connect to {}:{}. Check IP and server status.",
        "log_timeout":    "Timeout {}s — Ubuntu not responding.",
        "log_http_err":   "Server error {}: {}",
        "log_unk_err":    "Unexpected error: {}",
        "st_ok":          "Proxy applied ✓",
        "st_err":         "Error",
        "chk_start":      "Checking proxy via {}:{} …",
        "chk_ok":         "✓ Working  |  IP: {}  |  {}, {}  |  {}",
        "chk_warn":       "⚠ Works but NOT US: {} ({}, {})",
        "chk_fail":       "✗ Proxy unreachable: {}",
        "chk_st_ok":      "Proxy works ✓",
        "chk_st_warn":    "Not US ⚠",
        "chk_st_fail":    "Proxy failed ✗",
        "udp_checking":   "Checking UDP…",
        "udp_start":      "Checking UDP ASSOCIATE via {}:{} …",
        "udp_assoc_ok":   "✓ UDP ASSOCIATE works (DNS :53 via relay)",
        "udp_fail":       "✗ UDP ASSOCIATE not supported: {}",
        "udp_note":       "   › QUIC will be blocked (DROP). This raises antidetect fraud-score.",
        "quic_start":     "Checking QUIC on port 443 (the real port devices use for QUIC)…",
        "quic_ok":        "✓ QUIC/443 responds  |  real QUIC traffic from devices will go through the proxy",
        "quic_fail":      "✗ QUIC/443 not responding: {}",
        "quic_note":      "   › UDP works in general, but port 443 seems filtered separately by the proxy — real QUIC from devices may not get through, even though the DNS relay worked.",
        "udp_st_ok":      "UDP + QUIC work ✓",
        "udp_st_fail":    "UDP failed ✗",
        "udp_st_quic_fail": "UDP works, QUIC/443 doesn't ⚠",
        "btn_clean":      "⬡  Check cleanliness",
        "clean_checking": "Checking cleanliness & speed…",
        "clean_start":    "Checking cleanliness/speed via {}:{} …",
        "clean_geo":      "   IP: {}  |  {}, {}  |  {}",
        "clean_dirty":    "✗ DIRTY — IP flagged as proxy/VPN/Tor in open databases",
        "clean_host":     "⚠ Datacenter/Hosting — not residential, ↑ antidetect fraud-score",
        "clean_ok":       "✓ CLEAN — residential IP (not proxy, not hosting)",
        "clean_flags":    "   Flags:  proxy={}  hosting={}  mobile={}",
        "clean_rdns":     "   rDNS:  {}",
        "clean_speed":    "   Speed: {}  |  latency {} ms",
        "clean_speed_na": "   Speed: measurement failed",
        "clean_geo_na":   "   Reputation unavailable (open source did not respond via proxy)",
        "clean_st_ok":    "Clean ✓",
        "clean_st_warn":  "Datacenter ⚠",
        "clean_st_fail":  "Dirty ✗",
        "srv_up":         "✓  JackalRouter is running",
        "srv_warn":       "⚠  Server responds — issues found",
        "srv_down":       "✗  Server not responding at {}:{}",
        "srv_hint":       "   → sudo systemctl start jackalrouter",
        "srv_no_proxy":   "   › No proxy set — click Route",
        "srv_proxy":      "   › Proxy: {}",
        "srv_ipt_ok":     "configured",
        "srv_ipt_err":    "NOT configured",
        "srv_desc_sb":    "TCP/UDP → sing-box → SOCKS5",
        "srv_desc_dns":   "DHCP server / DNS",
        "srv_st_ok":      "Server ✓",
        "srv_st_warn":    "Server ⚠",
        "srv_st_down":    "Server unreachable ✗",
        # History
        "tab_main":       "Control",
        "tab_history":    "History",
        "hist_col_proxy": "Proxy",
        "hist_col_geo":   "Country / City",
        "hist_col_isp":   "ISP",
        "hist_col_date":  "When",
        "hist_col_st":    "St.",
        "hist_load":      "⇥  Load",
        "hist_check":     "⬡  Check",
        "hist_delete":    "✕  Delete",
        "hist_nosel":     "Select a proxy in the table",
        "hist_dblclick":  "Double-click to load proxy into the field above",
        "hist_loaded":    "Loaded from history: {}",
        "hist_checking":  "Checking proxy from history…",
    },
}

# ── Парсинг прокси ────────────────────────────────────────────────────────────

def parse_proxy(s: str):
    """Returns dict(ip, port, user, password) or None."""
    s = s.strip()
    s = re.sub(r'^[a-zA-Z0-9+.\-]+://', '', s)
    m = re.match(r'^([^:@]+):(.+)@([\d.]+):(\d+)$', s)
    if m:
        return {"user": m.group(1), "password": m.group(2),
                "ip": m.group(3), "port": int(m.group(4))}
    parts = s.split(":", 3)
    if len(parts) == 4 and re.match(r'^\d{1,5}$', parts[1]):
        return {"ip": parts[0], "port": int(parts[1]),
                "user": parts[2], "password": parts[3]}
    return None


# ── Скруглённая кнопка (Canvas) с hover-эффектом ──────────────────────────────

class RoundedButton(tk.Canvas):
    """Кнопка со скруглёнными углами, нарисованная на Canvas. Поддерживает
    hover, disabled-состояние, смену текста/цвета и тянется по fill='x'."""

    def __init__(self, parent, text="", command=None, *, width=150, height=36,
                 radius=10, bg="#313244", fg="#cdd6f4", hover="#45475a",
                 page_bg="#1e1e2e", font=("Segoe UI", 9, "bold")):
        super().__init__(parent, width=width, height=height, bg=page_bg,
                         highlightthickness=0, bd=0, takefocus=0)
        self.command = command
        self._radius = radius
        self._bg, self._hover, self._fg = bg, hover, fg
        self._dis_bg, self._dis_fg = "#26263a", "#585b70"
        self._font = font
        self._text = text
        self._cw, self._ch = width, height
        self._state = "normal"
        self._hovering = False
        self.bind("<Configure>", self._on_configure)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self._redraw()

    @staticmethod
    def _round_pts(x1, y1, x2, y2, r):
        return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
                x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]

    def _fill(self):
        if self._state == "disabled":
            return self._dis_bg
        return self._hover if self._hovering else self._bg

    def _redraw(self):
        self.delete("all")
        w, h = self._cw, self._ch
        r = max(2, min(self._radius, h // 2, w // 2))
        f = self._fill()
        self.create_polygon(self._round_pts(1, 1, w - 1, h - 1, r),
                            smooth=True, splinesteps=24, fill=f, outline=f)
        fg = self._dis_fg if self._state == "disabled" else self._fg
        self.create_text(w / 2, h / 2, text=self._text, fill=fg, font=self._font)

    def _on_configure(self, e):
        self._cw, self._ch = e.width, e.height
        self._redraw()

    def _on_enter(self, _e):
        if self._state == "normal":
            self._hovering = True
            self.configure(cursor="hand2")
            self._redraw()

    def _on_leave(self, _e):
        self._hovering = False
        self._redraw()

    def _on_click(self, _e):
        if self._state == "normal" and self.command:
            self.command()

    def config_text(self, text):
        self._text = text
        self._redraw()

    def set_state(self, state):
        self._state = "normal" if state in ("normal", True) else "disabled"
        if self._state == "disabled":
            self._hovering = False
            self.configure(cursor="")
        self._redraw()

    def set_colors(self, bg=None, fg=None, hover=None):
        if bg:    self._bg = bg
        if fg:    self._fg = fg
        if hover: self._hover = hover
        self._redraw()


# ── Приложение ────────────────────────────────────────────────────────────────

class App:
    BG      = "#11111b"   # фон страницы (crust)
    CARD    = "#1e1e2e"   # карточки (base)
    PANEL   = "#181825"   # инпуты / лог (mantle)
    TEXT    = "#cdd6f4"
    SUB     = "#a6adc8"
    MUTED   = "#6c7086"
    BLUE    = "#89b4fa"
    SAPPH   = "#74c7ec"
    GREEN   = "#a6e3a1"
    RED     = "#f38ba8"
    YELLOW  = "#f9e2af"
    MAUVE   = "#cba6f7"
    SURF    = "#313244"
    SURF2   = "#45475a"
    BORDER  = "#313244"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.lang = "ru"
        self.history = self._load_history()
        self.config = self._load_config()
        self._pending_proxy = ""
        root.geometry("780x680")
        root.resizable(True, True)
        root.minsize(720, 600)
        root.configure(bg=self.BG)
        self._build()
        self._apply_lang()
        # Тихая фоновая проверка обновления клиента — не блокирует запуск,
        # ничего не показывает, если обновлять нечего.
        self._client_update_content = None
        threading.Thread(target=self._check_client_update_bg, daemon=True).start()

    # ── Построение UI ─────────────────────────────────────────────────────────

    def _build(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=self.BG, borderwidth=0,
                        tabmargins=[8, 6, 8, 0])
        style.configure("TNotebook.Tab", background=self.BG, foreground=self.MUTED,
                        font=("Segoe UI", 10, "bold"), padding=[20, 9], borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", self.CARD)],
                  foreground=[("selected", self.BLUE), ("active", self.TEXT)])
        style.configure("Hist.Treeview", background=self.PANEL, foreground=self.TEXT,
                        fieldbackground=self.PANEL, rowheight=30,
                        font=("Consolas", 9), borderwidth=0)
        style.configure("Hist.Treeview.Heading", background=self.CARD, foreground=self.SUB,
                        font=("Segoe UI", 9, "bold"), relief="flat", padding=[6, 7])
        style.map("Hist.Treeview.Heading", background=[("active", self.SURF)])
        style.map("Hist.Treeview",
                  background=[("selected", self.SURF)],
                  foreground=[("selected", self.BLUE)])
        style.configure("Hist.Vertical.TScrollbar", background=self.SURF,
                        troughcolor=self.BG, arrowcolor=self.MUTED, borderwidth=0)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_main = tk.Frame(self.notebook, bg=self.BG)
        self.tab_hist = tk.Frame(self.notebook, bg=self.BG)
        self.notebook.add(self.tab_main, text="Управление")
        self.notebook.add(self.tab_hist, text="История")

        self._build_main_tab()
        self._build_history_tab()

    def _card(self, parent, accent=None, expand=False, pady=(0, 12)):
        """Карточка-секция: лёгкая рамка, опциональная акцентная полоса слева."""
        card = tk.Frame(parent, bg=self.CARD,
                        highlightbackground=self.BORDER, highlightthickness=1)
        card.pack(fill="both" if expand else "x", expand=expand, padx=18, pady=pady)
        if accent:
            tk.Frame(card, bg=accent, width=3).pack(side="left", fill="y")
        inner = tk.Frame(card, bg=self.CARD)
        inner.pack(side="left", fill="both", expand=True, padx=16, pady=13)
        return inner

    def _sec(self, parent):
        lbl = tk.Label(parent, bg=self.CARD, fg=self.MUTED,
                       font=("Segoe UI", 8, "bold"))
        lbl.pack(anchor="w", pady=(0, 9))
        return lbl

    def _build_main_tab(self):
        p = self.tab_main

        # ── Шапка: акцент + заголовок + сегментированный язык ────────────────
        head = tk.Frame(p, bg=self.BG)
        head.pack(fill="x", padx=18, pady=(16, 12))

        title_box = tk.Frame(head, bg=self.BG)
        title_box.pack(side="left")
        tk.Frame(title_box, bg=self.BLUE, width=4, height=40).pack(side="left", padx=(0, 12))
        tbox = tk.Frame(title_box, bg=self.BG)
        tbox.pack(side="left")
        self.lbl_title = tk.Label(tbox, bg=self.BG, fg=self.TEXT,
                                  font=("Segoe UI Semibold", 17, "bold"))
        self.lbl_title.pack(anchor="w")
        self.lbl_subtitle = tk.Label(tbox, bg=self.BG, fg=self.MUTED,
                                     font=("Segoe UI", 9))
        self.lbl_subtitle.pack(anchor="w")

        seg = tk.Frame(head, bg=self.SURF, highlightbackground=self.BORDER,
                       highlightthickness=1)
        seg.pack(side="right", anchor="n", pady=(3, 0))
        self.btn_ru = RoundedButton(seg, text="RU", width=42, height=26, radius=7,
                                    bg=self.SURF, fg=self.MUTED, hover=self.SURF2,
                                    page_bg=self.SURF, command=lambda: self._set_lang("ru"))
        self.btn_ru.pack(side="left", padx=2, pady=2)
        self.btn_en = RoundedButton(seg, text="EN", width=42, height=26, radius=7,
                                    bg=self.SURF, fg=self.MUTED, hover=self.SURF2,
                                    page_bg=self.SURF, command=lambda: self._set_lang("en"))
        self.btn_en.pack(side="left", padx=2, pady=2)

        self.btn_update = RoundedButton(head, text="", width=110, height=28, radius=8,
                                        bg=self.SURF, fg=self.MUTED, hover=self.SURF2,
                                        page_bg=self.BG, command=self._on_update)
        self.btn_update.pack(side="right", anchor="n", padx=(0, 8), pady=(3, 0))

        # ── Баннер «доступно обновление клиента» — скрыт, пока не найдено ────
        # обновление на GitHub (проверяется тихо в фоне при старте). НЕ packed
        # заранее: место не занимает и не отвлекает, если обновлять нечего.
        self.banner_client_update = tk.Label(
            p, bg=self.BLUE, fg=self.BG, font=("Segoe UI", 9, "bold"),
            cursor="hand2", pady=6)
        self.banner_client_update.bind("<Button-1>", lambda e: self._on_client_update_apply())

        # ── Карточка «Сейчас раздаётся» ──────────────────────────────────────
        cur = self._card(p, accent=self.GREEN, pady=(0, 12))
        # _card() возвращает внутренний inner-фрейм, а не тот, что реально
        # packed в p — для banner_client_update ниже нужна ссылка именно на
        # packed-обёртку (cur.master), чтобы вставить баннер ПЕРЕД ней через before=.
        self._card_cur_frame = cur.master
        cur_row = tk.Frame(cur, bg=self.CARD)
        cur_row.pack(fill="x")
        self.btn_cur = RoundedButton(cur_row, text="⟳", width=42, height=34, radius=9,
                                     bg=self.SURF, fg=self.TEXT, hover=self.SURF2,
                                     page_bg=self.CARD, font=("Segoe UI", 13, "bold"),
                                     command=self._on_refresh_current)
        self.btn_cur.pack(side="right")
        self.btn_health = RoundedButton(cur_row, text="", width=148, height=34,
                                        bg=self.SURF, fg=self.YELLOW, hover=self.SURF2,
                                        page_bg=self.CARD, command=self._on_health)
        self.btn_health.pack(side="right", padx=(0, 8))
        self.lbl_cur_dot = tk.Label(cur_row, text="●", bg=self.CARD, fg=self.MUTED,
                                    font=("Segoe UI", 12))
        self.lbl_cur_dot.pack(side="left", padx=(0, 10))
        cur_txt = tk.Frame(cur_row, bg=self.CARD)
        cur_txt.pack(side="left", fill="x", expand=True)
        self.lbl_cur_title = tk.Label(cur_txt, bg=self.CARD, fg=self.SUB,
                                      font=("Segoe UI", 8, "bold"))
        self.lbl_cur_title.pack(anchor="w")
        self.lbl_cur_val = tk.Label(cur_txt, bg=self.CARD, fg=self.MUTED,
                                    font=("Segoe UI", 10), anchor="w", justify="left")
        self.lbl_cur_val.pack(anchor="w")

        # ── Карточка «Сервер» ────────────────────────────────────────────────
        srv = self._card(p, accent=self.BLUE)
        self.lbl_sec_server = self._sec(srv)
        srv_row = tk.Frame(srv, bg=self.CARD)
        srv_row.pack(fill="x")
        self.lbl_ip = tk.Label(srv_row, bg=self.CARD, fg=self.SUB,
                               font=("Segoe UI", 9), width=11, anchor="w")
        self.lbl_ip.pack(side="left")
        # Не хардкодим IP — подставляем последний использованный (если есть),
        # иначе оставляем поле пустым, пользователь вводит его сам.
        self.ip_var = tk.StringVar(value=self.config.get("server_ip", ""))
        self._entry(srv_row, self.ip_var, width=18).pack(side="left", padx=(4, 12), ipady=4)
        self.btn_server = RoundedButton(srv_row, text="", width=170, height=34,
                                        bg=self.SURF, fg=self.TEXT, hover=self.SURF2,
                                        page_bg=self.CARD, command=self._on_server_check)
        self.btn_server.pack(side="left")

        # ── Карточка «Прокси» ────────────────────────────────────────────────
        prx = self._card(p, accent=self.MAUVE)
        self.lbl_sec_proxy = self._sec(prx)
        self.proxy_var = tk.StringVar()
        pe = self._entry(prx, self.proxy_var, width=55)
        pe.pack(fill="x", ipady=5)
        pe.focus()
        pe.bind("<Control-v>", self._paste_proxy)
        pe.bind("<Control-V>", self._paste_proxy)
        self.lbl_hint = tk.Label(prx, bg=self.CARD, fg=self.MUTED, font=("Segoe UI", 8))
        self.lbl_hint.pack(anchor="w", pady=(7, 11))
        btns = tk.Frame(prx, bg=self.CARD)
        btns.pack(fill="x")
        self.btn_check = RoundedButton(btns, text="", width=172, height=34,
                                       bg=self.SURF, fg=self.TEXT, hover=self.SURF2,
                                       page_bg=self.CARD, command=self._on_check)
        self.btn_check.pack(side="left")
        self.btn_udp = RoundedButton(btns, text="", width=150, height=34,
                                     bg=self.SURF, fg=self.TEXT, hover=self.SURF2,
                                     page_bg=self.CARD, command=self._on_udp_check)
        self.btn_udp.pack(side="left", padx=(8, 0))
        self.btn_clean = RoundedButton(btns, text="", width=180, height=34,
                                       bg=self.SURF, fg=self.TEXT, hover=self.SURF2,
                                       page_bg=self.CARD, command=self._on_clean_check)
        self.btn_clean.pack(side="left", padx=(8, 0))

        # ── Чекбокс QUIC ─────────────────────────────────────────────────────
        quic_box = tk.Frame(p, bg=self.BG)
        quic_box.pack(fill="x", padx=18, pady=(8, 0))
        self.quic_var = tk.BooleanVar(value=False)
        self.chk_quic = tk.Checkbutton(quic_box, text="", variable=self.quic_var,
                                       bg=self.BG, fg=self.TEXT, selectcolor=self.BG,
                                       activebackground=self.BG, activeforeground=self.TEXT,
                                       font=("Segoe UI", 9), command=self._on_quic_toggle)
        self.chk_quic.pack(side="left")

        # ── Кнопки Route и Stop ──────────────────────────────────────────────
        route_box = tk.Frame(p, bg=self.BG)
        route_box.pack(fill="x", padx=18, pady=(0, 8))
        btns_row = tk.Frame(route_box, bg=self.BG)
        btns_row.pack(fill="x")
        self.btn_apply = RoundedButton(btns_row, text="", height=46, radius=12,
                                       bg=self.BLUE, fg=self.BG, hover=self.SAPPH,
                                       page_bg=self.BG, font=("Segoe UI", 12, "bold"),
                                       command=self._on_apply)
        self.btn_apply.pack(side="left", fill="both", expand=True)
        self.btn_stop = RoundedButton(btns_row, text="", height=46, radius=12,
                                      bg=self.RED, fg=self.BG, hover="#cc3333",
                                      page_bg=self.BG, font=("Segoe UI", 12, "bold"),
                                      command=self._on_stop)
        self.btn_stop.pack(side="left", fill="both", expand=True, padx=(8, 0))

        # ── Статус ───────────────────────────────────────────────────────────
        self.status_var = tk.StringVar()
        self.status_lbl = tk.Label(p, textvariable=self.status_var, bg=self.BG,
                                   fg=self.TEXT, font=("Segoe UI", 10, "bold"))
        self.status_lbl.pack(pady=(0, 8))

        # ── Карточка «Лог» ───────────────────────────────────────────────────
        log_card = self._card(p, accent=self.SURF2, expand=True, pady=(0, 16))
        self.lbl_log = tk.Label(log_card, bg=self.CARD, fg=self.MUTED,
                                font=("Segoe UI", 8, "bold"))
        self.lbl_log.pack(anchor="w", pady=(0, 6))
        self.log = scrolledtext.ScrolledText(
            log_card, bg=self.PANEL, fg=self.TEXT, font=("Consolas", 9),
            insertbackground=self.TEXT, state="disabled", relief="flat",
            borderwidth=0, highlightthickness=0)
        self.log.pack(fill="both", expand=True)
        self.log.tag_config("ok",   foreground=self.GREEN)
        self.log.tag_config("err",  foreground=self.RED)
        self.log.tag_config("info", foreground=self.BLUE)
        self.log.tag_config("warn", foreground=self.YELLOW)

    def _build_history_tab(self):
        p = self.tab_hist

        # ── Шапка ─────────────────────────────────────────────────────────────
        head = tk.Frame(p, bg=self.BG)
        head.pack(fill="x", padx=18, pady=(16, 8))
        tk.Frame(head, bg=self.MAUVE, width=4, height=26).pack(side="left", padx=(0, 12))
        self.lbl_hist_title = tk.Label(head, bg=self.BG, fg=self.TEXT,
                                       font=("Segoe UI Semibold", 14, "bold"))
        self.lbl_hist_title.pack(side="left")

        # ── Карточка с таблицей ───────────────────────────────────────────────
        card = tk.Frame(p, bg=self.CARD, highlightbackground=self.BORDER,
                        highlightthickness=1)
        card.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        tree_frame = tk.Frame(card, bg=self.CARD)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        sb = ttk.Scrollbar(tree_frame, orient="vertical",
                           style="Hist.Vertical.TScrollbar")
        self.hist_tree = ttk.Treeview(
            tree_frame, style="Hist.Treeview",
            columns=("server", "geo", "isp", "date", "status"),
            show="headings", selectmode="browse", yscrollcommand=sb.set,
        )
        sb.config(command=self.hist_tree.yview)
        sb.pack(side="right", fill="y")
        self.hist_tree.pack(fill="both", expand=True)

        self.hist_tree.column("server", width=160, minwidth=120, anchor="w")
        self.hist_tree.column("geo",    width=190, minwidth=140, anchor="w")
        self.hist_tree.column("isp",    width=170, minwidth=100, anchor="w")
        self.hist_tree.column("date",   width=92,  minwidth=80,  anchor="center")
        self.hist_tree.column("status", width=40,  minwidth=40,  anchor="center")

        self.hist_tree.tag_configure("ok",      foreground=self.GREEN)
        self.hist_tree.tag_configure("warn",    foreground=self.YELLOW)
        self.hist_tree.tag_configure("fail",    foreground=self.RED)
        self.hist_tree.tag_configure("unknown", foreground=self.MUTED)

        self.hist_tree.bind("<Double-1>", lambda _e: self._hist_load())

        # ── Кнопки действий ──────────────────────────────────────────────────
        btn_frame = tk.Frame(p, bg=self.BG)
        btn_frame.pack(fill="x", padx=18, pady=(0, 6))

        self.btn_hist_load = RoundedButton(btn_frame, text="", width=142, height=34,
                                           bg=self.SURF, fg=self.TEXT, hover=self.SURF2,
                                           page_bg=self.BG, command=self._hist_load)
        self.btn_hist_load.pack(side="left")
        self.btn_hist_check = RoundedButton(btn_frame, text="", width=142, height=34,
                                            bg=self.SURF, fg=self.TEXT, hover=self.SURF2,
                                            page_bg=self.BG, command=self._hist_check)
        self.btn_hist_check.pack(side="left", padx=(8, 0))
        self.btn_hist_delete = RoundedButton(btn_frame, text="", width=142, height=34,
                                             bg=self.SURF, fg=self.RED, hover=self.SURF2,
                                             page_bg=self.BG, command=self._hist_delete)
        self.btn_hist_delete.pack(side="left", padx=(8, 0))

        # ── Подсказка ─────────────────────────────────────────────────────────
        self.lbl_hist_hint = tk.Label(p, bg=self.BG, fg=self.MUTED,
                                      font=("Segoe UI", 8))
        self.lbl_hist_hint.pack(padx=18, anchor="w", pady=(0, 12))

        self._refresh_hist_table()

    def _entry(self, parent, var, width=30):
        return tk.Entry(
            parent, textvariable=var, width=width,
            bg=self.PANEL, fg=self.TEXT, insertbackground=self.BLUE,
            relief="flat", font=("Consolas", 11),
            highlightthickness=1, highlightbackground=self.BORDER,
            highlightcolor=self.BLUE,
        )

    # ── Язык ──────────────────────────────────────────────────────────────────

    def _set_lang(self, lang: str):
        self.lang = lang
        self._apply_lang()

    def _apply_lang(self):
        t = S[self.lang]
        self.root.title(t["title"])
        self.lbl_title.config(text="JackalRouter")
        self.lbl_subtitle.config(text=t["subtitle"])
        self.lbl_ip.config(text=t["ip_label"])
        self.lbl_hint.config(text=t["hint"])
        self.lbl_sec_server.config(text=t["sec_server"])
        self.lbl_sec_proxy.config(text=t["sec_proxy"])
        self.lbl_log.config(text=t["log_header"])
        self.lbl_cur_title.config(text=t["cur_label"])
        self.btn_apply.config_text(t["btn_apply"].strip())
        self.btn_stop.config_text(t["btn_stop"].strip())
        self.chk_quic.config(text=t["chk_quic"])
        self.btn_check.config_text(t["btn_check"])
        self.btn_udp.config_text(t["btn_udp"])
        self.btn_clean.config_text(t["btn_clean"])
        self.btn_server.config_text(t["btn_server"])
        self.btn_health.config_text(t["btn_health"])
        self.btn_update.config_text(t["btn_update"])
        self.banner_client_update.config(text=t["client_update_banner"])
        if not getattr(self, "_cur_set", False):
            self.lbl_cur_val.config(text=t["cur_none"], fg=self.MUTED)

        # сегментированный переключатель языка
        if self.lang == "ru":
            self.btn_ru.set_colors(bg=self.BLUE, fg=self.BG, hover=self.SAPPH)
            self.btn_en.set_colors(bg=self.SURF, fg=self.MUTED, hover=self.SURF2)
        else:
            self.btn_en.set_colors(bg=self.BLUE, fg=self.BG, hover=self.SAPPH)
            self.btn_ru.set_colors(bg=self.SURF, fg=self.MUTED, hover=self.SURF2)

        if not self.status_var.get():
            self._status(t["ready"], self.MUTED)

        self.notebook.tab(0, text=t["tab_main"])
        self.notebook.tab(1, text=t["tab_history"])
        self.lbl_hist_title.config(text=t["tab_history"])
        self.btn_hist_load.config_text(t["hist_load"])
        self.btn_hist_check.config_text(t["hist_check"])
        self.btn_hist_delete.config_text(t["hist_delete"])
        self.lbl_hist_hint.config(text=t["hist_dblclick"])
        for col, key in [("server", "hist_col_proxy"), ("geo", "hist_col_geo"),
                         ("isp",    "hist_col_isp"),   ("date", "hist_col_date"),
                         ("status", "hist_col_st")]:
            self.hist_tree.heading(col, text=t[key])

    def _paste_proxy(self, event):
        try:
            text = self.root.clipboard_get()
            event.widget.delete(0, tk.END)
            event.widget.insert(0, text.strip())
        except Exception:
            pass
        return "break"

    def _(self, key: str, *args) -> str:
        s = S[self.lang][key]
        return s.format(*args) if args else s

    def _errmsg(self, d: dict) -> str:
        """Локализует ошибку из ответа сервера по error_code; иначе — сырой текст."""
        code = d.get("error_code")
        key = f"errc_{code}" if code else None
        if key and key in S[self.lang]:
            return self._(key)
        return d.get("error", "?")

    # ── Логирование ───────────────────────────────────────────────────────────

    def _log(self, msg: str, tag: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.config(state="normal")
        self.log.insert("end", f"[{ts}] {msg}\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def _status(self, msg: str, color: str = None):
        self.status_var.set(f"●  {msg}")
        self.status_lbl.config(fg=color or self.TEXT)

    def _set_buttons(self, enabled: bool):
        st = "normal" if enabled else "disabled"
        for b in (self.btn_apply, self.btn_stop, self.btn_check, self.btn_udp, self.btn_clean,
                  self.btn_server, self.btn_cur, self.btn_health, self.btn_hist_load,
                  self.btn_hist_check, self.btn_hist_delete, self.btn_update):
            b.set_state(st)

    # ── Применить прокси ──────────────────────────────────────────────────────

    def _on_apply(self):
        proxy     = self.proxy_var.get().strip()
        ubuntu_ip = self.ip_var.get().strip()

        if not ubuntu_ip:
            self._log(self._("err_no_ip"), "err"); return
        if not proxy:
            self._log(self._("err_no_proxy"), "err"); return
        if not parse_proxy(proxy):
            self._log(self._("err_format", proxy), "err")
            self._log(self._("err_format2"), "warn"); return

        self._remember_ip(ubuntu_ip)
        self._pending_proxy = proxy
        self._set_buttons(False)
        self._status(self._("sending"), self.YELLOW)
        self._log(self._("log_sending", ubuntu_ip, SERVER_PORT), "info")
        threading.Thread(target=self._send, args=(ubuntu_ip, proxy), daemon=True).start()

    def _send(self, ubuntu_ip: str, proxy: str):
        url = f"http://{ubuntu_ip}:{SERVER_PORT}/set_proxy"
        try:
            resp = requests.post(url, json={"proxy_string": proxy}, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            self.root.after(0, self._on_apply_ok, data)
        except requests.exceptions.ConnectionError:
            self.root.after(0, self._on_apply_err,
                self._("log_conn_err", ubuntu_ip, SERVER_PORT))
        except requests.exceptions.Timeout:
            self.root.after(0, self._on_apply_err,
                self._("log_timeout", TIMEOUT))
        except requests.exceptions.HTTPError as e:
            detail = ""
            try: detail = e.response.json().get("detail", "")
            except Exception: pass
            self.root.after(0, self._on_apply_err,
                self._("log_http_err", e.response.status_code, detail))
        except Exception as e:
            self.root.after(0, self._on_apply_err, self._("log_unk_err", e))

    def _on_apply_ok(self, data: dict):
        self._log(self._("log_ok", data.get("proxy", "")), "ok")
        self._status(self._("st_ok"), self.GREEN)
        self._set_buttons(True)
        self._hist_upsert(self._pending_proxy, status="unknown")
        # Сразу показать, какой IP теперь раздаётся
        self._on_refresh_current()

    def _on_apply_err(self, msg: str):
        self._log(msg, "err")
        self._status(self._("st_err"), self.RED)
        self._set_buttons(True)

    # ── Отключить прокси ──────────────────────────────────────────────────────

    def _on_stop(self):
        ubuntu_ip = self.ip_var.get().strip()
        if not ubuntu_ip:
            self._log(self._("err_no_ip"), "err"); return

        self._set_buttons(False)
        self._status(self._("sending"), self.YELLOW)
        t = self.LANG[self.lang]
        self._log(f"→  POST http://{ubuntu_ip}:{SERVER_PORT}/stop_proxy", "info")
        threading.Thread(target=self._send_stop, args=(ubuntu_ip,), daemon=True).start()

    def _send_stop(self, ubuntu_ip: str):
        url = f"http://{ubuntu_ip}:{SERVER_PORT}/stop_proxy"
        try:
            resp = requests.post(url, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            self.root.after(0, self._on_stop_ok, data)
        except requests.exceptions.ConnectionError:
            self.root.after(0, self._on_stop_err,
                self._("log_conn_err", ubuntu_ip, SERVER_PORT))
        except requests.exceptions.Timeout:
            self.root.after(0, self._on_stop_err,
                self._("log_timeout", TIMEOUT))
        except requests.exceptions.HTTPError as e:
            detail = ""
            try: detail = e.response.json().get("detail", "")
            except Exception: pass
            self.root.after(0, self._on_stop_err,
                self._("log_http_err", e.response.status_code, detail))
        except Exception as e:
            self.root.after(0, self._on_stop_err, self._("log_unk_err", e))

    def _on_stop_ok(self, data: dict):
        self._log("✓ Прокси отключен, весь трафик идёт напрямую.", "ok")
        self._status("Отключено ✓", self.GREEN)
        self._set_buttons(True)
        self._on_refresh_current()

    def _on_stop_err(self, msg: str):
        self._log(msg, "err")
        self._status(self._("st_err"), self.RED)
        self._set_buttons(True)

    # ── Update (кнопка в шапке) ─────────────────────────────────────────────────
    # Сервер сам тянет актуальный server.py с GitHub, валидирует (компиляция +
    # import-smoke-test в отдельном подпроцессе — не трогая рабочий процесс),
    # применяет с бэкапом и перезапускает себя. Клиент только жмёт кнопку и
    # получает ответ ДО того, как сервис перезапустится (сервер откладывает
    # рестарт на ~1.5с в фоновом потоке специально ради этого).

    def _on_update(self):
        ubuntu_ip = self.ip_var.get().strip()
        if not ubuntu_ip:
            self._log(self._("err_no_ip"), "err"); return

        self._set_buttons(False)
        self._status(self._("update_st_checking"), self.YELLOW)
        self._log(self._("update_checking"), "info")
        self._log(self._("update_start", ubuntu_ip, SERVER_PORT), "info")
        threading.Thread(target=self._send_update, args=(ubuntu_ip,), daemon=True).start()

    def _send_update(self, ubuntu_ip: str):
        url = f"http://{ubuntu_ip}:{SERVER_PORT}/self_update"
        try:
            # Дольше обычного TIMEOUT: сервер сам ходит на GitHub + компилирует
            # + импортирует новую версию в подпроцессе, прежде чем ответить.
            resp = requests.post(url, timeout=max(TIMEOUT, 30))
            resp.raise_for_status()
            data = resp.json()
            self.root.after(0, self._on_update_ok, data, ubuntu_ip)
        except requests.exceptions.ConnectionError:
            self.root.after(0, self._on_update_err,
                self._("log_conn_err", ubuntu_ip, SERVER_PORT))
        except requests.exceptions.Timeout:
            self.root.after(0, self._on_update_err,
                self._("log_timeout", max(TIMEOUT, 30)))
        except requests.exceptions.HTTPError as e:
            detail = ""
            try: detail = e.response.json().get("detail", "")
            except Exception: pass
            self.root.after(0, self._on_update_err,
                self._("log_http_err", e.response.status_code, detail))
        except Exception as e:
            self.root.after(0, self._on_update_err, self._("log_unk_err", e))

    def _on_update_ok(self, data: dict, ubuntu_ip: str):
        status = data.get("status")
        if status == "uptodate":
            self._log(self._("update_uptodate"), "ok")
            self._status(self._("update_st_uptodate"), self.GREEN)
            self._set_buttons(True)
            return

        # status == "updated": сервис уже перезапускается на стороне сервера —
        # подождём и переспросим /status, чтобы честно подтвердить, что он
        # реально поднялся, а не просто отрапортовать и надеяться.
        self._log(self._("update_applied"), "ok")
        self._log(self._("update_verifying"), "info")
        threading.Thread(target=self._verify_update, args=(ubuntu_ip,), daemon=True).start()

    def _verify_update(self, ubuntu_ip: str, attempt: int = 1, max_attempts: int = 6):
        time.sleep(2)
        try:
            resp = requests.get(f"http://{ubuntu_ip}:{SERVER_PORT}/status", timeout=5)
            resp.raise_for_status()
            resp.json()  # сервис ответил валидным JSON — значит поднялся
            self.root.after(0, self._on_update_verified, True)
            return
        except Exception:
            pass
        if attempt < max_attempts:
            self._verify_update(ubuntu_ip, attempt + 1, max_attempts)
        else:
            self.root.after(0, self._on_update_verified, False)

    def _on_update_verified(self, healthy: bool):
        if healthy:
            self._log(self._("update_done"), "ok")
            self._status(self._("update_st_done"), self.GREEN)
        else:
            self._log(self._("update_done_slow"), "warn")
            self._status(self._("update_st_err"), self.YELLOW)
        self._set_buttons(True)
        self._on_refresh_current()

    def _on_update_err(self, msg: str):
        self._log(self._("update_err", msg), "err")
        self._status(self._("update_st_err"), self.RED)
        self._set_buttons(True)

    # ── Обновление самого клиента (баннер, тихая фоновая проверка) ─────────────
    # В отличие от кнопки Update выше (та обновляет СЕРВЕР на Ubuntu-коробке
    # по HTTP), это обновляет САМ Windows-клиент с GitHub. Собранный .exe не
    # может перезаписать сам себя — обновляем исходник client/client.py и
    # передаём эстафету update_client.bat (ждёт закрытия, пересобирает через
    # PyInstaller, перезапускает), а сами закрываемся сразу после запуска.

    def _check_client_update_bg(self):
        try:
            new_content = fetch_github_client_py()
            src_path = client_source_path()
            if not os.path.exists(src_path):
                return  # exe скопирован отдельно от репозитория — нечего сверять
            cur_content = open(src_path, "r", encoding="utf-8").read()
            if new_content != cur_content:
                self._client_update_content = new_content
                self.root.after(0, self._show_client_update_banner)
        except Exception as e:
            # Тихо — это фоновая необязательная проверка при старте, не мешаем
            # пользователю всплывающими ошибками из-за временной недоступности GitHub.
            print(self._("client_update_check_err", e))

    def _show_client_update_banner(self):
        # before=«Сейчас раздаётся»: и шапка, и эта карточка уже упакованы к
        # моменту, когда фоновая проверка находит обновление, так что просто
        # pack() добавил бы баннер В КОНЕЦ (ниже всех карточек) — нужно явно
        # воткнуть его между шапкой и первой карточкой.
        self.banner_client_update.pack(fill="x", padx=18, pady=(0, 12),
                                       before=self._card_cur_frame)

    def _on_client_update_apply(self):
        if not self._client_update_content:
            return
        self.banner_client_update.unbind("<Button-1>")
        self.banner_client_update.config(text=self._("client_update_applying"), cursor="")
        self._set_buttons(False)
        threading.Thread(target=self._apply_client_update, daemon=True).start()

    def _apply_client_update(self):
        content = self._client_update_content
        ok, err = validate_client_py(content)
        if not ok:
            self.root.after(0, self._on_client_update_err, self._("client_update_bad", err))
            return

        try:
            src_path = client_source_path()
            with open(src_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
        except Exception as e:
            self.root.after(0, self._on_client_update_err, str(e))
            return

        if getattr(sys, "frozen", False):
            bat_path = os.path.join(project_root_path(), "update_client.bat")
            if not os.path.exists(bat_path):
                self.root.after(0, self._on_client_update_err, self._("client_update_no_bat"))
                return
            try:
                # CREATE_NEW_CONSOLE: отдельное окно — видно, что пересборка
                # идёт, скрипт переживёт закрытие этого процесса (не привязан
                # к нашему stdout/stdin).
                subprocess.Popen([bat_path], cwd=project_root_path(),
                                 creationflags=subprocess.CREATE_NEW_CONSOLE)
            except Exception as e:
                self.root.after(0, self._on_client_update_err, str(e))
                return
        else:
            # Dev-режим: перезапускаем сам процесс, пересборка exe не нужна.
            subprocess.Popen([sys.executable, os.path.abspath(__file__)])

        self.root.after(0, self._shutdown_for_client_update)

    def _on_client_update_err(self, msg: str):
        self._log(msg, "err")
        self.banner_client_update.pack_forget()
        self._set_buttons(True)

    def _shutdown_for_client_update(self):
        # Даём update_client.bat/новому процессу шанс полностью стартовать
        # свою собственную обработку, прежде чем убить текущий — сама
        # пересборка/relaunch запущены уже отдельным процессом (see above),
        # это только закрывает GUI, чтобы освободить .exe от блокировки файла.
        try:
            self.root.destroy()
        finally:
            os._exit(0)

    # ── QUIC переключатель ────────────────────────────────────────────────────

    def _on_quic_toggle(self):
        ubuntu_ip = self.ip_var.get().strip()
        if not ubuntu_ip:
            self._log(self._("err_no_ip"), "err")
            self.quic_var.set(not self.quic_var.get())  # откатить чекбокс
            return

        block_quic = self.quic_var.get()
        self._set_buttons(False)
        self._status(self._("sending"), self.YELLOW)
        self._log(f"→  POST http://{ubuntu_ip}:{SERVER_PORT}/set_quic?block_quic={block_quic}", "info")
        threading.Thread(target=self._send_quic, args=(ubuntu_ip, block_quic), daemon=True).start()

    def _send_quic(self, ubuntu_ip: str, block_quic: bool):
        url = f"http://{ubuntu_ip}:{SERVER_PORT}/set_quic?block_quic={block_quic}"
        try:
            resp = requests.post(url, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            self.root.after(0, self._on_quic_ok, data, block_quic)
        except requests.exceptions.ConnectionError:
            self.root.after(0, self._on_quic_err,
                self._("log_conn_err", ubuntu_ip, SERVER_PORT), block_quic)
        except requests.exceptions.Timeout:
            self.root.after(0, self._on_quic_err,
                self._("log_timeout", TIMEOUT), block_quic)
        except requests.exceptions.HTTPError as e:
            detail = ""
            try: detail = e.response.json().get("detail", "")
            except Exception: pass
            self.root.after(0, self._on_quic_err,
                self._("log_http_err", e.response.status_code, detail), block_quic)
        except Exception as e:
            self.root.after(0, self._on_quic_err, self._("log_unk_err", e), block_quic)

    def _on_quic_ok(self, data: dict, block_quic: bool):
        msg = f"✓ QUIC: {'блокирован' if block_quic else 'разрешен'}"
        self._log(msg, "ok")
        self._status(msg, self.GREEN)
        self._set_buttons(True)

    def _on_quic_err(self, msg: str, block_quic: bool):
        self._log(msg, "err")
        self._status(self._("st_err"), self.RED)
        self._set_buttons(True)
        self.quic_var.set(not block_quic)  # откатить чекбокс если ошибка

    # ── Проверка прокси ───────────────────────────────────────────────────────

    def _on_check(self):
        proxy_str = self.proxy_var.get().strip()
        if not proxy_str:
            self._log(self._("err_no_proxy"), "err"); return

        p = parse_proxy(proxy_str)
        if not p:
            self._log(self._("err_format", proxy_str), "err")
            self._log(self._("err_format2"), "warn"); return

        self._set_buttons(False)
        self._status(self._("checking"), self.YELLOW)
        self._log(self._("chk_start", p["ip"], p["port"]), "info")
        threading.Thread(target=self._check_proxy, args=(p, proxy_str), daemon=True).start()

    def _check_proxy(self, p: dict, proxy_str: str = ""):
        ok, reason = socks5_ping(p["ip"], p["port"], p["user"], p["password"])
        if not ok:
            if proxy_str:
                ps = proxy_str
                self.root.after(0, lambda: self._hist_upsert(ps, status="fail"))
            self.root.after(0, self._on_check_fail, self._("chk_fail", reason))
            return

        u  = quote(p["user"],     safe="")
        pw = quote(p["password"], safe="")
        proxies = {
            "http":  f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
            "https": f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
        }

        data = None
        for url in GEO_URLS:
            try:
                resp = requests.get(url, proxies=proxies, timeout=TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                if data:
                    break
            except Exception:
                data = None

        if data is None or ("status" in data and data.get("status") != "success"):
            warn = ("⚠ Прокси работает (гео недоступно)"
                    if self.lang == "ru" else "⚠ Proxy works (geo unavailable)")
            if proxy_str:
                ps = proxy_str
                self.root.after(0, lambda: self._hist_upsert(ps, status="warn"))
            self.root.after(0, self._on_check_warn, warn)
            return

        ip      = data.get("query") or data.get("ip", "?")
        country = data.get("country", "?")
        code    = data.get("countryCode", "?")
        region  = data.get("regionName") or data.get("region", "?")
        city    = data.get("city", "?")
        isp     = data.get("isp") or data.get("org", "?")

        if code == "US":
            status = "ok"
            msg    = self._("chk_ok", ip, city, region, isp)
            cb     = self._on_check_ok
        elif ip not in ("?", None, ""):
            status = "warn"
            msg    = self._("chk_warn", ip, country, city)
            cb     = self._on_check_warn
        else:
            status = "warn"
            msg    = ("⚠ Прокси работает (гео недоступно)"
                      if self.lang == "ru" else "⚠ Proxy works (geo unavailable)")
            cb     = self._on_check_warn

        if proxy_str:
            ps, gd, st = proxy_str, data, status
            self.root.after(0, lambda: self._hist_upsert(ps, geo_data=gd, status=st))

        self.root.after(0, cb, msg)

    def _on_check_ok(self, msg: str):
        self._log(msg, "ok")
        self._status(self._("chk_st_ok"), self.GREEN)
        self._set_buttons(True)

    def _on_check_warn(self, msg: str):
        self._log(msg, "warn")
        self._status(self._("chk_st_warn"), self.YELLOW)
        self._set_buttons(True)

    def _on_check_fail(self, msg: str):
        self._log(msg, "err")
        self._status(self._("chk_st_fail"), self.RED)
        self._set_buttons(True)

    # ── Проверка UDP ASSOCIATE ─────────────────────────────────────────────────

    def _on_udp_check(self):
        proxy_str = self.proxy_var.get().strip()
        if not proxy_str:
            self._log(self._("err_no_proxy"), "err"); return

        p = parse_proxy(proxy_str)
        if not p:
            self._log(self._("err_format", proxy_str), "err")
            self._log(self._("err_format2"), "warn"); return

        self._set_buttons(False)
        self._status(self._("udp_checking"), self.YELLOW)
        self._log(self._("udp_start", p["ip"], p["port"]), "info")
        threading.Thread(target=self._udp_check, args=(p,), daemon=True).start()

    def _udp_check(self, p: dict):
        # Шаг 1: UDP ASSOCIATE вообще работает? (DNS/53 — простой, быстрый тест)
        ok, reason = socks5_udp_check(p["ip"], p["port"], p["user"], p["password"])
        if not ok:
            self.root.after(0, self._on_udp_fail, self._("udp_fail", reason))
            return
        self.root.after(0, self._log, self._("udp_assoc_ok"), "ok")
        self.root.after(0, self._log, self._("quic_start"), "info")

        # Шаг 2: а порт 443 — тот самый, которым реально пользуется QUIC с
        # устройств — не режется ли у прокси отдельно от DNS? Без этого шага
        # тест 1 сам по себе может дать ложноположительный "QUIC работает".
        qok, qreason = quic_udp_check(p["ip"], p["port"], p["user"], p["password"])
        if qok:
            self.root.after(0, self._on_udp_ok, self._("quic_ok"))
        else:
            self.root.after(0, self._on_quic_fail, self._("quic_fail", qreason))

    def _on_udp_ok(self, msg: str):
        self._log(msg, "ok")
        self._status(self._("udp_st_ok"), self.GREEN)
        self._set_buttons(True)

    def _on_udp_fail(self, msg: str):
        self._log(msg, "err")
        self._log(self._("udp_note"), "warn")
        self._status(self._("udp_st_fail"), self.RED)
        self._set_buttons(True)

    def _on_quic_fail(self, msg: str):
        """UDP ASSOCIATE в целом работает, но именно порт 443 (реальный порт
        QUIC) не отвечает — типично для прокси, которые режут UDP выборочно
        по порту. Отдельный статус, чтобы не путать с полным отказом UDP."""
        self._log(msg, "err")
        self._log(self._("quic_note"), "warn")
        self._status(self._("udp_st_quic_fail"), self.YELLOW)
        self._set_buttons(True)

    # ── Проверка чистоты (репутация + скорость) ────────────────────────────────

    def _on_clean_check(self):
        proxy_str = self.proxy_var.get().strip()
        if not proxy_str:
            self._log(self._("err_no_proxy"), "err"); return

        p = parse_proxy(proxy_str)
        if not p:
            self._log(self._("err_format", proxy_str), "err")
            self._log(self._("err_format2"), "warn"); return

        self._set_buttons(False)
        self._status(self._("clean_checking"), self.YELLOW)
        self._log(self._("clean_start", p["ip"], p["port"]), "info")
        threading.Thread(target=self._clean_check, args=(p, proxy_str), daemon=True).start()

    def _clean_check(self, p: dict, proxy_str: str = ""):
        # ── Шаг 1: прокси вообще живой? ──────────────────────────────────────
        ok, reason = socks5_ping(p["ip"], p["port"], p["user"], p["password"])
        if not ok:
            if proxy_str:
                ps = proxy_str
                self.root.after(0, lambda: self._hist_upsert(ps, status="fail"))
            self.root.after(0, self._on_clean_fail, self._("chk_fail", reason))
            return

        u  = quote(p["user"],     safe="")
        pw = quote(p["password"], safe="")
        proxies = {
            "http":  f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
            "https": f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
        }

        # ── Шаг 2: репутация через открытый источник (ip-api security-флаги) ──
        data = None
        try:
            resp = requests.get(CLEAN_URL, proxies=proxies, timeout=TIMEOUT)
            resp.raise_for_status()
            j = resp.json()
            if j.get("status") == "success":
                data = j
        except Exception:
            data = None

        # ── Шаг 3: замер скорости (всегда, даже если репутация недоступна) ───
        mbps, kbps, latency = measure_speed(proxies)

        self.root.after(0, self._on_clean_result, data, proxy_str,
                        mbps, kbps, latency)

    def _on_clean_result(self, data, proxy_str, mbps, kbps, latency):
        # ── Вердикт по флагам ────────────────────────────────────────────────
        if data is None:
            self._log(self._("clean_geo_na"), "warn")
            verdict_status = "warn"
            status_txt, status_col = self._("clean_st_warn"), self.YELLOW
        else:
            ip      = data.get("query", "?")
            country = data.get("country", "?")
            city    = data.get("city", "?")
            isp     = data.get("isp") or data.get("org", "?")
            is_proxy   = bool(data.get("proxy"))
            is_hosting = bool(data.get("hosting"))
            is_mobile  = bool(data.get("mobile"))
            rdns       = data.get("reverse", "")

            self._log(self._("clean_geo", ip, country, city, isp), "info")

            if is_proxy:
                self._log(self._("clean_dirty"), "err")
                verdict_status = "fail"
                status_txt, status_col = self._("clean_st_fail"), self.RED
            elif is_hosting:
                self._log(self._("clean_host"), "warn")
                verdict_status = "warn"
                status_txt, status_col = self._("clean_st_warn"), self.YELLOW
            else:
                self._log(self._("clean_ok"), "ok")
                verdict_status = "ok"
                status_txt, status_col = self._("clean_st_ok"), self.GREEN

            self._log(self._("clean_flags", is_proxy, is_hosting, is_mobile),
                      "err" if (is_proxy or is_hosting) else "ok")
            if rdns:
                self._log(self._("clean_rdns", rdns), "info")

        # ── Скорость ─────────────────────────────────────────────────────────
        speed_str = None
        if mbps is not None:
            speed_str = f"{mbps:.1f} Mbps ({kbps:.0f} KB/s)"
            lat = latency if latency is not None else "?"
            self._log(self._("clean_speed", speed_str, lat),
                      "ok" if mbps >= 2 else "warn")
        else:
            self._log(self._("clean_speed_na"), "err")

        self._status(status_txt, status_col)
        self._set_buttons(True)

        # ── Сохранить в историю (гео + статус + скорость) ────────────────────
        if proxy_str:
            extra = {}
            if speed_str:
                extra["speed"] = speed_str
            self._hist_upsert(proxy_str, geo_data=data,
                              status=verdict_status, extra=extra or None)

    def _on_clean_fail(self, msg: str):
        self._log(msg, "err")
        self._status(self._("chk_st_fail"), self.RED)
        self._set_buttons(True)

    # ── Проверка сервера ──────────────────────────────────────────────────────

    def _on_server_check(self):
        ubuntu_ip = self.ip_var.get().strip()
        if not ubuntu_ip:
            self._log(self._("err_no_ip"), "err")
            return
        self._remember_ip(ubuntu_ip)
        self._set_buttons(False)
        self._status(self._("srv_checking"), self.YELLOW)
        self._log(f"→  GET http://{ubuntu_ip}:{SERVER_PORT}/status", "info")
        threading.Thread(target=self._server_check, args=(ubuntu_ip,), daemon=True).start()

    def _server_check(self, ubuntu_ip: str):
        url = f"http://{ubuntu_ip}:{SERVER_PORT}/status"
        try:
            resp = requests.get(url, timeout=TIMEOUT)
            resp.raise_for_status()
            self.root.after(0, self._on_server_result, resp.json())
        except requests.exceptions.ConnectionError:
            self.root.after(0, self._on_server_down, ubuntu_ip, "connection refused")
        except requests.exceptions.Timeout:
            self.root.after(0, self._on_server_down, ubuntu_ip, f"timeout {TIMEOUT}s")
        except Exception as e:
            self.root.after(0, self._on_server_down, ubuntu_ip, str(e))

    def _on_server_result(self, data: dict):
        svcs = [
            ("sing_box", self._("srv_desc_sb")),
            ("dnsmasq",  self._("srv_desc_dns")),
        ]
        all_ok = (
            all(data.get(s) == "active" for s, _ in svcs) and
            data.get("iptables") == "ok"
        )
        header_key = "srv_up" if all_ok else "srv_warn"
        header_tag = "ok"     if all_ok else "warn"
        self._log(self._(header_key), header_tag)
        for svc, label in svcs:
            state = data.get(svc, "unknown")
            ok    = state == "active"
            self._log(f"   {'●' if ok else '○'}  {svc:<12} {state:<10}  {label}",
                      "ok" if ok else "warn")
        ipt_ok  = data.get("iptables") == "ok"
        ipt_lbl = self._("srv_ipt_ok") if ipt_ok else self._("srv_ipt_err")
        self._log(f"   {'●' if ipt_ok else '○'}  {'iptables':<12} {ipt_lbl}",
                  "ok" if ipt_ok else "err")
        proxy = data.get("proxy")
        self._log(
            self._("srv_proxy", proxy) if proxy else self._("srv_no_proxy"),
            "info" if proxy else "warn",
        )
        self._status(
            self._("srv_st_ok") if all_ok else self._("srv_st_warn"),
            self.GREEN if all_ok else self.YELLOW,
        )
        self._set_buttons(True)
        # Обновить баннер «сейчас раздаётся»
        if proxy:
            self._on_refresh_current()

    def _on_server_down(self, ubuntu_ip: str, reason: str):
        self._log(self._("srv_down", ubuntu_ip, SERVER_PORT), "err")
        self._log(f"   {reason}", "err")
        self._log(self._("srv_hint"), "warn")
        self._status(self._("srv_st_down"), self.RED)
        self._set_buttons(True)

    # ── Тест канала: реальная пропускная активного прокси (через сервер) ───────

    def _on_health(self):
        ubuntu_ip = self.ip_var.get().strip()
        if not ubuntu_ip:
            self._log(self._("err_no_ip"), "err"); return
        self._set_buttons(False)
        self._status(self._("health_checking"), self.YELLOW)
        self._log(self._("health_start"), "info")
        threading.Thread(target=self._health_worker, args=(ubuntu_ip,), daemon=True).start()

    def _health_worker(self, ubuntu_ip: str):
        try:
            # серверный тест занимает до ~25с — даём запас
            r = requests.get(f"http://{ubuntu_ip}:{SERVER_PORT}/proxy_health", timeout=45)
            r.raise_for_status()
            self.root.after(0, self._on_health_result, r.json())
        except requests.exceptions.ConnectionError:
            self.root.after(0, self._on_health_fail,
                            self._("log_conn_err", ubuntu_ip, SERVER_PORT))
        except requests.exceptions.Timeout:
            self.root.after(0, self._on_health_fail, self._("log_timeout", 45))
        except Exception as e:
            self.root.after(0, self._on_health_fail, str(e))

    def _on_health_result(self, d: dict):
        if not d.get("ok") and "got_bytes" not in d:
            if d.get("error_code") == "no_proxy":
                self._log(self._("health_noproxy"), "warn")
                self._status(self._("health_st_fail"), self.YELLOW)
            else:
                self._log(self._("health_err", self._errmsg(d)), "err")
                self._status(self._("health_st_fail"), self.RED)
            self._set_buttons(True)
            return

        got_kb  = round(d.get("got_bytes", 0) / 1024)
        elapsed = d.get("elapsed", "?")
        if d.get("ok"):
            self._log(self._("health_ok", got_kb, elapsed, d.get("kbps", "?")), "ok")
            self._status(self._("health_st_ok"), self.GREEN)
        else:
            self._log(self._("health_stall", got_kb, elapsed), "err")
            self._status(self._("health_st_fail"), self.RED)
        self._set_buttons(True)

    def _on_health_fail(self, msg: str):
        self._log(self._("health_err", msg), "err")
        self._status(self._("health_st_fail"), self.RED)
        self._set_buttons(True)

    # ── Сейчас раздаётся: exit-IP активного прокси + гео ───────────────────────

    def _set_current(self, text: str, color: str = None, mark: bool = True):
        self._cur_set = mark
        self.lbl_cur_val.config(text=text, fg=color or self.MUTED)
        self.lbl_cur_dot.config(fg=color or self.MUTED)
        self.btn_cur.set_state("normal")

    def _on_refresh_current(self):
        ubuntu_ip = self.ip_var.get().strip()
        if not ubuntu_ip:
            self._set_current(self._("cur_err", self._("err_no_ip")), self.RED)
            return
        self.btn_cur.set_state("disabled")
        self._set_current(self._("cur_loading"), self.YELLOW)
        threading.Thread(target=self._refresh_current_worker,
                         args=(ubuntu_ip,), daemon=True).start()

    def _refresh_current_worker(self, ubuntu_ip: str):
        # 1) Авторитетный путь: сервер сам ходит через активный прокси
        try:
            r = requests.get(f"http://{ubuntu_ip}:{SERVER_PORT}/current_ip",
                             timeout=25)
            if r.status_code == 200:
                d = r.json()
                if d.get("ok"):
                    self.root.after(0, self._show_current,
                                    d.get("exit_ip"), d.get("countryCode"),
                                    d.get("country"), d.get("city"), d.get("isp"))
                    return
                # Сервер ответил, но прокси не задан / гео не получено
                if d.get("error_code") == "no_proxy":
                    self.root.after(0, self._set_current,
                                    self._("cur_no_proxy"), self.YELLOW)
                    return
                # иначе пробуем клиентский fallback (вдруг временный сбой гео)
        except Exception:
            pass
        # 2) Fallback: старый сервер без /current_ip → берём ip:port из /status,
        #    учётку ищем в текущем поле или в истории, гео меряем сами.
        self._fallback_current(ubuntu_ip)

    def _fallback_current(self, ubuntu_ip: str):
        try:
            r = requests.get(f"http://{ubuntu_ip}:{SERVER_PORT}/status",
                             timeout=TIMEOUT)
            r.raise_for_status()
            status_data = r.json()
            # Обновляем состояние QUIC чекбокса
            quic_blocked = status_data.get("quic_blocked", False)
            self.root.after(0, lambda: self.quic_var.set(quic_blocked))
            active = status_data.get("proxy")
        except Exception as e:
            self.root.after(0, self._set_current, self._("cur_err", str(e)), self.RED)
            return
        if not active:
            self.root.after(0, self._set_current, self._("cur_no_proxy"), self.YELLOW)
            return

        full = self._creds_for(active)
        p = parse_proxy(full) if full else None
        if not p:
            self.root.after(0, self._set_current,
                            self._("cur_partial", active), self.YELLOW)
            return

        u  = quote(p["user"],     safe="")
        pw = quote(p["password"], safe="")
        proxies = {
            "http":  f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
            "https": f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
        }
        data = None
        for url in GEO_URLS:
            try:
                resp = requests.get(url, proxies=proxies, timeout=TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                if data:
                    break
            except Exception:
                data = None
        if not data or ("status" in data and data.get("status") != "success"):
            self.root.after(0, self._set_current,
                            self._("cur_partial", active), self.YELLOW)
            return
        self.root.after(0, self._show_current,
                        data.get("query") or data.get("ip"),
                        data.get("countryCode"), data.get("country"),
                        data.get("city"), data.get("isp") or data.get("org"))

    def _show_current(self, ip, code, country, city, isp):
        flag = self._flag(code or "")
        geo  = f"{flag} {code or '?'}, {city or country or '?'}".strip()
        self._set_current(self._("cur_fmt", ip or "?", geo, isp or "?"), self.GREEN)

    def _creds_for(self, display: str):
        """Ищет полную строку прокси (с учёткой) для активного ip:port —
        сначала в текущем поле, затем в истории."""
        cur = self.proxy_var.get().strip()
        p = parse_proxy(cur)
        if p and f"{p['ip']}:{p['port']}" == display:
            return cur
        for e in self.history:
            if e.get("display") == display:
                return e.get("proxy")
        return None

    # ── История ───────────────────────────────────────────────────────────────

    def _load_history(self) -> list:
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _save_history(self):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ── Конфиг клиента (последний использованный IP сервера и т.п.) ────────────

    def _load_config(self) -> dict:
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_config(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _remember_ip(self, ip: str):
        """Запомнить последний использованный IP сервера — чтобы не хардкодить
        его в коде и не заставлять вводить заново при следующем запуске."""
        if ip and self.config.get("server_ip") != ip:
            self.config["server_ip"] = ip
            self._save_config()

    @staticmethod
    def _flag(code: str) -> str:
        if not code or len(code) != 2:
            return ""
        try:
            return (chr(0x1F1E6 + ord(code[0].upper()) - 65) +
                    chr(0x1F1E6 + ord(code[1].upper()) - 65))
        except Exception:
            return ""

    def _hist_upsert(self, proxy_str: str, geo_data: dict = None,
                     status: str = "unknown", extra: dict = None):
        """Add or update a history entry keyed by IP:port."""
        if not proxy_str:
            return
        p = parse_proxy(proxy_str)
        if not p:
            return
        display = f"{p['ip']}:{p['port']}"
        now = datetime.now().strftime("%d.%m %H:%M")

        for entry in self.history:
            if entry.get("display") == display:
                entry["proxy"]     = proxy_str
                entry["last_used"] = now
                if status != "unknown":
                    entry["status"] = status
                if geo_data:
                    entry["country"]      = geo_data.get("country", "?")
                    entry["country_code"] = geo_data.get("countryCode", "?")
                    entry["city"]         = geo_data.get("city", "?")
                    entry["isp"]          = (geo_data.get("isp") or
                                             geo_data.get("org", "?"))
                if extra:
                    entry.update(extra)
                self._save_history()
                self.root.after(0, self._refresh_hist_table)
                return

        entry = {
            "proxy":        proxy_str,
            "display":      display,
            "country":      geo_data.get("country", "?")      if geo_data else "?",
            "country_code": geo_data.get("countryCode", "?")  if geo_data else "?",
            "city":         geo_data.get("city", "?")         if geo_data else "?",
            "isp":          (geo_data.get("isp") or geo_data.get("org", "?")) if geo_data else "?",
            "last_used":    now,
            "status":       status,
        }
        if extra:
            entry.update(extra)
        self.history.insert(0, entry)
        if len(self.history) > 50:
            self.history = self.history[:50]
        self._save_history()
        self.root.after(0, self._refresh_hist_table)

    def _refresh_hist_table(self):
        for row in self.hist_tree.get_children():
            self.hist_tree.delete(row)
        for i, e in enumerate(self.history):
            code     = e.get("country_code", "")
            flag     = self._flag(code)
            city     = e.get("city", "?")
            geo_str  = f"{flag} {code} / {city}" if code and code != "?" else "?"
            isp      = e.get("isp", "?")
            isp_disp = (isp[:22] + "…") if len(isp) > 23 else isp
            date     = e.get("last_used", "?")
            st       = e.get("status", "unknown")
            icon     = {"ok": "✓", "warn": "⚠", "fail": "✗"}.get(st, "?")
            tag      = st if st in ("ok", "warn", "fail") else "unknown"
            self.hist_tree.insert("", "end", iid=str(i),
                values=(e.get("display", "?"), geo_str, isp_disp, date, icon),
                tags=(tag,))

    def _hist_selected_idx(self):
        sel = self.hist_tree.selection()
        if not sel:
            self._log(self._("hist_nosel"), "warn")
            return None
        return int(sel[0])

    def _hist_load(self):
        idx = self._hist_selected_idx()
        if idx is None:
            return
        entry = self.history[idx]
        self.proxy_var.set(entry["proxy"])
        self.notebook.select(0)
        self._log(self._("hist_loaded", entry["display"]), "info")

    def _hist_check(self):
        idx = self._hist_selected_idx()
        if idx is None:
            return
        entry = self.history[idx]
        p = parse_proxy(entry["proxy"])
        if not p:
            return
        self._set_buttons(False)
        self._status(self._("hist_checking"), self.YELLOW)
        self._log(self._("chk_start", p["ip"], p["port"]), "info")
        threading.Thread(
            target=self._check_proxy,
            args=(p, entry["proxy"]),
            daemon=True,
        ).start()

    def _hist_delete(self):
        idx = self._hist_selected_idx()
        if idx is None:
            return
        del self.history[idx]
        self._save_history()
        self._refresh_hist_table()


if __name__ == "__main__":
    root = tk.Tk()
    try:
        bundle_dir = getattr(sys, "_MEIPASS", APP_DIR) if getattr(sys, "frozen", False) else APP_DIR
        icon_path = os.path.join(bundle_dir, "mag.ico")
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
    except Exception:
        pass
    App(root)
    root.mainloop()
