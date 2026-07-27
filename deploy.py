#!/usr/bin/env python3
"""
JackalRouter — удалённый деплой с клиента (одной командой).

Запуск:   python deploy.py
          (или двойной клик по deploy.bat на Windows)

Что делает:
  1. Спрашивает IP сервера и SSH-логин, проверяет связь.
  2. Кладёт на сервер SSH-ключ — пароль спрашивается один раз за весь деплой.
  3. Показывает, что уже настроено от прошлых запусков (деплой мог упасть
     на середине), и спрашивает, ставить ли поверх.
  4. Отключает пароль sudo на сервере (NOPASSWD).
  5. Предлагает выбрать вид деплоя (UBUNTU+ROUTER / RASPBERRY+ROUTER /
     RASPBERRY+WIFI / UBUNTU+WIFI).
  6. Копирует файлы по scp (со сжатием и повторами — Wi-Fi часто рвётся)
     и запускает деплой на сервере.

Требуется: клиент OpenSSH (ssh/scp). На Windows 10/11 он встроен, на Linux/Mac есть.
"""

import os
import sys
import shutil
import subprocess

# ── Вывод в UTF-8 (иначе рамки/кириллица падают в cp1251 при пайпе/старой cmd) ─
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
if os.name == "nt":
    os.system("")                        # включить ANSI-escape на Win10+
    os.system("chcp 65001 >nul 2>&1")    # консоль в UTF-8, чтобы рендерились рамки

R = "\033[0;31m"; G = "\033[0;32m"; Y = "\033[0;33m"
B = "\033[0;34m"; C = "\033[0;36m"; W = "\033[1;37m"; N = "\033[0m"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REMOTE_DIR = "jackalrouter-deploy"           # каталог на сервере (в домашней папке)
SUDOERS    = "/etc/sudoers.d/jackal-nopasswd"
# Отдельный ключ только под деплой — общий id_ed25519 пользователя не трогаем
KEY_PATH   = os.path.join(os.path.expanduser("~"), ".ssh", "jackalrouter_deploy")

# ServerAlive* — чтобы соединение не умирало молча на нестабильном Wi-Fi:
# ssh сам заметит пропажу канала и переиспользует TCP, а не будет ждать таймаута.
SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"]

# Виды деплоя: ключ → (человекочитаемое имя, файл, описание)
DEPLOYS = {
    "1": ("UBUNTU + ROUTER",     "deploy.sh",
          "Ubuntu-ноутбук: интернет по Wi-Fi, раздача по кабелю через тех. роутер"),
    "2": ("RASPBERRY + ROUTER",  "deploy-rpi5.sh",
          "Raspberry Pi: интернет по Wi-Fi, раздача по кабелю через тех. роутер"),
    "3": ("RASPBERRY + WIFI",    "deploy-rpi5-ap.sh",
          "Raspberry Pi = свой Wi-Fi роутер: интернет по кабелю, раздача по Wi-Fi"),
    "4": ("UBUNTU + WIFI",       "deploy-ubuntu-wifi-ap.sh",
          "Ubuntu = свой Wi-Fi роутер (нужны 2 Wi-Fi адаптера): интернет по Wi-Fi, раздача своей Wi-Fi сетью"),
}

# Файлы/папки, которые нужны на сервере для запуска деплоя
PAYLOAD = ["deploy.sh", "deploy-rpi5.sh", "deploy-rpi5-ap.sh",
           "deploy-ubuntu-wifi-ap.sh", "server"]


def ok(m):   print(f"{G}  ✓ {m}{N}")
def warn(m): print(f"{Y}  ⚠ {m}{N}")
def err(m):  print(f"{R}  ✗ {m}{N}")
def info(m): print(f"{C}  → {m}{N}")


def die(msg, hint=""):
    print(f"\n{R}═══════════════════════════════════════════════{N}")
    print(f"{R}  ОШИБКА: {msg}{N}")
    print(f"{R}═══════════════════════════════════════════════{N}")
    if hint:
        print(f"{Y}  Что делать: {hint}{N}")
    sys.exit(1)


def header():
    print(f"{B}╔══════════════════════════════════════════════╗{N}")
    print(f"{B}║{W}    JackalRouter — Удалённый деплой          {B}║{N}")
    print(f"{B}║{C}  Заливает и запускает всё на сервере сам     {B}║{N}")
    print(f"{B}╚══════════════════════════════════════════════╝{N}\n")


def check_tools():
    for t in ("ssh", "scp", "ssh-keygen"):
        if shutil.which(t) is None:
            die(f"Не найден '{t}' (клиент OpenSSH).",
                "Windows 10/11: Параметры → Приложения → Доп. компоненты → "
                "'Клиент OpenSSH'. Linux/Mac: установите openssh-client.")
    ok("SSH/SCP на месте")


def run_ssh(user, host, remote_cmd, tty=False, check=True, quiet=False):
    """Выполнить команду на сервере. tty=True — для интерактива (пароль sudo,
    вопросы деплоя): подключает живой терминал."""
    cmd = ["ssh"] + SSH_OPTS + (["-t"] if tty else []) + [f"{user}@{host}", remote_cmd]
    kwargs = {}
    if quiet:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    r = subprocess.run(cmd, **kwargs)
    if check and r.returncode != 0:
        return False
    return r.returncode == 0


def ssh_capture(user, host, remote_cmd):
    """Выполнить команду на сервере и вернуть её stdout (пусто при ошибке)."""
    cmd = ["ssh"] + SSH_OPTS + [f"{user}@{host}", remote_cmd]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def setup_ssh_key(user, host):
    """Положить свой SSH-ключ на сервер, чтобы пароль спрашивался ОДИН раз
    за весь деплой, а не на каждом шаге (связь, sudo, scp, запуск).

    Используем отдельный ключ, а не общий id_ed25519 — чтобы не трогать то,
    чем пользователь пользуется для других серверов."""
    ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    if not os.path.exists(KEY_PATH):
        info("Создаю SSH-ключ для деплоя…")
        r = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", KEY_PATH,
             "-C", "jackalrouter-deploy"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0 or not os.path.exists(KEY_PATH):
            warn("Не удалось создать SSH-ключ — продолжу с паролем.")
            return False
        ok("SSH-ключ создан")

    try:
        with open(KEY_PATH + ".pub", "r", encoding="utf-8") as f:
            pub = f.read().strip()
    except Exception:
        warn("Не читается публичный ключ — продолжу с паролем.")
        return False

    # Уже установлен? Тогда пароль вообще не понадобится.
    probe = ["ssh"] + SSH_OPTS + ["-i", KEY_PATH, "-o", "BatchMode=yes",
                                  f"{user}@{host}", "true"]
    if subprocess.run(probe, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
        SSH_OPTS.extend(["-i", KEY_PATH])
        ok("Вход по ключу уже настроен — пароль не потребуется")
        return True

    info("Устанавливаю ключ на сервер (последний раз спросит пароль)…")
    # grep -qxF делает шаг идемпотентным: повторный деплой не плодит дубли ключа.
    install = (
        "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
        f"grep -qxF '{pub}' ~/.ssh/authorized_keys || echo '{pub}' >> ~/.ssh/authorized_keys; "
        "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"
    )
    if not run_ssh(user, host, install, tty=True):
        warn("Не удалось положить ключ — продолжу с паролем.")
        return False

    if subprocess.run(probe, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
        SSH_OPTS.extend(["-i", KEY_PATH])
        ok("Ключ установлен — дальше без пароля")
        return True

    warn("Ключ положен, но вход по нему не сработал — продолжу с паролем.")
    return False


# Что проверяем на сервере перед установкой: ключ → человекочитаемое имя
STATE_CHECKS = [
    ("singbox",  "sing-box установлен"),
    ("venv",     "Python-окружение /opt/jackalrouter/venv"),
    ("deps",     "Python-зависимости (fastapi/uvicorn/pydantic)"),
    ("api",      "Сервис jackalrouter"),
    ("sb",       "Сервис sing-box"),
    ("dnsmasq",  "Сервис dnsmasq (DHCP)"),
    ("ap",       "Профиль Wi-Fi точки доступа (jackal-ap)"),
    ("dhcpconf", "Конфиг DHCP (jackal-dhcp.conf)"),
]


def probe_state(user, host):
    """Снять состояние сервера: что от прошлых запусков уже настроено.

    Нужно, потому что деплой мог упасть на середине (например, на установке
    Python-пакетов) — тогда часть системы уже поднята, и пользователь должен
    понимать, во что он входит, а не гадать."""
    script = (
        'echo "py=$(python3 -c \'import sys;print("%d.%d"%sys.version_info[:2])\' 2>/dev/null || echo ?)";'
        'echo "singbox=$(test -x /usr/local/bin/sing-box && echo yes || echo no)";'
        'echo "venv=$(test -d /opt/jackalrouter/venv && echo yes || echo no)";'
        'echo "deps=$(/opt/jackalrouter/venv/bin/python3 -c "import fastapi,uvicorn,pydantic" 2>/dev/null && echo yes || echo no)";'
        # head -1: is-active для неактивного юнита печатает "inactive" И возвращает
        # ненулевой код — без этого "|| echo no" дописал бы второе слово.
        'echo "api=$(systemctl is-active jackalrouter 2>/dev/null | head -1)";'
        'echo "sb=$(systemctl is-active sing-box 2>/dev/null | head -1)";'
        'echo "dnsmasq=$(systemctl is-active dnsmasq 2>/dev/null | head -1)";'
        'echo "ap=$(nmcli -t -f NAME con show 2>/dev/null | grep -qx jackal-ap && echo yes || echo no)";'
        'echo "dhcpconf=$(test -f /etc/dnsmasq.d/jackal-dhcp.conf && echo yes || echo no)"'
    )
    out = ssh_capture(user, host, script)
    state = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            # юнита может не быть вовсе — systemctl тогда молчит, считаем "no"
            state[k.strip()] = v.strip() or "no"
    return state


def report_state(state):
    """Показать состояние и вернуть True, если прошлая установка уже была."""
    if not state:
        warn("Не удалось снять состояние сервера — продолжаю как есть.")
        return False

    good = {"yes", "active", "enabled"}
    present = [(k, t) for k, t in STATE_CHECKS if state.get(k, "no") in good]

    py = state.get("py", "?")
    print()
    info(f"Python на сервере: {W}{py}{N}")

    if not present:
        ok("Сервер чистый — ставим с нуля")
        return False

    print(f"{Y}  ⚠ На сервере уже есть следы прошлой установки:{N}")
    for k, title in STATE_CHECKS:
        val = state.get(k, "no")
        mark = f"{G}✓{N}" if val in good else f"{R}—{N}"
        print(f"      {mark} {title}: {C}{val}{N}")

    fully_up = state.get("api") == "active" and state.get("deps") == "yes"
    if fully_up:
        print(f"{G}  Похоже, JackalRouter уже установлен и работает.{N}")
    else:
        print(f"{Y}  Установка выглядит НЕзавершённой — прошлый запуск, видимо, упал.{N}")
    print(f"{C}  Повторный деплой безопасен: скрипты перезаписывают конфиги и правила заново.{N}")
    return True


def run_scp(user, host, attempts=3):
    """Скопировать PAYLOAD в ~/REMOTE_DIR на сервере (относительные пути —
    иначе Windows-путь 'C:\\...' scp примет за host:path).

    Коробка обычно сидит на Wi-Fi, и передача нескольких мегабайт там нередко
    рвётся на полпути. Поэтому: сжатие (-C) и несколько попыток — обрыв на
    середине больше не убивает весь деплой."""
    os.chdir(SCRIPT_DIR)
    missing = [p for p in PAYLOAD if not os.path.exists(p)]
    if missing:
        die(f"Рядом с deploy.py нет: {', '.join(missing)}",
            "Запускайте deploy.py из папки проекта (где лежат deploy.sh и server/).")
    cmd = ["scp"] + SSH_OPTS + ["-C", "-r"] + PAYLOAD + [f"{user}@{host}:{REMOTE_DIR}/"]
    for i in range(1, attempts + 1):
        if subprocess.run(cmd).returncode == 0:
            return True
        if i < attempts:
            warn(f"Передача оборвалась (попытка {i} из {attempts}) — повторяю…")
    return False


def main():
    header()

    # ── 0. Инструменты ────────────────────────────────────────────────────────
    check_tools()

    # ── 1. Параметры подключения ──────────────────────────────────────────────
    host = ""
    if len(sys.argv) > 1:
        host = sys.argv[1].strip()
    while not host:
        host = input(f"{W}  IP сервера (например 192.168.1.96): {N}").strip()
    user = input(f"{W}  SSH-логин [family]: {N}").strip() or "family"

    print()
    info(f"Проверяю связь с {user}@{host} …  (если попросит пароль — введите)")
    if not run_ssh(user, host, "true", quiet=True):
        die(f"Нет SSH-связи с {user}@{host}.",
            "Проверьте: сервер включён, IP верный, SSH включён (sudo systemctl "
            "enable --now ssh), логин правильный. Если просит пароль — введите его.")
    ok(f"Связь есть: {user}@{host}")

    # ── 2. SSH-ключ (чтобы пароль спросили один раз за весь деплой) ───────────
    print()
    setup_ssh_key(user, host)

    # ── 3. Что уже настроено от прошлых запусков ──────────────────────────────
    had_install = report_state(probe_state(user, host))
    if had_install:
        ans = input(f"{W}  Продолжить и переустановить поверх? [Enter=да / n=выход]: {N}").strip()
        if ans.lower().startswith("n"):
            print(f"{Y}  Отменено пользователем.{N}")
            sys.exit(0)

    # ── 4. Отключение пароля sudo (NOPASSWD) ──────────────────────────────────
    print()
    info("Отключаю запрос пароля sudo (NOPASSWD) — возможно, спросит пароль один раз…")
    sudo_setup = (
        f'echo "{user} ALL=(ALL) NOPASSWD:ALL" | sudo tee {SUDOERS} >/dev/null '
        f'&& sudo chmod 440 {SUDOERS} '
        f'&& sudo visudo -cf {SUDOERS}'
    )
    if not run_ssh(user, host, sudo_setup, tty=True):
        die("Не удалось настроить NOPASSWD sudo.",
            "Убедитесь, что пользователь в группе sudo и пароль верный.")
    # проверка: sudo теперь без пароля
    if not run_ssh(user, host, "sudo -n true", quiet=True):
        warn("sudo всё ещё просит пароль — деплой может переспросить его.")
    else:
        ok("sudo без пароля настроен")

    # ── 5. Выбор вида деплоя ───────────────────────────────────────────────────
    print()
    print(f"{W}  Выберите вид деплоя:{N}")
    for k, (name, _f, desc) in DEPLOYS.items():
        print(f"    {G}{k}{N}) {W}{name}{N}")
        print(f"       {C}{desc}{N}")
    choice = ""
    while choice not in DEPLOYS:
        choice = input(f"{W}  Номер [1-{len(DEPLOYS)}]: {N}").strip()
    name, script, _desc = DEPLOYS[choice]
    ok(f"Выбрано: {name}  ({script})")

    # ── 6. Копирование файлов ─────────────────────────────────────────────────
    print()
    info(f"Копирую файлы в ~/{REMOTE_DIR} на сервере…")
    run_ssh(user, host, f"mkdir -p ~/{REMOTE_DIR}", quiet=True)
    if not run_scp(user, host):
        # Точный диагноз вместо списка догадок: раз соединение уже работало выше,
        # проверяем, отвечает ли машина сейчас, и говорим ровно то, что выяснили.
        still_up = run_ssh(user, host, "true", quiet=True)
        if still_up:
            die("Файлы копировались, но передача обрывалась на середине.",
                f"Машина {host} отвечает, значит дело не в доступе и не в месте на диске — "
                "рвётся сам канал (обычно нестабильный Wi-Fi у коробки). "
                "Проще всего обойти это: скопировать папку проекта на коробку любым способом "
                "(флешка, git clone) и запустить установку прямо на ней:  sudo bash <нужный скрипт>")
        else:
            die(f"Связь с {host} пропала во время копирования.",
                "Машина сейчас не отвечает. Проверьте, что она включена, не ушла в сон "
                "и не сменила IP (Wi-Fi мог переподключиться и получить другой адрес). "
                "Уточнить текущий адрес:  на коробке выполните  ip -4 addr")
    ok("Файлы скопированы")

    # нормализуем переносы строк (если git выгрузил .sh как CRLF — bash сломается)
    normalize = (
        f"cd ~/{REMOTE_DIR} && "
        f"sed -i 's/\\r$//' *.sh server/*.py server/*.service 2>/dev/null; true"
    )
    run_ssh(user, host, normalize, quiet=True)

    # ── 7. Запуск деплоя ───────────────────────────────────────────────────────
    print()
    print(f"{B}══════════════════════════════════════════════{N}")
    print(f"{W}  Запускаю {name} на сервере…{N}")
    print(f"{B}══════════════════════════════════════════════{N}\n")
    run_cmd = f"cd ~/{REMOTE_DIR} && sudo bash {script}"
    success = run_ssh(user, host, run_cmd, tty=True)

    print()
    if success:
        print(f"{G}╔══════════════════════════════════════════════╗{N}")
        print(f"{G}║{W}        ДЕПЛОЙ ЗАВЕРШЁН                      {G}║{N}")
        print(f"{G}╚══════════════════════════════════════════════╝{N}")
        print(f"{W}  Дальше: откройте клиент JackalRouter, укажите IP {C}{host}{N}")
        print(f"{W}  (или {C}10.0.0.1{N}{W} со стороны Wi-Fi у Pi-AP), вставьте прокси → Route.{N}")
    else:
        err("Деплой завершился с ошибкой — смотрите вывод выше.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}  Прервано пользователем.{N}")
        sys.exit(130)
