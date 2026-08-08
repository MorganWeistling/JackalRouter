#!/usr/bin/env python3
"""
JackalRouter — обновление уже развёрнутой коробки с GitHub (без полного
передеплоя).

Запуск:   python update.py
          (или двойной клик по update.bat на Windows)

Что делает:
  1. Спрашивает IP коробки и SSH-логин, проверяет связь.
  2. Кладёт SSH-ключ (как deploy.py) — пароль спросит один раз.
  3. Спрашивает, какой вид деплоя стоит на коробке (для справки и чтобы
     обновить сохранённую там копию скрипта — САМ скрипт не перезапускается,
     сетевые настройки/Wi-Fi/DHCP не трогаются).
  4. Тянет актуальный server/server.py с GitHub (raw, ветка main); если сети
     до GitHub нет — берёт локальную копию рядом с этим файлом.
  5. Сверяет с тем, что реально лежит на коробке (/opt/jackalrouter/server.py),
     игнорируя строку INT_IFACE (она у каждой коробки своя).
  6. Если отличается — показывает diff, делает бэкап, накатывает новую версию,
     перезапускает jackalrouter, проверяет что сервис жив и API отвечает.
     Если что-то не так — откатывает бэкап автоматически.
  7. Перегенерирует /etc/sing-box/config.json под уже настроенный на коробке
     прокси (иначе фикс подхватится только при следующем нажатии Route
     в клиенте) и следом sing-box.
  8. Проверяет/создаёт systemd-юнит устойчивости policy routing.

Флаг --check (или -n): только показать, есть ли обновление, ничего не менять.
Порт SSH: --port N (или -p N), либо прямо в адресе как host:port (например
для туннеля Pinggy:  python update.py stjem-....pinggy-free.link:37949 stevan).
Вид деплоя: --type N (1-4, как в меню) — пропускает интерактивный вопрос,
нужно для неинтерактивного/скриптового запуска.

Требуется: клиент OpenSSH (ssh/scp). На Windows 10/11 он встроен, на Linux/Mac есть.
"""

import os
import sys
import shutil
import subprocess
import urllib.request

# ── Вывод в UTF-8 ────────────────────────────────────────────────────────────
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
if os.name == "nt":
    os.system("")
    os.system("chcp 65001 >nul 2>&1")

R = "\033[0;31m"; G = "\033[0;32m"; Y = "\033[0;33m"
B = "\033[0;34m"; C = "\033[0;36m"; W = "\033[1;37m"; N = "\033[0m"

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
REMOTE_DIR   = "jackalrouter-deploy"   # тот же каталог, что использует deploy.py
DEPLOY_DIR   = "/opt/jackalrouter"
KEY_PATH     = os.path.join(os.path.expanduser("~"), ".ssh", "jackalrouter_deploy")
GITHUB_REPO  = "MorganWeistling/JackalRouter"
GITHUB_REF   = "main"

SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"]
# Нестандартный порт (например, туннель Pinggy) — задаётся через --port/-p
# или напрямую в адресе как host:port. ssh и scp принимают порт РАЗНЫМИ
# флагами (-p и -P соответственно) — отсюда два отдельных хелпера.
SSH_PORT = None


def ssh_port_args():
    return ["-p", str(SSH_PORT)] if SSH_PORT else []


def scp_port_args():
    return ["-P", str(SSH_PORT)] if SSH_PORT else []

# Тот же список видов деплоя, что в deploy.py — только для контекста/подсказки,
# сам скрипт этим апдейтером НЕ запускается (сеть/Wi-Fi/DHCP не трогаем).
DEPLOYS = {
    "1": ("UBUNTU + ROUTER",     "deploy.sh"),
    "2": ("RASPBERRY + ROUTER",  "deploy-rpi5.sh"),
    "3": ("RASPBERRY + WIFI",    "deploy-rpi5-ap.sh"),
    "4": ("UBUNTU + WIFI",       "deploy-ubuntu-wifi-ap.sh"),
}


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
    print(f"{B}║{W}    JackalRouter — Обновление коробки        {B}║{N}")
    print(f"{B}║{C}  Тянет фиксы с GitHub, без полного передеплоя{B}║{N}")
    print(f"{B}╚══════════════════════════════════════════════╝{N}\n")


def check_tools():
    for t in ("ssh", "scp", "ssh-keygen"):
        if shutil.which(t) is None:
            die(f"Не найден '{t}' (клиент OpenSSH).",
                "Windows 10/11: Параметры → Приложения → Доп. компоненты → "
                "'Клиент OpenSSH'. Linux/Mac: установите openssh-client.")
    ok("SSH/SCP на месте")


def run_ssh(user, host, remote_cmd, tty=False, quiet=False):
    cmd = ["ssh"] + SSH_OPTS + ssh_port_args() + (["-t"] if tty else []) + [f"{user}@{host}", remote_cmd]
    kwargs = {}
    if quiet:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    r = subprocess.run(cmd, **kwargs)
    return r.returncode == 0


def ssh_capture(user, host, remote_cmd, input_text=None):
    """Выполнить команду на сервере (опционально передав ей stdin) и вернуть
    (returncode, stdout, stderr).

    input_text шлём БАЙТАМИ, не через text=True: на Windows subprocess в
    текстовом режиме молча транслирует \\n -> \\r\\n при записи в stdin
    дочернего процесса — remote bash получает CRLF и падает с
    "$'\\r': command not found". Проверено на живой коробке."""
    cmd = ["ssh"] + SSH_OPTS + ssh_port_args() + [f"{user}@{host}", remote_cmd]
    try:
        input_bytes = input_text.encode("utf-8") if input_text is not None else None
        r = subprocess.run(cmd, input=input_bytes, capture_output=True)
        stdout = r.stdout.decode("utf-8", errors="replace")
        stderr = r.stderr.decode("utf-8", errors="replace")
        return r.returncode, stdout, stderr
    except Exception as e:
        return 1, "", str(e)


def setup_ssh_key(user, host):
    """Тот же механизм, что в deploy.py — отдельный ключ под этот тулинг,
    чтобы пароль спрашивался максимум один раз за прогон."""
    ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    if not os.path.exists(KEY_PATH):
        info("Создаю SSH-ключ…")
        r = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", KEY_PATH,
             "-C", "jackalrouter-deploy"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0 or not os.path.exists(KEY_PATH):
            warn("Не удалось создать SSH-ключ — продолжу с паролем.")
            return
        ok("SSH-ключ создан")

    try:
        pub = open(KEY_PATH + ".pub", "r", encoding="utf-8").read().strip()
    except Exception:
        warn("Не читается публичный ключ — продолжу с паролем.")
        return

    probe = ["ssh"] + SSH_OPTS + ssh_port_args() + ["-i", KEY_PATH, "-o", "BatchMode=yes",
                                  f"{user}@{host}", "true"]
    if subprocess.run(probe, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
        SSH_OPTS.extend(["-i", KEY_PATH])
        ok("Вход по ключу уже настроен — пароль не потребуется")
        return

    info("Устанавливаю ключ на сервер (может спросить пароль последний раз)…")
    install = (
        "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
        f"grep -qxF '{pub}' ~/.ssh/authorized_keys || echo '{pub}' >> ~/.ssh/authorized_keys; "
        "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"
    )
    if not run_ssh(user, host, install, tty=True):
        warn("Не удалось положить ключ — продолжу с паролем.")
        return
    if subprocess.run(probe, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
        SSH_OPTS.extend(["-i", KEY_PATH])
        ok("Ключ установлен — дальше без пароля")
    else:
        warn("Ключ положен, но вход по нему не сработал — продолжу с паролем.")


def ensure_nopasswd_sudo(user, host):
    """Без этого удалённый апдейт-скрипт пришлось бы гонять через -t с живым
    вводом пароля sudo — неудобно для тулза, который планируется запускать
    регулярно. Идемпотентно, безопасно повторять."""
    sudoers = "/etc/sudoers.d/jackal-nopasswd"
    setup = (
        f'echo "{user} ALL=(ALL) NOPASSWD:ALL" | sudo tee {sudoers} >/dev/null '
        f'&& sudo chmod 440 {sudoers} && sudo visudo -cf {sudoers}'
    )
    if not run_ssh(user, host, setup, tty=True):
        warn("Не удалось настроить NOPASSWD sudo — попробую всё равно.")
        return
    if run_ssh(user, host, "sudo -n true", quiet=True):
        ok("sudo без пароля настроен")
    else:
        warn("sudo всё ещё просит пароль — обновление может не пройти.")


def fetch_latest_server_py():
    """Тянем актуальный server.py С GITHUB (как просили — сверка именно
    с GitHub, а не с тем, что случайно лежит локально). Если сети до GitHub
    нет (или репозиторий приватный) — падаем на локальную копию рядом
    с update.py, она обычно и есть последний запушенный коммит."""
    url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_REF}/server/server.py"
    info(f"Тяну актуальный server.py с GitHub ({GITHUB_REF})…")
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            content = r.read().decode("utf-8")
        if "def make_singbox_conf" not in content:
            raise ValueError("похоже на не тот файл")
        ok("Получено с GitHub")
        return content, "github"
    except Exception as e:
        warn(f"Не удалось получить с GitHub ({e}) — беру локальную копию.")
        local_path = os.path.join(SCRIPT_DIR, "server", "server.py")
        if not os.path.exists(local_path):
            die("Нет ни доступа к GitHub, ни локальной копии server/server.py.",
                "Запускайте update.py из папки проекта, либо проверьте интернет.")
        content = open(local_path, "r", encoding="utf-8").read()
        ok(f"Взято локально: {local_path}")
        return content, "local"


def fetch_deploy_script(filename):
    """Best-effort: тянет соответствующий deploy-скрипт (для справки/на
    случай ручного передеплоя в будущем) — не выполняется апдейтером."""
    url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_REF}/{filename}"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return r.read().decode("utf-8")
    except Exception:
        local_path = os.path.join(SCRIPT_DIR, filename)
        if os.path.exists(local_path):
            return open(local_path, "r", encoding="utf-8").read()
        return None


REMOTE_UPDATE_SCRIPT = r'''
set -uo pipefail
DEPLOY_DIR="/opt/jackalrouter"
NEW="/tmp/jackal_update/server.py.new"
STAMP=$(date +%Y%m%d%H%M%S)
BACKUP="$DEPLOY_DIR/server.py.bak-$STAMP"

if [ ! -f "$DEPLOY_DIR/server.py" ]; then
    echo "STATUS=NOT_DEPLOYED"
    exit 1
fi
if [ ! -f "$NEW" ]; then
    echo "STATUS=NO_PAYLOAD"
    exit 1
fi

# INT_IFACE — своя для каждой коробки (прописывается при первом деплое),
# новую версию НЕ должна перезатирать placeholder-значением. POSIX sed, а не
# grep -P: PCRE требует UTF-8 локаль и молча падает без неё (проверено —
# в локали без UTF-8 весь блок тихо пропускался бы через "|| true").
CUR_IFACE=$(sed -n 's/^INT_IFACE *= *"\([^"]*\)".*/\1/p' "$DEPLOY_DIR/server.py" | head -1)
if [ -n "$CUR_IFACE" ]; then
    sed -i "s/INT_IFACE *= *\"[^\"]*\"/INT_IFACE    = \"$CUR_IFACE\"/" "$NEW"
fi

if diff -q "$DEPLOY_DIR/server.py" "$NEW" >/dev/null 2>&1; then
    echo "STATUS=UPTODATE"
    rm -rf /tmp/jackal_update
    exit 0
fi

echo "----- что изменится (diff) -----"
diff -u "$DEPLOY_DIR/server.py" "$NEW" | head -200
echo "---------------------------------"

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "STATUS=DRYRUN_WOULD_UPDATE"
    rm -rf /tmp/jackal_update
    exit 0
fi

cp "$DEPLOY_DIR/server.py" "$BACKUP"
cp "$NEW" "$DEPLOY_DIR/server.py"
rm -rf /tmp/jackal_update

systemctl restart jackalrouter
sleep 3
if ! systemctl is-active --quiet jackalrouter; then
    cp "$BACKUP" "$DEPLOY_DIR/server.py"
    systemctl restart jackalrouter
    echo "STATUS=FAIL_SERVICE_ROLLED_BACK"
    exit 1
fi

if ! curl -s --max-time 5 http://localhost:8000/status | grep -q sing_box; then
    cp "$BACKUP" "$DEPLOY_DIR/server.py"
    systemctl restart jackalrouter
    echo "STATUS=FAIL_HEALTH_ROLLED_BACK"
    exit 1
fi

echo "STATUS=UPDATED"
echo "BACKUP_PATH=$BACKUP"

# Форсируем перегенерацию конфига под уже настроенный на коробке прокси —
# иначе новая логика (QUIC-детект, честный DNS-resolve) подхватится только
# при следующем нажатии Route в клиенте, а не сразу.
if [ -f /etc/sing-box/config.json ]; then
    REGEN=$("$DEPLOY_DIR/venv/bin/python3" - <<'PYEOF'
import json, importlib.util, sys
try:
    c = json.load(open('/etc/sing-box/config.json'))
    o = next((x for x in c['outbounds'] if x.get('tag') == 'proxy'), None)
    if not o:
        print("SKIPPED_NO_PROXY"); sys.exit(0)
    spec = importlib.util.spec_from_file_location("srv", "/opt/jackalrouter/server.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    udp_ok = m.check_udp_associate(o['server'], o['server_port'],
                                   o.get('username', ''), o.get('password', ''))
    m.write_singbox_conf(o['server'], o['server_port'],
                         o.get('username', ''), o.get('password', ''),
                         udp_supported=udp_ok)
    print(f"OK udp_supported={udp_ok}")
except Exception as e:
    print(f"ERROR {e}")
PYEOF
)
    echo "CONFIG_REGEN=$REGEN"
    systemctl restart sing-box
    sleep 2
    systemctl is-active --quiet sing-box && echo "SING_BOX=active" || echo "SING_BOX=inactive"
else
    echo "CONFIG_REGEN=SKIPPED_NO_CONFIG"
fi

# Policy-routing persistence — та же защита, что теперь есть во всех деплой-
# скриптах: без неё ip rule/ip route не переживают перезагрузку, и TPROXY
# молча роняет трафик клиентов после ребута коробки.
if [ ! -f /etc/systemd/system/jackal-policy-routing.service ]; then
    cat > /etc/systemd/system/jackal-policy-routing.service << 'UNIT'
[Unit]
Description=JackalRouter: policy routing for TProxy (fwmark 1 -> table 100)
After=network-online.target
Wants=network-online.target
Before=sing-box.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip rule add fwmark 1 table 100 2>/dev/null; ip route add local default dev lo table 100 2>/dev/null; exit 0'

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable jackal-policy-routing -q 2>/dev/null || true
    ip rule add fwmark 1 table 100 2>/dev/null || true
    ip route add local default dev lo table 100 2>/dev/null || true
    echo "POLICY_UNIT=created"
else
    echo "POLICY_UNIT=exists"
fi
'''


def main():
    global SSH_PORT
    header()
    check_tools()

    raw = sys.argv[1:]
    dry_run = any(a in ("--check", "-n") for a in raw)
    deploy_type = None   # если задан флагом --type — пропускаем интерактивный вопрос
    positional = []
    i = 0
    while i < len(raw):
        a = raw[i]
        if a in ("--check", "-n"):
            pass
        elif a in ("--port", "-p"):
            i += 1
            if i < len(raw):
                SSH_PORT = raw[i].strip()
        elif a.startswith("--port="):
            SSH_PORT = a.split("=", 1)[1].strip()
        elif a == "--type":
            i += 1
            if i < len(raw):
                deploy_type = raw[i].strip()
        elif a.startswith("--type="):
            deploy_type = a.split("=", 1)[1].strip()
        else:
            positional.append(a)
        i += 1

    host = positional[0].strip() if positional else ""
    while not host:
        host = input(f"{W}  IP коробки (например 192.168.1.96, можно host:port для нестандартного порта): {N}").strip()
    # Удобство: адрес вида host:port (например туннель Pinggy) — порт можно
    # не выносить отдельным флагом, если он идёт прямо в адресе.
    if ":" in host and SSH_PORT is None:
        host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            SSH_PORT = maybe_port
    user = (positional[1].strip() if len(positional) > 1 else "") or \
        input(f"{W}  SSH-логин [family]: {N}").strip() or "family"

    if SSH_PORT:
        info(f"SSH-порт: {SSH_PORT}")

    if dry_run:
        info("Режим --check: только проверю, есть ли обновление, ничего не изменю.")

    print()
    info(f"Проверяю связь с {user}@{host} …  (если попросит пароль — введите)")
    if not run_ssh(user, host, "true", quiet=True):
        die(f"Нет SSH-связи с {user}@{host}.",
            "Проверьте: коробка включена, IP верный, SSH включён, логин правильный.")
    ok(f"Связь есть: {user}@{host}")

    print()
    setup_ssh_key(user, host)
    if not dry_run:
        print()
        ensure_nopasswd_sudo(user, host)

    # ── Вид деплоя — для справки и обновления сохранённой копии скрипта ──────
    print()
    if deploy_type and deploy_type in DEPLOYS:
        choice = deploy_type
    else:
        if deploy_type:
            warn(f"--type {deploy_type} не распознан ([1-{len(DEPLOYS)}]) — спрошу интерактивно.")
        print(f"{W}  Какой вид деплоя стоит на этой коробке?{N}")
        for k, (name, _f) in DEPLOYS.items():
            print(f"    {G}{k}{N}) {W}{name}{N}")
        choice = ""
        while choice not in DEPLOYS:
            choice = input(f"{W}  Номер [1-{len(DEPLOYS)}]: {N}").strip()
    depl_name, depl_script = DEPLOYS[choice]
    ok(f"Отмечено: {depl_name} ({depl_script}) — сеть/Wi-Fi/DHCP не трогаем")

    # ── Проверяем, что коробка вообще уже развёрнута ──────────────────────────
    rc, out, _ = ssh_capture(user, host, f"test -f {DEPLOY_DIR}/server.py && echo yes || echo no")
    if out.strip() != "yes":
        die(f"На {host} не найден {DEPLOY_DIR}/server.py — похоже, JackalRouter там не развёрнут.",
            f"Сначала выполните полный деплой:  python deploy.py {host} {user}")
    ok("JackalRouter на коробке найден")

    # ── Тянем актуальный server.py и заливаем на коробку во временный путь ───
    print()
    content, source = fetch_latest_server_py()
    info(f"Источник: {'GitHub raw' if source == 'github' else 'локальная копия'}")

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        local_new = os.path.join(tmp, "server.py.new")
        with open(local_new, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)

        run_ssh(user, host, "mkdir -p /tmp/jackal_update", quiet=True)
        scp_cmd = ["scp"] + SSH_OPTS + scp_port_args() + [local_new, f"{user}@{host}:/tmp/jackal_update/server.py.new"]
        if subprocess.run(scp_cmd).returncode != 0:
            die("Не удалось скопировать новый server.py на коробку.",
                "Проверьте связь и повторите.")

    # ── Обновлённая копия deploy-скрипта — best effort, справочно ────────────
    depl_content = fetch_deploy_script(depl_script)
    if depl_content:
        rc, _, _ = ssh_capture(user, host, f"mkdir -p ~/{REMOTE_DIR}/server")
        import tempfile as _tf
        with _tf.TemporaryDirectory() as tmp2:
            p = os.path.join(tmp2, depl_script)
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(depl_content)
            subprocess.run(["scp"] + SSH_OPTS + scp_port_args() + [p, f"{user}@{host}:~/{REMOTE_DIR}/{depl_script}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ── Запускаем сверку/апдейт на коробке ────────────────────────────────────
    print()
    print(f"{B}══════════════════════════════════════════════{N}")
    print(f"{W}  Сверяю и обновляю на коробке…{N}")
    print(f"{B}══════════════════════════════════════════════{N}\n")

    remote_cmd = f"DRY_RUN={'1' if dry_run else '0'} sudo -n bash -s"
    rc, out, errtext = ssh_capture(user, host, remote_cmd, input_text=REMOTE_UPDATE_SCRIPT)
    print(out.strip())
    if errtext.strip():
        print(f"{Y}{errtext.strip()}{N}")

    status = ""
    for line in out.splitlines():
        if line.startswith("STATUS="):
            status = line.split("=", 1)[1].strip()

    print()
    if status == "UPTODATE":
        print(f"{G}╔══════════════════════════════════════════════╗{N}")
        print(f"{G}║{W}   УЖЕ АКТУАЛЬНО — обновлять нечего          {G}║{N}")
        print(f"{G}╚══════════════════════════════════════════════╝{N}")
    elif status == "DRYRUN_WOULD_UPDATE":
        print(f"{Y}╔══════════════════════════════════════════════╗{N}")
        print(f"{Y}║{W}   ЕСТЬ ОБНОВЛЕНИЕ (--check, не применялось) {Y}║{N}")
        print(f"{Y}╚══════════════════════════════════════════════╝{N}")
        print(f"{W}  Запустите без --check, чтобы применить.{N}")
    elif status == "UPDATED":
        print(f"{G}╔══════════════════════════════════════════════╗{N}")
        print(f"{G}║{W}        ОБНОВЛЕНО И ПРИМЕНЕНО УСПЕШНО        {G}║{N}")
        print(f"{G}╚══════════════════════════════════════════════╝{N}")
        print(f"{W}  server.py обновлён, jackalrouter/sing-box перезапущены,{N}")
        print(f"{W}  конфиг перегенерирован под текущий прокси на коробке.{N}")
    elif status in ("FAIL_SERVICE_ROLLED_BACK", "FAIL_HEALTH_ROLLED_BACK"):
        err("Новая версия не прошла проверку — автоматически откачено на бэкап.")
        print(f"{Y}  Сервис работает на старой (рабочей) версии. Посмотрите логи на коробке:{N}")
        print(f"{C}  sudo journalctl -u jackalrouter -n 50 --no-pager{N}")
        sys.exit(1)
    elif status == "NOT_DEPLOYED":
        die("На коробке не найден JackalRouter (server.py пропал?).", "")
    else:
        err(f"Не удалось разобрать результат (STATUS={status!r}) — смотрите вывод выше.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}  Прервано пользователем.{N}")
        sys.exit(130)
