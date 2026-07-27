#!/bin/bash
# =============================================================================
#  JackalRouter — Деплой на Ubuntu в режиме Wi-Fi ↔ Wi-Fi (два адаптера)
#  Запуск:  sudo bash deploy-ubuntu-wifi-ap.sh
#
#  Топология (нужны ДВА Wi-Fi адаптера, сервера НЕ нужно):
#     • Wi-Fi #1 (клиент)       → берёт интернет из существующей сети (WAN)
#     • Wi-Fi #2 (точка доступа) → раздаёт прокси телефонам/ноутбукам (LAN)
#
#  Диапазоны НЕ зафиксированы жёстко на 5/2.4 ГГц: WAN подключается на том
#  диапазоне, на котором реально вещает выбранная сеть, а диапазон раздачи
#  (по умолчанию 2.4 ГГц — лучше дальность/совместимость) выбирается в диалоге.
#  Один физический радиомодуль не может одновременно быть клиентом И точкой
#  доступа, поэтому нужны два отдельных Wi-Fi адаптера (например, встроенный +
#  USB-свисток).
#
#  Если WAN-адаптер уже подключён к рабочей сети с интернетом (в т.ч. если
#  именно через него идёт эта самая SSH-сессия) — скрипт НЕ переподключает
#  его заново, а использует как есть. Это важно: раньше принудительное
#  пересоздание соединения на уже активном адаптере рвало SSH-сессию, через
#  которую запускался сам скрипт.
#
#  Рассчитан на новичка: проверки совместимости, спросит SSID/пароли,
#  всё настроит и объяснит, что делать дальше.
# =============================================================================

set -euo pipefail

# ── Цвета ─────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
B='\033[0;34m'; C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'
OK="${G}  ✓${N}"; WARN="${Y}  ⚠${N}"; ERR="${R}  ✗${N}"; INFO="${C}  →${N}"

# ── Константы ─────────────────────────────────────────────────────────────────
DEPLOY_DIR="/opt/jackalrouter"
LAN_SUBNET="10.0.0"
LAN_IP="${LAN_SUBNET}.1"
DHCP_FROM="${LAN_SUBNET}.100"
DHCP_TO="${LAN_SUBNET}.200"
SINGBOX_PORT=7893
SERVER_PORT=8000
# Диапазон/канал раздачи по умолчанию (2.4 ГГц, канал 6 — не пересекается с 1/11).
# Меняется в диалоге на шаге 2 (можно выбрать 5 ГГц вместо 2.4).
AP_BAND="bg"
AP_CHANNEL=6
AP_BAND_LABEL="2.4 ГГц"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_STEPS=10

# ── Вспомогательные функции ───────────────────────────────────────────────────
step() { echo -e "\n${W}[$1/$TOTAL_STEPS] $2${N}"; }
ok()   { echo -e "${OK} $1"; }
warn() { echo -e "${WARN} $1"; }
err()  { echo -e "${ERR} $1"; }
info() { echo -e "${INFO} $1"; }
die() {
    echo -e "\n${R}═══════════════════════════════════════════════${N}"
    echo -e "${R}  ОШИБКА: $1${N}"
    echo -e "${R}═══════════════════════════════════════════════${N}"
    echo -e "${Y}  Что делать: $2${N}\n"
    exit 1
}
have_net() { curl -s --max-time 8 https://google.com -o /dev/null 2>/dev/null; }
# Пытаемся понять, через какой интерфейс идёт ТЕКУЩАЯ SSH-сессия (если скрипт
# запущен по SSH) — чтобы не превратить его в точку доступа и не оборвать себя.
mgmt_iface_hint() {
    [ -n "${SSH_CONNECTION:-}" ] || return 1
    local local_ip; local_ip=$(awk '{print $3}' <<< "$SSH_CONNECTION")
    [ -z "$local_ip" ] && return 1
    ip -4 -o addr show 2>/dev/null | awk -v ip="$local_ip" '$4 ~ "^"ip"/"{print $2; exit}'
}

# ── Шапка ─────────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e "${B}╔══════════════════════════════════════════════╗${N}"
echo -e "${B}║${W}  JackalRouter — Ubuntu, Wi-Fi ↔ Wi-Fi       ${B}║${N}"
echo -e "${B}║${C}  Интернет по Wi-Fi → раздача по Wi-Fi       ${B}║${N}"
echo -e "${B}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}Как всё будет соединено:${N}"
echo -e "  ${C}Wi-Fi адаптер #1 → подключается к вашей домашней Wi-Fi сети (интернет)${N}"
echo -e "  ${C}Wi-Fi адаптер #2 → раздаёт свою сеть, сюда подключаете телефон${N}"
echo -e "  ${Y}Нужны ДВА разных Wi-Fi адаптера (например, встроенный + USB-свисток).${N}"
echo -e "  ${Y}Если WAN-адаптер уже онлайн — переиспользуем текущее подключение, не рвём его.${N}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
step 1 "Проверка совместимости"
# ═══════════════════════════════════════════════════════════════════════════════

[ "$(id -u)" -ne 0 ] && die "Скрипт должен запускаться от root." "Выполните:  sudo bash deploy-ubuntu-wifi-ap.sh"
ok "Права root — есть"

if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
    warn "Система не Ubuntu — продолжаем, но возможны проблемы"
else
    UBUNTU_VER=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    ok "Ubuntu $UBUNTU_VER обнаружена"
fi

if ! systemctl is-active NetworkManager -q 2>/dev/null; then
    die "NetworkManager не активен — он нужен для Wi-Fi клиента и точки доступа." \
        "Установите/включите:  sudo apt install -y network-manager && sudo systemctl enable --now NetworkManager"
fi
ok "NetworkManager активен"

info "Проверяю поддержку TProxy в ядре..."
modprobe xt_TPROXY 2>/dev/null || true
modprobe nf_tproxy_ipv4 2>/dev/null || true
iptables -t mangle -N JR_TPTEST 2>/dev/null || iptables -t mangle -F JR_TPTEST 2>/dev/null || true
if iptables -t mangle -A JR_TPTEST -p tcp -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1 2>/dev/null; then
    ok "Ядро поддерживает TPROXY"
else
    iptables -t mangle -F JR_TPTEST 2>/dev/null || true; iptables -t mangle -X JR_TPTEST 2>/dev/null || true
    die "Ядро не поддерживает TPROXY." "Обновите:  sudo apt update && sudo apt full-upgrade -y && sudo reboot  — затем запустите скрипт снова."
fi
iptables -t mangle -F JR_TPTEST 2>/dev/null || true; iptables -t mangle -X JR_TPTEST 2>/dev/null || true
echo -e "xt_TPROXY\nnf_tproxy_ipv4" > /etc/modules-load.d/jackalrouter.conf 2>/dev/null || true

info "Ищу Wi-Fi адаптеры..."
rfkill unblock wifi 2>/dev/null || true
rfkill unblock all 2>/dev/null || true
mapfile -t WIFI_IFACES < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')
[ "${#WIFI_IFACES[@]}" -lt 2 ] && die \
    "Найдено Wi-Fi адаптеров: ${#WIFI_IFACES[@]}. Нужно минимум 2 (один для интернета, второй для раздачи)." \
    "Подключите второй Wi-Fi адаптер (например, USB-свисток) и запустите скрипт снова. Проверить:  iw dev"
ok "Найдено Wi-Fi адаптеров: ${#WIFI_IFACES[@]} (${WIFI_IFACES[*]})"

# ═══════════════════════════════════════════════════════════════════════════════
step 2 "Запрет сна — коробка работает как роутер, крышка будет закрыта"
# ═══════════════════════════════════════════════════════════════════════════════
# Ноутбук в этой роли обязан работать всегда, вне зависимости от закрытой
# крышки и простоя. Дефолт systemd на закрытие крышки — suspend, что убивает
# и Wi-Fi AP, и прокси для всех клиентов разом. Фиксим на двух уровнях:
# systemd-logind (действует всегда) и GNOME power-plugin (на случай, если
# что-то инициирует sleep через сессию, а не через lid-switch напрямую).

info "systemd-logind: игнорировать закрытие крышки и простой..."
mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/99-jackalrouter-no-sleep.conf << 'EOF'
[Login]
HandleLidSwitch=ignore
HandleLidSwitchDocked=ignore
HandleLidSwitchExternalPower=ignore
IdleAction=ignore
EOF
systemctl restart systemd-logind
ok "Крышка/простой больше не усыпляют систему"

info "Блокирую sleep/suspend/hibernate на уровне systemd..."
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target 2>/dev/null || true
ok "sleep-таргеты замаскированы — в спящий режим не уйдёт, даже если что-то попросит"

# GNOME (если есть графическая сессия) — своя логика энергосбережения поверх
# logind, лучше выключить и её. Не критично, если DE нет: просто пропускаем.
if command -v gsettings >/dev/null 2>&1; then
    JR_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-}")
    JR_UID=$(id -u "$JR_USER" 2>/dev/null || true)
    if [ -n "$JR_USER" ] && [ -n "$JR_UID" ] && [ -S "/run/user/$JR_UID/bus" ]; then
        info "GNOME power-настройки для $JR_USER: отключаю автосон..."
        for kv in \
            "org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing" \
            "org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type nothing" \
            "org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0" \
            "org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0" \
            "org.gnome.desktop.session idle-delay 0"
        do
            schema=$(echo "$kv" | awk '{print $1}')
            key=$(echo "$kv" | awk '{print $2}')
            val=$(echo "$kv" | cut -d' ' -f3-)
            sudo -u "$JR_USER" env XDG_RUNTIME_DIR="/run/user/$JR_UID" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$JR_UID/bus" \
                gsettings set "$schema" "$key" "$val" 2>/dev/null || true
        done
        ok "GNOME автосон отключён для $JR_USER"
    else
        info "Графической сессии не видно (сервер/безголовая система) — GNOME-настройки пропущены, они и не нужны"
    fi
else
    info "gsettings нет — GNOME отсутствует, пропускаю (systemd-уровня фикса достаточно)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
step 3 "Выбор адаптеров и параметры сетей"
# ═══════════════════════════════════════════════════════════════════════════════

list_ifaces() {
    local i=1
    for f in "${WIFI_IFACES[@]}"; do echo "   $i) $f"; i=$((i+1)); done
}
# Спросить корректный номер адаптера (1..N); $1 — подсказка, $2 — значение по умолчанию.
ask_iface() {
    local prompt="$1" def="$2" ans
    while :; do
        read -r -p "$prompt" ans; ans=${ans:-$def}
        if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le "${#WIFI_IFACES[@]}" ]; then
            printf '%s' "${WIFI_IFACES[$((ans-1))]}"; return 0
        fi
        echo -e "   ${Y}Введите число от 1 до ${#WIFI_IFACES[@]}.${N}" >&2
    done
}

if [ -t 0 ]; then
    echo ""
    echo -e "${W}Какой адаптер брать под интернет (клиент)?${N}"
    list_ifaces
    WAN_IFACE=$(ask_iface "   Номер [1]: " 1)
    echo ""
    echo -e "${W}Какой адаптер брать под раздачу (точка доступа)?${N}"
    list_ifaces
    LAN_IFACE=$(ask_iface "   Номер (не совпадает с предыдущим) [2]: " 2)
else
    WAN_IFACE="${WIFI_IFACES[0]}"
    LAN_IFACE="${WIFI_IFACES[1]}"
    warn "Не интерактивно — беру $WAN_IFACE под интернет, $LAN_IFACE под раздачу."
fi
[ "$WAN_IFACE" = "$LAN_IFACE" ] && die "WAN и LAN адаптер совпадают ($WAN_IFACE)." "Нужны два РАЗНЫХ Wi-Fi адаптера."
ok "Интернет (WAN): ${W}$WAN_IFACE${N}   Раздача (LAN, точка доступа): ${W}$LAN_IFACE${N}"

# ── Не превратить в AP интерфейс, через который сейчас идёт эта же SSH-сессия ──
MGMT_IFACE="$(mgmt_iface_hint || true)"
if [ -n "${MGMT_IFACE:-}" ] && [ "$MGMT_IFACE" = "$LAN_IFACE" ]; then
    warn "Похоже, именно через $LAN_IFACE сейчас идёт ЭТА SSH-сессия!"
    echo -e "   ${Y}Превращение $LAN_IFACE в точку доступа ОБОРВЁТ текущее подключение.${N}"
    if [ -t 0 ]; then
        read -r -p "   Всё равно продолжить и потерять эту сессию? (наберите 'yes'): " CONFIRM_LOSE_SSH
        [ "$CONFIRM_LOSE_SSH" = "yes" ] || die "Отменено пользователем." \
            "Подключитесь с локальной консоли (не через $LAN_IFACE) или выберите другой LAN-адаптер, и запустите скрипт снова."
    else
        die "$LAN_IFACE несёт текущую SSH-сессию — не буду превращать его в точку доступа без подтверждения." \
            "Запустите скрипт с локальной консоли, либо выберите другой Wi-Fi адаптер под раздачу."
    fi
elif [ -n "${MGMT_IFACE:-}" ] && [ "$MGMT_IFACE" = "$WAN_IFACE" ]; then
    info "Эта SSH-сессия идёт через $WAN_IFACE — если он уже онлайн, переподключать не буду (см. ниже)."
fi

# ── Уже подключён ли WAN-адаптер к рабочей сети с интернетом? ────────────────
# Если да — используем как есть, НЕ пересоздаём соединение (иначе можно
# оборвать именно ту сеть, через которую сейчас идёт управление коробкой).
WAN_ALREADY_UP=false
CUR_DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}' || true)
if [ "$CUR_DEFAULT_IFACE" = "$WAN_IFACE" ] && have_net; then
    WAN_ALREADY_UP=true
    CUR_SSID=$(nmcli -t -f active,ssid dev wifi list ifname "$WAN_IFACE" 2>/dev/null \
        | awk -F: '$1=="yes"{print $2; exit}')
    ok "$WAN_IFACE уже подключён и раздаёт интернет (сеть \"${CUR_SSID:-?}\") — использую как есть"
fi

echo ""
if $WAN_ALREADY_UP; then
    info "Пароль/SSID для WAN не нужен — беру текущее подключение $WAN_IFACE."
    WAN_SSID="$CUR_SSID"
else
    echo -e "${W}Сеть, к которой подключаемся за интернетом на $WAN_IFACE:${N}"
    info "Ищу доступные сети на $WAN_IFACE..."
    nmcli -t -f SSID,FREQ,SIGNAL dev wifi list ifname "$WAN_IFACE" --rescan yes 2>/dev/null \
        | awk -F: 'NF && $1!=""{printf "   • %s  (%s МГц, сигнал %s)\n",$1,$2,$3}' | sort -u | head -14 || true
    if [ -t 0 ]; then
        read -r -p "   Имя сети (SSID): " WAN_SSID
        read -r -s -p "   Пароль Wi-Fi сети: " WAN_PASS; echo ""
    else
        die "Нужны SSID/пароль домашней сети — запустите скрипт в интерактивном терминале." \
            "Запустите:  sudo bash deploy-ubuntu-wifi-ap.sh  (без пайпов/фонового режима)"
    fi
fi

# ── Регуляторный домен Wi-Fi (страна) ────────────────────────────────────────
# Нужен для точки доступа: от него зависит, какие каналы/мощность разрешены.
# На 5 ГГц неверный или пустой домен ("00", world) — частая причина, по которой
# AP вообще не поднимается. Коробка уже подключена к Wi-Fi, поэтому ядро обычно
# само переняло домен от точки провайдера (802.11d) — берём его и не спрашиваем.
DETECTED_COUNTRY=$(iw reg get 2>/dev/null | awk '/^country/{gsub(/:/,"",$2); print $2; exit}')
if [[ "${DETECTED_COUNTRY:-}" =~ ^[A-Z]{2}$ ]] && [ "$DETECTED_COUNTRY" != "00" ]; then
    COUNTRY="$DETECTED_COUNTRY"
    ok "Регион Wi-Fi определён автоматически: ${W}$COUNTRY${N} (ничего вводить не нужно)"
elif [ -t 0 ]; then
    echo -e "   ${Y}Регион Wi-Fi не определён автоматически.${N}"
    echo -e "   ${C}Нужен ISO-код страны из 2 букв (US, IN, RU, DE…) — от него зависят${N}"
    echo -e "   ${C}разрешённые каналы Wi-Fi. Укажите страну, где реально стоит коробка.${N}"
    while :; do
        read -r -p "   Код страны [US]: " COUNTRY; COUNTRY=${COUNTRY:-US}
        COUNTRY=$(tr '[:lower:]' '[:upper:]' <<< "$COUNTRY")
        [[ "$COUNTRY" =~ ^[A-Z]{2}$ ]] && break
        echo -e "   ${Y}Нужны ровно 2 латинские буквы, например US или IN.${N}"
    done
else
    COUNTRY="US"
fi

echo ""
echo -e "${W}Диапазон, в котором эта коробка будет раздавать Wi-Fi:${N}"
echo "   1) 2.4 ГГц — лучше дальность и проникновение сквозь стены (по умолчанию)"
echo "   2) 5 ГГц   — быстрее, меньше помех от соседей, короче дальность"
if [ -t 0 ]; then
    read -r -p "   Номер [1]: " AP_BAND_CHOICE; AP_BAND_CHOICE=${AP_BAND_CHOICE:-1}
else
    AP_BAND_CHOICE=1
fi
if [ "$AP_BAND_CHOICE" = "2" ]; then
    AP_BAND="a"; AP_CHANNEL=36; AP_BAND_LABEL="5 ГГц"
else
    AP_BAND="bg"; AP_CHANNEL=6; AP_BAND_LABEL="2.4 ГГц"
fi
ok "Раздача будет на $AP_BAND_LABEL (канал $AP_CHANNEL)"

echo ""
echo -e "${W}Сеть, которую будет раздавать эта коробка ($AP_BAND_LABEL):${N}"
if [ -t 0 ]; then
    read -r -p "   Имя сети (SSID) [JackalRouter]: " AP_SSID; AP_SSID=${AP_SSID:-JackalRouter}
    while :; do
        read -r -s -p "   Пароль Wi-Fi (минимум 8 символов): " AP_PASS; echo ""
        [ "${#AP_PASS}" -ge 8 ] && break
        echo -e "   ${Y}Пароль слишком короткий — нужно не меньше 8 символов.${N}"
    done
else
    AP_SSID="JackalRouter"; AP_PASS="Jackal$(date +%s | tail -c 6)"
    warn "Не интерактивно — задал: SSID=${AP_SSID}, пароль=${AP_PASS} (ОБЯЗАТЕЛЬНО смените!)"
fi
ok "Раздаём: SSID \"${W}$AP_SSID${N}\", страна $COUNTRY"

info "Прописываю $LAN_IFACE в конфиг сервера..."
sed -i "s/INT_IFACE *= *\"[^\"]*\"/INT_IFACE    = \"$LAN_IFACE\"/" "$SCRIPT_DIR/server/server.py"
ok "Интерфейс $LAN_IFACE записан в server.py"

# ═══════════════════════════════════════════════════════════════════════════════
step 4 "Установка пакетов"
# ═══════════════════════════════════════════════════════════════════════════════

info "Обновляю список пакетов (до минуты)..."
apt-get update -qq 2>/dev/null || warn "Некоторые репозитории недоступны — не критично."
ok "Список пакетов обновлён"

echo ""
info "Устанавливаю пакеты (python3, dnsmasq, iptables-persistent, iw, ethtool, rfkill, curl, wget)..."
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing \
    python3 python3-venv dnsmasq iptables iptables-persistent \
    iw ethtool rfkill curl wget 2>/dev/null || die \
    "Не удалось установить пакеты." "Проверьте интернет и повторите запуск."
ok "Все пакеты установлены"

# ═══════════════════════════════════════════════════════════════════════════════
step 5 "Подключение к интернету через $WAN_IFACE"
# ═══════════════════════════════════════════════════════════════════════════════

info "Задаю регион ($COUNTRY)..."
if iw reg set "$COUNTRY" 2>/dev/null; then
    sleep 1
    APPLIED_COUNTRY=$(iw reg get 2>/dev/null | awk '/^country/{gsub(/:/,"",$2); print $2; exit}')
    if [ "${APPLIED_COUNTRY:-}" = "$COUNTRY" ]; then
        ok "Регион Wi-Fi: ${W}$COUNTRY${N}"
    else
        warn "Запросил регион $COUNTRY, ядро сообщает '${APPLIED_COUNTRY:-неизвестно}' — на 5 ГГц часть каналов может быть недоступна."
    fi
else
    warn "Ядро отклонило регион '$COUNTRY' (неверный код?) — оставляю текущий: ${APPLIED_COUNTRY:-$(iw reg get 2>/dev/null | awk '/^country/{gsub(/:/,"",$2); print $2; exit}')}"
fi

if $WAN_ALREADY_UP; then
    info "$WAN_IFACE уже онлайн (сеть \"$WAN_SSID\") — не переподключаюсь, использую как есть."
else
    info "Подключаюсь к \"$WAN_SSID\" на $WAN_IFACE (диапазон — какой реально вещает сеть)..."
    nmcli con delete jackal-wan 2>/dev/null || true
    nmcli con add type wifi ifname "$WAN_IFACE" con-name jackal-wan ssid "$WAN_SSID" 2>/dev/null \
        || die "Не удалось создать Wi-Fi соединение." "Проверьте $WAN_IFACE:  ip link show $WAN_IFACE"
    nmcli con modify jackal-wan \
        wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$WAN_PASS" \
        connection.autoconnect yes 2>/dev/null \
        || die "Не удалось настроить Wi-Fi клиент." "Проверьте пароль сети."
    nmcli con up jackal-wan 2>/dev/null || warn "Соединение не поднялось сразу — проверю ниже."
    sleep 3
fi

if ! have_net; then
    die "Нет интернета через $WAN_IFACE." \
        "Проверьте: сеть \"$WAN_SSID\" реально в радиусе действия, пароль верный, сигнал достаточный. Логи:  nmcli con show jackal-wan; journalctl -u NetworkManager -n 30"
fi
WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
ok "Интернет (WAN): ${W}$WAN_IFACE${N} ($WAN_IP)"

# ═══════════════════════════════════════════════════════════════════════════════
step 6 "Точка доступа на $LAN_IFACE ($AP_BAND_LABEL)"
# ═══════════════════════════════════════════════════════════════════════════════

info "Создаю точку доступа \"$AP_SSID\" (WPA2, $AP_BAND_LABEL, канал $AP_CHANNEL) с IP $LAN_IP..."
nmcli con delete jackal-ap 2>/dev/null || true
nmcli con add type wifi ifname "$LAN_IFACE" con-name jackal-ap ssid "$AP_SSID" 2>/dev/null \
    || die "Не удалось создать Wi-Fi соединение." "Проверьте $LAN_IFACE:  ip link show $LAN_IFACE"
nmcli con modify jackal-ap \
    802-11-wireless.mode ap 802-11-wireless.band "$AP_BAND" 802-11-wireless.channel "$AP_CHANNEL" \
    ipv4.method manual ipv4.addresses "${LAN_IP}/24" ipv4.never-default yes \
    wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$AP_PASS" \
    connection.autoconnect yes 2>/dev/null \
    || die "Не удалось настроить точку доступа." "Проверьте, что адаптер поддерживает режим AP и диапазон $AP_BAND_LABEL:  iw list | grep -A6 'Supported interface modes'"
nmcli con up jackal-ap 2>/dev/null || warn "Точка доступа не поднялась сразу — проверю в конце."
sleep 3

if iw dev "$LAN_IFACE" info 2>/dev/null | grep -qi 'type AP'; then
    ok "Точка доступа активна: SSID \"${W}$AP_SSID${N}\", IP $LAN_IP"
else
    warn "$LAN_IFACE пока не в режиме AP — иногда поднимается через 5–10 секунд."
fi

# ═══════════════════════════════════════════════════════════════════════════════
step 7 "DHCP-сервер для Wi-Fi клиентов (dnsmasq)"
# ═══════════════════════════════════════════════════════════════════════════════

info "Настраиваю dnsmasq (DHCP + DNS на $LAN_IFACE)..."
cat > /etc/dnsmasq.d/jackal-dhcp.conf << EOF
# JackalRouter DHCP + DNS — не менять вручную
interface=$LAN_IFACE
bind-interfaces
dhcp-range=${DHCP_FROM},${DHCP_TO},255.255.255.0,12h
dhcp-option=3,${LAN_IP}
dhcp-option=6,8.8.8.8
server=8.8.8.8
server=8.4.4.4
no-resolv
EOF
ok "DHCP + DNS конфиг записан (диапазон ${DHCP_FROM}–${DHCP_TO})"

mkdir -p /etc/systemd/system/dnsmasq.service.d
cat > /etc/systemd/system/dnsmasq.service.d/override.conf << 'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=5s
EOF
systemctl daemon-reload

# ── Кто раздаёт DHCP: наш dnsmasq или NetworkManager? ────────────────────────
# NetworkManager в режиме точки доступа переводит соединение в ipv4.method=shared
# и поднимает СВОЙ dnsmasq на 10.0.0.1:53. Наш системный тогда не может занять
# порт, падает с "Address already in use", а Restart=on-failure крутит его
# бесконечно (на живой коробке досчитало до 402 перезапусков подряд).
# Драться за порт бессмысленно: DHCP от NM работает, а утечку DNS мы всё равно
# закрываем правилами TPROXY для :53 в шаге 7 — независимо от того, чей dnsmasq.
sleep 2
if pgrep -f "dnsmasq.*${LAN_IFACE}" >/dev/null 2>&1; then
    systemctl disable dnsmasq -q 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    ok "DHCP раздаёт NetworkManager (его dnsmasq) — свой отключил, чтобы не конфликтовал"
    info "Клиенты получат DNS 10.0.0.1, но запросы принудительно уходят в sing-box (шаг 7)"
else
    systemctl enable dnsmasq -q 2>/dev/null || true
    systemctl restart dnsmasq 2>/dev/null \
        || warn "dnsmasq пока не стартовал (ждёт $LAN_IFACE) — поднимется автоматически."
    ok "DHCP раздаёт наш dnsmasq (диапазон ${DHCP_FROM}–${DHCP_TO})"
fi

# ═══════════════════════════════════════════════════════════════════════════════
step 8 "iptables — TProxy маршрутизация и защита от утечек"
# ═══════════════════════════════════════════════════════════════════════════════

info "Включаю IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 -q
grep -q "net.ipv4.ip_forward" /etc/sysctl.conf \
    && sed -i 's/.*net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf \
    || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
ok "IP forwarding включён (постоянно)"

info "Policy routing (fwmark 1 → local)..."
ip rule del fwmark 1 table 100 2>/dev/null || true
ip rule add fwmark 1 table 100
ip route del local default dev lo table 100 2>/dev/null || true
ip route add local default dev lo table 100
ok "fwmark 1 → таблица 100"

# ── ВАЖНО: сделать policy routing постоянным ─────────────────────────────────
# netfilter-persistent сохраняет ТОЛЬКО iptables. Правила "ip rule"/"ip route"
# после перезагрузки исчезают, и тогда TPROXY метит пакеты меткой 1, а доставить
# их локально ядру нечем — трафик клиентов молча пропадает. Снаружи это выглядит
# как "Wi-Fi раздаётся, DHCP выдаёт адрес, но интернета нет". Поэтому вешаем
# oneshot-юнит, который восстанавливает их при каждой загрузке до старта sing-box.
info "Делаю policy routing постоянным (переживёт перезагрузку)..."
cat > /etc/systemd/system/jackal-policy-routing.service << 'EOF'
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
EOF
systemctl daemon-reload
systemctl enable jackal-policy-routing -q 2>/dev/null || warn "Не удалось включить автозапуск policy routing"
ok "Policy routing восстанавливается при загрузке (jackal-policy-routing.service)"

info "MSS clamp 1280 на $LAN_IFACE..."
iptables -t mangle -D PREROUTING -i "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280 2>/dev/null || true
iptables -t mangle -A PREROUTING -i "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280
iptables -t mangle -D POSTROUTING -o "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280 2>/dev/null || true
iptables -t mangle -A POSTROUTING -o "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280
ok "MSS clamp 1280 — ingress + egress"

info "TProxy цепочка SING_BOX..."
iptables -t mangle -N SING_BOX 2>/dev/null || true
iptables -t mangle -F SING_BOX
# DNS клиентов перехватываем ПЕРВЫМ делом — до RETURN'ов для приватных сетей.
# NetworkManager в режиме shared поднимает свой dnsmasq и выдаёт клиентам
# DNS = 10.0.0.1 (сам себя). Без этих двух правил такие запросы попадают под
# "-d 10.0.0.0/8 -j RETURN", уходят мимо sing-box и резолвятся напрямую —
# то есть DNS течёт в обход прокси. Проверено на живой коробке.
iptables -t mangle -A SING_BOX -p udp --dport 53 -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1
iptables -t mangle -A SING_BOX -p tcp --dport 53 -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1
for net in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 \
           172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t mangle -A SING_BOX -d "$net" -j RETURN
done
iptables -t mangle -A SING_BOX -p udp -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1
iptables -t mangle -A SING_BOX -p tcp -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1
iptables -t mangle -D PREROUTING -i "$LAN_IFACE" -j SING_BOX 2>/dev/null || true
iptables -t mangle -A PREROUTING -i "$LAN_IFACE" -j SING_BOX
ok "TProxy: весь UDP+TCP с Wi-Fi → sing-box :$SINGBOX_PORT (QUIC через прокси, FakeIP)"

info "MASQUERADE и FORWARD (LAN $LAN_IFACE ↔ любой выход в интернет)..."
# WAN-сторона намеренно НЕ привязана к имени интерфейса. Если человек потом
# переключит коробку на другую Wi-Fi сеть, воткнёт кабель или USB-модем —
# выход в интернет окажется на другом интерфейсе, и правила с "-o wlp2s0"
# перестали бы совпадать (клиенты остались бы без интернета). Поэтому
# привязываемся только к LAN (точке доступа), а всё остальное считаем WAN.
# Тот же подход уже используется в server.py (catch-all MASQUERADE).
iptables -t nat -D POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true
iptables -t nat -C POSTROUTING ! -o "$LAN_IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING ! -o "$LAN_IFACE" -j MASQUERADE

iptables -D FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -C FORWARD -i "$LAN_IFACE" ! -o "$LAN_IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$LAN_IFACE" ! -o "$LAN_IFACE" -j ACCEPT
iptables -C FORWARD ! -i "$LAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD ! -i "$LAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
ok "MASQUERADE + FORWARD настроены (переживут смену Wi-Fi сети/адаптера)"

info "Блокирую IPv6 из Wi-Fi..."
ip6tables -D FORWARD -i "$LAN_IFACE" -j DROP 2>/dev/null || true
ip6tables -D FORWARD -o "$LAN_IFACE" -j DROP 2>/dev/null || true
ip6tables -A FORWARD -i "$LAN_IFACE" -j DROP
ip6tables -A FORWARD -o "$LAN_IFACE" -j DROP
ip6tables -D INPUT -i "$LAN_IFACE" -p ipv6-icmp -j DROP 2>/dev/null || true
ip6tables -A INPUT -i "$LAN_IFACE" -p ipv6-icmp -j DROP
ok "IPv6 FORWARD DROP"

info "Отключаю GRO/GSO/TSO на $LAN_IFACE..."
ethtool -K "$LAN_IFACE" gro off gso off tso off lro off 2>/dev/null || warn "ethtool не смог (Wi-Fi) — не критично"
ok "offload отключён (где поддерживается)"

info "Сохраняю правила iptables..."
netfilter-persistent save -q 2>/dev/null \
    || { mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6; }
ok "Правила сохранены (переживут перезагрузку)"

# ═══════════════════════════════════════════════════════════════════════════════
step 9 "Установка sing-box и JackalRouter"
# ═══════════════════════════════════════════════════════════════════════════════

# ── Сначала убеждаемся, что у САМОЙ коробки жив DNS ──────────────────────────
# К этому моменту уже подняты dnsmasq и применён NAT — то есть тронуто ровно то,
# от чего зависит резолвинг на самой коробке. Если DNS отвалился, дальше всё
# упадёт с бессмысленным "проверьте интернет", хотя интернет-то есть.
ensure_dns() {
    getent hosts github.com >/dev/null 2>&1 && return 0
    warn "Коробка перестала резолвить имена — чиню /etc/resolv.conf..."
    if [ -f /run/systemd/resolve/resolv.conf ]; then
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
        getent hosts github.com >/dev/null 2>&1 && { ok "DNS восстановлен (systemd-resolved)"; return 0; }
    fi
    printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' > /etc/resolv.conf
    getent hosts github.com >/dev/null 2>&1 && { ok "DNS восстановлен (8.8.8.8)"; return 0; }
    return 1
}

info "Проверяю DNS и интернет перед загрузкой..."
if ! ensure_dns; then
    die "На коробке не работает DNS — github.com не резолвится." \
        "Интернет при этом может быть жив (SSH же работает). Проверьте на коробке:  cat /etc/resolv.conf ; systemctl status systemd-resolved dnsmasq ; sudo ss -lnup | grep :53   — вероятно, dnsmasq занял порт 53 и вытеснил systemd-resolved."
fi
ok "DNS резолвит"

info "Определяю последнюю версию sing-box..."
SINGBOX_VERSION=$(curl -s --max-time 20 https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    2>/dev/null | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' | head -1 || true)
if [ -z "${SINGBOX_VERSION:-}" ]; then
    SINGBOX_VERSION="1.13.13"
    warn "GitHub API не ответил — беру проверенную версию $SINGBOX_VERSION."
    warn "Само по себе это сигнал, что у коробки проблемы с доступом в сеть."
else
    ok "sing-box v${SINGBOX_VERSION}"
fi

info "Скачиваю sing-box..."
STMP=$(mktemp -d)
SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
# -f: без него curl сохраняет HTML-страницу ошибки как .tar.gz, и падает уже tar
# с невнятным сообщением. Плюс повторы — канал у коробки нестабильный.
DL_OK=false
for attempt in 1 2 3; do
    if curl -fsSL --max-time 180 "$SINGBOX_URL" -o "$STMP/sing-box.tar.gz"; then
        DL_OK=true; break
    fi
    warn "Загрузка не удалась (попытка $attempt из 3) — повторяю через 3 сек..."
    sleep 3
done
if ! $DL_OK; then
    rm -rf "$STMP"
    die "Не удалось скачать sing-box (3 попытки)." \
        "URL: $SINGBOX_URL — проверьте его вручную на коробке:  curl -I $SINGBOX_URL . Если ответа нет, а SSH работает — у коробки нет выхода в интернет (DNS/маршрут/NAT), а не проблема с GitHub."
fi
tar xzf "$STMP/sing-box.tar.gz" -C "$STMP" || die "Архив sing-box не распаковался." "Повторите запуск."
install -m 755 "$STMP/sing-box-${SINGBOX_VERSION}-linux-amd64/sing-box" /usr/local/bin/sing-box
rm -rf "$STMP"
/usr/local/bin/sing-box version >/dev/null 2>&1 \
    && ok "sing-box установлен и запускается" \
    || die "sing-box не запускается." "Повторите запуск скрипта."

mkdir -p /etc/sing-box /var/lib/sing-box
cat > /etc/sing-box/config.json << 'SBEOF'
{
  "log": {"level": "info"},
  "dns": {
    "servers": [
      {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"},
      {"type": "tcp", "tag": "direct-dns", "server": "8.8.8.8"}
    ],
    "rules": [
      {"query_type": ["A"], "server": "fakeip"},
      {"query_type": [64, 65], "action": "reject"}
    ],
    "final": "direct-dns",
    "strategy": "ipv4_only"
  },
  "inbounds": [{"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": 7893}],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "route": {
    "default_domain_resolver": "direct-dns",
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "outbound": "direct"}
    ],
    "final": "direct"
  },
  "experimental": {
    "cache_file": {"enabled": true, "store_fakeip": true, "path": "/var/lib/sing-box/cache.db"}
  }
}
SBEOF
ok "/etc/sing-box/config.json записан (FakeIP заглушка — до первого Route)"

info "Регистрирую сервис sing-box..."
cp "$SCRIPT_DIR/server/sing-box.service" /etc/systemd/system/sing-box.service
systemctl daemon-reload; systemctl enable sing-box -q
ok "sing-box сервис зарегистрирован (автозапуск)"

info "Копирую JackalRouter в $DEPLOY_DIR..."
mkdir -p "$DEPLOY_DIR"
cp "$SCRIPT_DIR/server/server.py" "$DEPLOY_DIR/server.py"
python3 -m venv "$DEPLOY_DIR/venv" || die "Не удалось создать venv." "sudo apt-get install -y python3-venv"
PYVER=$("$DEPLOY_DIR/venv/bin/python3" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "?")
info "Python в venv: $PYVER — ставлю fastapi/uvicorn/pydantic..."
"$DEPLOY_DIR/venv/bin/pip" install --quiet --upgrade pip wheel >/dev/null 2>&1 || true
# Версии НЕ прибиты жёстко: на новых Python (3.13/3.14) у старых pydantic нет
# готовых wheel, и pip уходит собирать pydantic-core из исходников через Rust/PyO3,
# где сборка падает ("interpreter version is newer than PyO3's maximum supported").
# Нижние границы + --prefer-binary заставляют pip взять готовый wheel под этот Python.
"$DEPLOY_DIR/venv/bin/pip" install --quiet --prefer-binary \
    "fastapi>=0.111" "uvicorn[standard]>=0.29" "pydantic>=2.7" || die \
    "Не удалось установить Python-пакеты (Python $PYVER)." \
    "Это НЕ проблема интернета: для Python $PYVER нет готовых пакетов и pip пытается компилировать их из исходников. Посмотрите ошибку выше. Обычно помогает системный python3 версии LTS (3.10–3.12). Вручную:  $DEPLOY_DIR/venv/bin/pip install fastapi 'uvicorn[standard]' pydantic"
cp "$SCRIPT_DIR/server/jackalrouter.service" /etc/systemd/system/jackalrouter.service
systemctl daemon-reload; systemctl enable jackalrouter -q
ok "JackalRouter API установлен (автозапуск)"

# ═══════════════════════════════════════════════════════════════════════════════
step 10 "Запуск и проверка сервисов"
# ═══════════════════════════════════════════════════════════════════════════════

info "Запускаю sing-box..."
systemctl restart sing-box; sleep 2
systemctl is-active sing-box -q \
    && ok "sing-box        — ${G}активен${N}" \
    || { warn "sing-box не запустился:"; journalctl -u sing-box -n 10 --no-pager 2>/dev/null || true; }

info "Проверяю точку доступа..."
iw dev "$LAN_IFACE" info 2>/dev/null | grep -qi 'type AP' \
    && ok "Wi-Fi точка      — ${G}раздаётся${N} (SSID \"$AP_SSID\")" \
    || warn "Точка доступа ещё поднимается — подождите ~10 сек и проверьте:  nmcli con up jackal-ap"

info "Проверяю dnsmasq..."
systemctl is-active dnsmasq -q \
    && ok "dnsmasq         — ${G}активен${N} (DHCP на $LAN_IFACE)" \
    || warn "dnsmasq ждёт $LAN_IFACE — поднимется автоматически (Restart=on-failure)."

info "Запускаю JackalRouter API..."
systemctl restart jackalrouter; sleep 3
if systemctl is-active jackalrouter -q; then
    ok "jackalrouter    — ${G}активен${N} (API :$SERVER_PORT)"
else
    err "JackalRouter не запустился:"; journalctl -u jackalrouter -n 15 --no-pager 2>/dev/null || true
    die "Сервис не запустился." "Изучите логи выше."
fi

# ═══════════════════════════════════════════════════════════════════════════════
# ИТОГ
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${G}╔══════════════════════════════════════════════╗${N}"
echo -e "${G}║${W}        УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!         ${G}║${N}"
echo -e "${G}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}Ubuntu теперь Wi-Fi ↔ Wi-Fi мост с защитой от утечек:${N}"
echo -e "  ${G}✓${N} Интернет через $WAN_IFACE (\"$WAN_SSID\")"
echo -e "  ${G}✓${N} Раздача \"${W}$AP_SSID${N}\" ($AP_BAND_LABEL, WPA2) → шлюз $LAN_IP"
echo -e "  ${G}✓${N} DNS/TCP/UDP QUIC/WebRTC → sing-box TProxy → SOCKS5 прокси"
echo -e "  ${G}✓${N} MSS clamp 1280, IPv6 заблокирован"
echo -e "  ${G}✓${N} sing-box v${SINGBOX_VERSION}, API http://${LAN_IP}:${SERVER_PORT}"
echo ""
echo -e "${B}╔══════════════════════════════════════════════╗${N}"
echo -e "${B}║${W}   ЧТО ДЕЛАТЬ ДАЛЬШЕ                        ${B}║${N}"
echo -e "${B}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}1.${N} На телефоне подключитесь к Wi-Fi:"
echo -e "   • Сеть:   ${W}$AP_SSID${N}"
echo -e "   • Пароль: ${W}$AP_PASS${N}"
echo ""
echo -e "${W}2.${N} На управляющем ПК (в этой же Wi-Fi сети) запустите ${W}JackalRouter клиент${N}:"
echo -e "   • IP коробки: ${C}${LAN_IP}${N}"
echo -e "   • Вставьте SOCKS5 прокси → ${G}Route${N} → ${G}⚡ Тест канала${N}"
echo ""
echo -e "${W}3.${N} Проверка с телефона: ${C}https://ipleak.net${N} — IP прокси, DNS 8.8.8.8"
echo ""
echo -e "──────────────────────────────────────────────"
echo -e "${W}Управление:${N}"
echo -e "  sudo systemctl status jackalrouter sing-box dnsmasq"
echo -e "  nmcli con up jackal-wan     # если пропал интернет"
echo -e "  nmcli con up jackal-ap      # если точка доступа не поднялась"
echo -e "  sudo journalctl -u sing-box -f"
echo -e "──────────────────────────────────────────────"
echo ""
