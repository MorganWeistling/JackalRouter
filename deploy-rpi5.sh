#!/bin/bash
# =============================================================================
#  JackalRouter — Автоматический деплой на Raspberry Pi 5
#  Запуск:  sudo bash deploy-rpi5.sh
#
#  Схема подключения (запомни, это важно):
#     • Wi-Fi Pi (wlan0)  → домашний интернет   (WAN — откуда Pi берёт сеть)
#     • Ethernet Pi (eth0) → технический роутер   (LAN — куда раздаём прокси)
#
#  Скрипт рассчитан на новичка: сам проверит совместимость, при необходимости
#  подключит Wi-Fi, всё настроит и объяснит, что делать дальше.
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_STEPS=8

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

# ── Шапка ─────────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e "${B}╔══════════════════════════════════════════════╗${N}"
echo -e "${B}║${W}     JackalRouter — Установка на Pi 5        ${B}║${N}"
echo -e "${B}║${C}  Прокси-шлюз (sing-box TProxy) для роутера  ${B}║${N}"
echo -e "${B}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}Как всё будет соединено:${N}"
echo -e "  ${C}Wi-Fi Raspberry Pi   → ваш домашний интернет${N}"
echo -e "  ${C}Ethernet Raspberry Pi → кабель в WAN-порт тех. роутера${N}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
step 1 "Проверка совместимости Raspberry Pi"
# ═══════════════════════════════════════════════════════════════════════════════

# ── root ──────────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    die "Скрипт должен запускаться от root." \
        "Выполните команду:  sudo bash deploy-rpi5.sh"
fi
ok "Права root — есть"

# ── Модель платы ──────────────────────────────────────────────────────────────
PI_MODEL="неизвестно"
if [ -f /proc/device-tree/model ]; then
    PI_MODEL=$(tr -d '\0' < /proc/device-tree/model)
fi
if echo "$PI_MODEL" | grep -qi "Raspberry Pi 5"; then
    ok "Плата: ${W}$PI_MODEL${N}"
elif echo "$PI_MODEL" | grep -qi "Raspberry Pi"; then
    warn "Это ${PI_MODEL} — не Pi 5, но обычно тоже работает. Продолжаем."
else
    warn "Похоже, это не Raspberry Pi ($PI_MODEL). Продолжаем на свой риск."
fi

# ── Архитектура (нужна для sing-box) ─────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|arm64) SB_ARCH="arm64"; ok "Архитектура: 64-бит ARM (aarch64) — оптимально" ;;
    armv7l|armhf)  SB_ARCH="armv7"; warn "32-бит ОС ($ARCH). Работает, но лучше 64-бит Raspberry Pi OS." ;;
    x86_64|amd64)  SB_ARCH="amd64"; warn "Это x86_64, не ARM — тоже поставим." ;;
    *) die "Неизвестная архитектура: $ARCH." \
           "Нужна 64-бит Raspberry Pi OS (aarch64). Перепрошейте карту через Raspberry Pi Imager." ;;
esac

# ── ОС ────────────────────────────────────────────────────────────────────────
if grep -qiE 'raspbian|raspberry' /etc/os-release 2>/dev/null; then
    ok "ОС: Raspberry Pi OS"
elif grep -qi 'debian' /etc/os-release 2>/dev/null; then
    ok "ОС: Debian-совместимая — подходит"
else
    warn "ОС не Raspberry Pi OS / Debian — возможны проблемы. Продолжаем."
fi

# ── Проверка поддержки TProxy ядром (ключевая совместимость) ─────────────────
info "Проверяю поддержку TProxy в ядре..."
modprobe xt_TPROXY 2>/dev/null || true
modprobe nf_tproxy_ipv4 2>/dev/null || true
iptables -t mangle -N JR_TPTEST 2>/dev/null || iptables -t mangle -F JR_TPTEST 2>/dev/null || true
if iptables -t mangle -A JR_TPTEST -p tcp -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1 2>/dev/null; then
    ok "Ядро поддерживает TPROXY"
    iptables -t mangle -F JR_TPTEST 2>/dev/null || true
    iptables -t mangle -X JR_TPTEST 2>/dev/null || true
else
    iptables -t mangle -F JR_TPTEST 2>/dev/null || true
    iptables -t mangle -X JR_TPTEST 2>/dev/null || true
    die "Ядро не поддерживает TPROXY (модуль xt_TPROXY недоступен)." \
        "Обновите систему:  sudo apt update && sudo apt full-upgrade -y && sudo reboot  — затем запустите скрипт снова."
fi
# Чтобы модуль поднимался после перезагрузки:
echo -e "xt_TPROXY\nnf_tproxy_ipv4" > /etc/modules-load.d/jackalrouter.conf 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════════════
step 2 "Сеть: интернет по Wi-Fi (WAN) и порт для роутера (LAN)"
# ═══════════════════════════════════════════════════════════════════════════════

NM_ACTIVE=false
systemctl is-active NetworkManager -q 2>/dev/null && NM_ACTIVE=true

# ── Разблокируем Wi-Fi (частая проблема у новичков) ──────────────────────────
rfkill unblock wifi 2>/dev/null || true
rfkill unblock all 2>/dev/null || true

# ── Проверяем интернет; если нет — предлагаем настроить Wi-Fi ─────────────────
info "Проверяю доступ в интернет..."
if ! have_net; then
    warn "Интернета нет."
    if [ -e /sys/class/net/wlan0 ] && $NM_ACTIVE && [ -t 0 ]; then
        echo ""
        echo -e "${W}Настроим Wi-Fi для Raspberry Pi.${N}"
        echo -e "${C}Доступные сети рядом:${N}"
        nmcli -t -f SSID,SIGNAL dev wifi list ifname wlan0 2>/dev/null \
            | awk -F: 'NF && $1!=""{printf "   • %s  (сигнал %s)\n",$1,$2}' | sort -u | head -12 || true
        echo ""
        read -r -p "   Название Wi-Fi (SSID): " WIFI_SSID
        read -r -s -p "   Пароль Wi-Fi: " WIFI_PASS; echo ""
        info "Подключаюсь к \"$WIFI_SSID\"..."
        nmcli dev wifi connect "$WIFI_SSID" password "$WIFI_PASS" ifname wlan0 2>/dev/null \
            || warn "Не удалось подключиться — проверьте имя/пароль сети."
        sleep 5
    fi
    if ! have_net; then
        die "Нет доступа в интернет." \
            "Подключите Raspberry Pi к домашнему Wi-Fi (через рабочий стол или 'sudo raspi-config' → System → Wireless LAN) и запустите скрипт снова."
    fi
fi
ok "Интернет доступен"

# ── WAN = интерфейс с интернетом (обычно wlan0) ──────────────────────────────
WAN_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
[ -z "$WAN_IFACE" ] && die "Не удалось определить интернет-интерфейс." "Проверьте:  ip route"
WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
ok "Интернет (WAN): ${W}$WAN_IFACE${N} ($WAN_IP)"

# ── Статический IP для самой Pi (стабильный адрес для клиента) ────────────────
# По DHCP адрес Pi может смениться после ребута роутера, и клиент перестанет её
# находить. Фиксируем текущий Wi-Fi IP как статический (тот же адрес → ничего не рвём).
info "Статический IP Raspberry Pi (адрес, к которому подключается клиент)..."
WAN_CIDR=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
WAN_PREFIX="${WAN_CIDR#*/}"; [ "$WAN_PREFIX" = "$WAN_CIDR" ] && WAN_PREFIX=24
WAN_GW=$(ip route show default | awk '/default/{print $3; exit}')
STATIC_IP="$WAN_IP"
if [ -t 0 ]; then
    echo -e "    ${C}Текущий IP Pi: ${W}$WAN_IP${N}${C} (выдан роутером по Wi-Fi, может смениться).${N}"
    read -r -p "    Зафиксировать статически? [Enter=да] / другой IP / n=оставить DHCP: " ANS || ANS=""
    case "$ANS" in
        ""|[Yy]*) STATIC_IP="$WAN_IP" ;;
        [Nn]*)    STATIC_IP="" ;;
        *)        STATIC_IP="$ANS" ;;
    esac
fi
if [ -z "$STATIC_IP" ] || [ -z "$WAN_GW" ]; then
    warn "Оставлен DHCP — IP Pi может смениться. Клиент придётся перенастраивать."
elif $NM_ACTIVE; then
    WAN_CON=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$WAN_IFACE" '$2==d{print $1; exit}')
    if [ -n "$WAN_CON" ]; then
        nmcli con mod "$WAN_CON" ipv4.method manual \
            ipv4.addresses "${STATIC_IP}/${WAN_PREFIX}" ipv4.gateway "$WAN_GW" \
            ipv4.dns "8.8.8.8 1.1.1.1" 2>/dev/null \
            && nmcli con up "$WAN_CON" 2>/dev/null || warn "nmcli не смог применить — оставляю как есть."
        sleep 2
        WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
        ok "Статический IP Pi: ${W}$WAN_IP${N} (шлюз $WAN_GW, NetworkManager)"
    else
        warn "Не нашёл Wi-Fi соединение в NetworkManager — оставляю DHCP."
    fi
elif [ -f /etc/dhcpcd.conf ]; then
    sed -i '/# JackalRouter WAN/,/^$/d' /etc/dhcpcd.conf 2>/dev/null || true
    cat >> /etc/dhcpcd.conf << EOF

# JackalRouter WAN — не менять вручную
interface $WAN_IFACE
static ip_address=${STATIC_IP}/${WAN_PREFIX}
static routers=${WAN_GW}
static domain_name_servers=8.8.8.8 1.1.1.1
EOF
    systemctl restart dhcpcd 2>/dev/null || true
    sleep 2
    WAN_IP="$STATIC_IP"
    ok "Статический IP Pi: ${W}$WAN_IP${N} (шлюз $WAN_GW, dhcpcd)"
else
    warn "Не найден NetworkManager/dhcpcd — статику назначить нечем, оставляю DHCP."
fi

# ── Проверка DNS (после смены на manual стуб systemd-resolved иногда не резолвит) ─
if ! getent hosts google.com >/dev/null 2>&1; then
    warn "DNS не резолвит — исправляю resolv.conf..."
    if [ -f /run/systemd/resolve/resolv.conf ]; then
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    else
        printf 'nameserver %s\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n' "${WAN_GW:-8.8.8.8}" > /etc/resolv.conf
    fi
    getent hosts google.com >/dev/null 2>&1 && ok "DNS восстановлен" \
        || warn "DNS всё ещё не резолвит — проверьте вручную:  nslookup google.com"
else
    ok "DNS резолвит корректно"
fi

# ── LAN = eth0 (в него воткнём кабель к тех. роутеру) ─────────────────────────
if [ "$WAN_IFACE" = "eth0" ]; then
    die "Интернет идёт по кабелю (eth0), но этот порт нужен для тех. роутера." \
        "Подключите Pi к интернету по Wi-Fi, освободите Ethernet-порт под роутер и запустите скрипт снова."
fi
if [ -e /sys/class/net/eth0 ]; then
    LAN_IFACE="eth0"
else
    LAN_IFACE=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
        | grep -E '^(eth|en)' | grep -v "^${WAN_IFACE}$" | head -1 || true)
fi
[ -z "${LAN_IFACE:-}" ] && die "Не найден Ethernet-порт (eth0) для роутера." \
    "Проверьте, что это Raspberry Pi с сетевым портом:  ip link show"
LAN_STATE=$(ip link show "$LAN_IFACE" 2>/dev/null | grep -oP 'state \K\w+' || echo "?")
ok "Порт для роутера (LAN): ${W}$LAN_IFACE${N} (состояние: $LAN_STATE)"
[ "$LAN_STATE" != "UP" ] && warn "Кабель в Ethernet ещё не воткнут — это нормально, воткнёте после установки."

# ── Прописываем LAN-интерфейс в server.py ────────────────────────────────────
info "Прописываю $LAN_IFACE в конфиг сервера..."
sed -i "s/INT_IFACE *= *\"[^\"]*\"/INT_IFACE    = \"$LAN_IFACE\"/" "$SCRIPT_DIR/server/server.py"
ok "Интерфейс $LAN_IFACE записан в server.py"

# ═══════════════════════════════════════════════════════════════════════════════
step 3 "Установка пакетов"
# ═══════════════════════════════════════════════════════════════════════════════

info "Обновляю список пакетов (может занять до минуты)..."
apt-get update -qq 2>/dev/null || warn "Некоторые репозитории недоступны — не критично."
ok "Список пакетов обновлён"

echo ""
info "Устанавливаю пакеты:"
echo -e "    ${C}• python3, python3-venv — сервер управления${N}"
echo -e "    ${C}• dnsmasq               — DHCP-сервер для роутера${N}"
echo -e "    ${C}• iptables, iptables-persistent — правила и их сохранение${N}"
echo -e "    ${C}• network-manager       — статический IP на Ethernet${N}"
echo -e "    ${C}• curl, wget, ethtool, rfkill${N}"
echo ""

# preseed iptables-persistent, чтобы не задавал вопросов
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null || true

DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing \
    python3 python3-venv dnsmasq iptables iptables-persistent \
    curl wget ethtool rfkill 2>/dev/null || die \
    "Не удалось установить пакеты." \
    "Проверьте интернет и повторите запуск скрипта."
ok "Все пакеты установлены"

# ═══════════════════════════════════════════════════════════════════════════════
step 4 "Статический IP ${LAN_IP} на $LAN_IFACE"
# ═══════════════════════════════════════════════════════════════════════════════

info "Назначаю статический IP ${LAN_IP}/24 на $LAN_IFACE..."
if $NM_ACTIVE; then
    # Raspberry Pi OS Bookworm — NetworkManager
    nmcli con delete jackal-lan 2>/dev/null || true
    nmcli con add type ethernet ifname "$LAN_IFACE" con-name jackal-lan \
        ipv4.method manual ipv4.addresses "${LAN_IP}/24" \
        ipv4.never-default yes connection.autoconnect yes 2>/dev/null || \
        warn "nmcli не смог создать профиль — назначу IP напрямую."
    nmcli con up jackal-lan 2>/dev/null || true
    ip addr replace "${LAN_IP}/24" dev "$LAN_IFACE" 2>/dev/null || true
    ok "IP назначен через NetworkManager"
elif [ -f /etc/dhcpcd.conf ]; then
    # Старые Raspberry Pi OS — dhcpcd
    sed -i '/# JackalRouter LAN/,/^$/d' /etc/dhcpcd.conf 2>/dev/null || true
    cat >> /etc/dhcpcd.conf << EOF

# JackalRouter LAN — не менять вручную
interface $LAN_IFACE
static ip_address=${LAN_IP}/24
nolink
EOF
    ip addr flush dev "$LAN_IFACE" 2>/dev/null || true
    ip addr add "${LAN_IP}/24" dev "$LAN_IFACE" 2>/dev/null || true
    ip link set "$LAN_IFACE" up 2>/dev/null || true
    systemctl restart dhcpcd 2>/dev/null || true
    ok "IP назначен через dhcpcd"
else
    ip addr replace "${LAN_IP}/24" dev "$LAN_IFACE" 2>/dev/null || true
    ip link set "$LAN_IFACE" up 2>/dev/null || true
    warn "Не найден NetworkManager/dhcpcd — назначил IP напрямую (может слететь после ребута)."
fi

CURRENT_IP=$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | head -1)
[ -n "$CURRENT_IP" ] && ok "Текущий IP на $LAN_IFACE: ${W}$CURRENT_IP${N}" \
    || warn "IP пока не виден — появится при подключении кабеля"

# ═══════════════════════════════════════════════════════════════════════════════
step 5 "DHCP-сервер для роутера (dnsmasq)"
# ═══════════════════════════════════════════════════════════════════════════════

info "Настраиваю dnsmasq (DHCP + DNS)..."
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
ok "DHCP + DNS конфиг записан (диапазон ${DHCP_FROM}–${DHCP_TO}, шлюз ${LAN_IP})"

# dnsmasq стартует раньше, чем поднимается $LAN_IFACE, и падает с "unknown
# interface". Restart=on-failure + StartLimitIntervalSec=0 → повторяет старт
# бесконечно, пока интерфейс не появится (переживает перезагрузку Pi).
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
systemctl enable dnsmasq -q 2>/dev/null || true
ok "dnsmasq устойчив к порядку загрузки (переживает ребут)"

systemctl restart dnsmasq || die \
    "dnsmasq не запустился." "Логи:  sudo journalctl -u dnsmasq -n 30"
ok "DHCP-сервер запущен"

# ═══════════════════════════════════════════════════════════════════════════════
step 6 "iptables — TProxy маршрутизация и защита от утечек"
# ═══════════════════════════════════════════════════════════════════════════════

info "Включаю IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 -q
grep -q "net.ipv4.ip_forward" /etc/sysctl.conf \
    && sed -i 's/.*net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf \
    || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
ok "IP forwarding включён (постоянно)"

info "Настраиваю policy routing (fwmark 1 → local, для TProxy)..."
ip rule del fwmark 1 table 100 2>/dev/null || true
ip rule add fwmark 1 table 100
ip route del local default dev lo table 100 2>/dev/null || true
ip route add local default dev lo table 100
ok "Policy routing: fwmark 1 → таблица 100"

# ── ВАЖНО: сделать policy routing постоянным ─────────────────────────────────
# netfilter-persistent сохраняет ТОЛЬКО iptables. Правила "ip rule"/"ip route"
# после перезагрузки исчезают, и тогда TPROXY метит пакеты меткой 1, а доставить
# их локально ядру нечем — трафик клиентов молча пропадает. Снаружи это выглядит
# как "раздаётся, DHCP выдаёт адрес, но интернета нет". Поэтому вешаем oneshot-
# юнит, который восстанавливает их при каждой загрузке до старта sing-box.
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

# ── MSS clamp 1280 ────────────────────────────────────────────────────────────
info "MSS clamp 1280 на $LAN_IFACE..."
iptables -t mangle -D PREROUTING -i "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1280 2>/dev/null || true
iptables -t mangle -A PREROUTING -i "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1280
iptables -t mangle -D POSTROUTING -o "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1280 2>/dev/null || true
iptables -t mangle -A POSTROUTING -o "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1280
ok "MSS clamp 1280 — ingress + egress"

# ── SING_BOX chain (TProxy) ──────────────────────────────────────────────────
info "Создаю TProxy цепочку SING_BOX..."
iptables -t mangle -N SING_BOX 2>/dev/null || true
iptables -t mangle -F SING_BOX
for net in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 \
           172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t mangle -A SING_BOX -d "$net" -j RETURN
done
iptables -t mangle -A SING_BOX -p udp -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1
iptables -t mangle -A SING_BOX -p tcp -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1
iptables -t mangle -D PREROUTING -i "$LAN_IFACE" -j SING_BOX 2>/dev/null || true
iptables -t mangle -A PREROUTING -i "$LAN_IFACE" -j SING_BOX
ok "TProxy: весь UDP+TCP → sing-box :$SINGBOX_PORT (QUIC через прокси, FakeIP)"

# ── MASQUERADE + FORWARD ──────────────────────────────────────────────────────
info "MASQUERADE и FORWARD..."
# WAN-сторона намеренно НЕ привязана к имени интерфейса (! -o LAN_IFACE, а не
# -o WAN_IFACE): если интернет-адаптер сменится (переключение Wi-Fi сети,
# другой кабель/донгл, смена имени интерфейса) — правила не придётся
# переприменять, всё, что не в LAN, продолжит маскироваться автоматически.
iptables -t nat -D POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true
iptables -t nat -C POSTROUTING ! -o "$LAN_IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING ! -o "$LAN_IFACE" -j MASQUERADE
iptables -D FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" \
    -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -C FORWARD -i "$LAN_IFACE" ! -o "$LAN_IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$LAN_IFACE" ! -o "$LAN_IFACE" -j ACCEPT
iptables -C FORWARD ! -i "$LAN_IFACE" -o "$LAN_IFACE" \
    -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD ! -i "$LAN_IFACE" -o "$LAN_IFACE" \
    -m state --state RELATED,ESTABLISHED -j ACCEPT
ok "MASQUERADE + FORWARD настроены (переживут смену WAN-сети/адаптера)"

# ── IPv6 leak prevention ──────────────────────────────────────────────────────
info "Блокирую IPv6 из LAN..."
ip6tables -D FORWARD -i "$LAN_IFACE" -j DROP 2>/dev/null || true
ip6tables -D FORWARD -o "$LAN_IFACE" -j DROP 2>/dev/null || true
ip6tables -A FORWARD -i "$LAN_IFACE" -j DROP
ip6tables -A FORWARD -o "$LAN_IFACE" -j DROP
ip6tables -D INPUT -i "$LAN_IFACE" -p ipv6-icmp -j DROP 2>/dev/null || true
ip6tables -A INPUT -i "$LAN_IFACE" -p ipv6-icmp -j DROP
ok "IPv6 FORWARD DROP — устройства не получат IPv6"

# ── GRO off ───────────────────────────────────────────────────────────────────
info "Отключаю GRO/GSO/TSO на $LAN_IFACE..."
ethtool -K "$LAN_IFACE" gro off gso off tso off lro off 2>/dev/null || \
    warn "ethtool не смог отключить offload — не критично"
ok "GRO/GSO/TSO отключены"

info "Сохраняю правила iptables..."
netfilter-persistent save -q 2>/dev/null \
    || { mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6; }
ok "Правила сохранены (переживут перезагрузку)"

# ═══════════════════════════════════════════════════════════════════════════════
step 7 "Установка sing-box (ARM64) и JackalRouter"
# ═══════════════════════════════════════════════════════════════════════════════

info "Определяю последнюю версию sing-box..."
SINGBOX_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    2>/dev/null | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' | head -1 || true)
[ -z "${SINGBOX_VERSION:-}" ] && SINGBOX_VERSION="1.13.13"
ok "sing-box v${SINGBOX_VERSION}  (сборка linux-${SB_ARCH})"

info "Скачиваю sing-box для ${SB_ARCH}..."
STMP=$(mktemp -d)
SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}.tar.gz"
# -f: без него curl сохраняет HTML-страницу ошибки как .tar.gz, и падает уже tar
# с невнятным сообщением. Плюс повторы — канал бывает нестабильным.
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
        "URL: $SINGBOX_URL — проверьте его вручную:  curl -I $SINGBOX_URL"
fi
tar xzf "$STMP/sing-box.tar.gz" -C "$STMP" || \
    die "Архив sing-box повреждён/не подошёл под архитектуру ${SB_ARCH}." "Повторите запуск."
install -m 755 "$STMP/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box
rm -rf "$STMP"
# самопроверка бинарника
if /usr/local/bin/sing-box version >/dev/null 2>&1; then
    ok "sing-box установлен и запускается на этой архитектуре"
else
    die "sing-box не запускается (неверная архитектура?)." \
        "Убедитесь, что стоит 64-бит Raspberry Pi OS, и повторите."
fi

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

info "Регистрирую systemd-сервис sing-box..."
cp "$SCRIPT_DIR/server/sing-box.service" /etc/systemd/system/sing-box.service
systemctl daemon-reload
systemctl enable sing-box -q
ok "sing-box сервис зарегистрирован (автозапуск)"

# ── JackalRouter API ──────────────────────────────────────────────────────────
info "Копирую файлы в $DEPLOY_DIR..."
mkdir -p "$DEPLOY_DIR"
cp "$SCRIPT_DIR/server/server.py" "$DEPLOY_DIR/server.py"
ok "server.py скопирован"

info "Создаю Python-окружение (venv)..."
python3 -m venv "$DEPLOY_DIR/venv" || die \
    "Не удалось создать Python venv." "Попробуйте: sudo apt-get install -y python3-venv"
ok "Python venv создан"

info "Устанавливаю Python-зависимости (fastapi, uvicorn)..."
# Версии НЕ прибиты жёстко: на новых Python (3.13/3.14) у старых pydantic нет
# готовых wheel, и pip уходит собирать pydantic-core из исходников через Rust/PyO3,
# где сборка падает ("interpreter version is newer than PyO3's maximum supported").
# Нижние границы + --prefer-binary заставляют pip взять готовый wheel под этот Python.
"$DEPLOY_DIR/venv/bin/pip" install --quiet --prefer-binary \
    "fastapi>=0.111" "uvicorn[standard]>=0.29" "pydantic>=2.7" || die \
    "Не удалось установить Python-пакеты." "Проверьте интернет и повторите."
ok "Зависимости установлены"

info "Регистрирую systemd-сервис JackalRouter..."
cp "$SCRIPT_DIR/server/jackalrouter.service" /etc/systemd/system/jackalrouter.service
systemctl daemon-reload
systemctl enable jackalrouter -q
ok "Сервис зарегистрирован (автозапуск при старте)"

# ═══════════════════════════════════════════════════════════════════════════════
step 8 "Запуск и проверка сервисов"
# ═══════════════════════════════════════════════════════════════════════════════

info "Запускаю sing-box..."
systemctl restart sing-box
sleep 2
systemctl is-active sing-box -q \
    && ok "sing-box        — ${G}активен${N} (TProxy :$SINGBOX_PORT)" \
    || { warn "sing-box не запустился. Логи:"; journalctl -u sing-box -n 10 --no-pager 2>/dev/null || true; }

info "Проверяю dnsmasq..."
systemctl is-active dnsmasq -q \
    && ok "dnsmasq         — ${G}активен${N} (DHCP на $LAN_IFACE)" \
    || { err "dnsmasq не запустился."; journalctl -u dnsmasq -n 5 --no-pager 2>/dev/null || true; }

info "Запускаю JackalRouter API..."
systemctl restart jackalrouter
sleep 3
if systemctl is-active jackalrouter -q; then
    ok "jackalrouter    — ${G}активен${N} (API на порту $SERVER_PORT)"
else
    err "JackalRouter не запустился. Логи:"
    journalctl -u jackalrouter -n 15 --no-pager 2>/dev/null || true
    die "Сервис не запустился." "Изучите логи выше."
fi

sleep 1
API_STATUS=$(curl -s --max-time 3 "http://localhost:${SERVER_PORT}/status" 2>/dev/null || echo "")
echo "$API_STATUS" | grep -q "sing_box" \
    && ok "API отвечает: $API_STATUS" \
    || warn "API пока не отвечает — возможно ещё стартует"

# ═══════════════════════════════════════════════════════════════════════════════
# ИТОГ
# ═══════════════════════════════════════════════════════════════════════════════

SERVER_IP=$(ip -4 addr show "$WAN_IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)

echo ""
echo -e "${G}╔══════════════════════════════════════════════╗${N}"
echo -e "${G}║${W}        УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!         ${G}║${N}"
echo -e "${G}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}Защита от утечек на подключённых устройствах:${N}"
echo -e "  ${G}✓${N} DNS :53          → FakeIP → домен к прокси (нет IP-утечки)"
echo -e "  ${G}✓${N} TCP (весь)       → sing-box TProxy → SOCKS5 прокси"
echo -e "  ${G}✓${N} UDP QUIC :443    → SOCKS5 UDP ASSOCIATE (нет fraud-очков)"
echo -e "  ${G}✓${N} WebRTC/STUN      → через прокси"
echo -e "  ${G}✓${N} MSS clamp 1280   → нет проблем с PMTUD"
echo -e "  ${G}✓${N} IPv6             → заблокирован"
echo ""
echo -e "${W}Что установлено:${N}"
echo -e "  • sing-box v${SINGBOX_VERSION} (${SB_ARCH})  → /usr/local/bin/sing-box"
echo -e "  • JackalRouter API  → http://${SERVER_IP}:${SERVER_PORT}"
echo -e "  • LAN-шлюз роутера → ${LAN_IP} (порт $LAN_IFACE)"
echo -e "  • DHCP-диапазон    → ${DHCP_FROM} – ${DHCP_TO}"

echo ""
echo -e "${B}╔══════════════════════════════════════════════╗${N}"
echo -e "${B}║${W}   ЧТО ДЕЛАТЬ ДАЛЬШЕ (по шагам)             ${B}║${N}"
echo -e "${B}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}1.${N} Возьмите ${W}Ethernet-кабель${N} и соедините:"
echo -e "   ${C}Сетевой порт Raspberry Pi  ──кабель──▶  WAN-порт (Internet) тех. роутера${N}"
echo -e "   ${Y}(Wi-Fi роутера НЕ трогаем — интернет Pi берёт по своему Wi-Fi)${N}"
echo ""
echo -e "${W}2.${N} Подключите телефон к ${W}Wi-Fi технического роутера${N}"
echo ""
echo -e "${W}3.${N} Откройте в браузере веб-интерфейс роутера:"
echo -e "   ${Y}→ http://192.168.0.1${N}   (TP-Link, D-Link, Netgear, Xiaomi)"
echo -e "   ${Y}→ http://192.168.1.1${N}   (ASUS, Keenetic, Zyxel, Huawei)"
echo ""
echo -e "${W}4.${N} Найдите ${Y}WAN / Интернет / Тип подключения${N} → выберите ${G}DHCP${N} (Динамический IP)"
echo ""
echo -e "${W}5.${N} Сохраните, подождите 15 секунд"
echo ""
echo -e "${W}6.${N} На Windows запустите ${W}JackalRouter клиент${N}:"
echo -e "   • IP Raspberry Pi: ${C}${SERVER_IP}${N}"
echo -e "   • Вставьте строку SOCKS5 прокси → ${G}Route${N} → ${G}⚡ Тест канала${N}"
echo ""
echo -e "${W}7.${N} Проверка с телефона: ${C}https://ipleak.net${N} — IP прокси, DNS 8.8.8.8"
echo ""
echo -e "──────────────────────────────────────────────"
echo -e "${W}Управление:${N}"
echo -e "  sudo systemctl status jackalrouter"
echo -e "  sudo systemctl status sing-box"
echo -e "  sudo journalctl -u sing-box -f"
echo -e "──────────────────────────────────────────────"
echo ""
