#!/bin/bash
# =============================================================================
#  JackalRouter — Деплой на Raspberry Pi 5 в режиме Wi-Fi ТОЧКИ ДОСТУПА
#  Запуск:  sudo bash deploy-rpi5-ap.sh
#
#  Топология (Pi = самостоятельный Wi-Fi роутер, тех. роутер НЕ нужен):
#     • Ethernet (eth0)  → кабель в домашний роутер   (WAN — интернет)
#     • Wi-Fi (wlan0)    → Pi раздаёт свою Wi-Fi сеть  (LAN — телефоны сюда)
#
#  Отличие от deploy-rpi5.sh: там наоборот (интернет по Wi-Fi, раздача по кабелю
#  через тех. роутер). Здесь Pi сам является Wi-Fi точкой доступа.
#
#  Рассчитан на новичка: проверки совместимости, спросит имя/пароль Wi-Fi,
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
LAN_IFACE="wlan0"     # Wi-Fi точка доступа (раздача)
WAN_IFACE="eth0"      # Ethernet-кабель (интернет)
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
echo -e "${B}║${W}    JackalRouter — Pi как Wi-Fi роутер       ${B}║${N}"
echo -e "${B}║${C}  Интернет по кабелю → раздача по Wi-Fi      ${B}║${N}"
echo -e "${B}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}Как всё будет соединено:${N}"
echo -e "  ${C}Кабель: домашний роутер → Ethernet-порт Pi   (интернет)${N}"
echo -e "  ${C}Wi-Fi Pi (wlan0)      → сюда подключаете телефон${N}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
step 1 "Проверка совместимости Raspberry Pi"
# ═══════════════════════════════════════════════════════════════════════════════

[ "$(id -u)" -ne 0 ] && die "Скрипт должен запускаться от root." "Выполните:  sudo bash deploy-rpi5-ap.sh"
ok "Права root — есть"

PI_MODEL="неизвестно"
[ -f /proc/device-tree/model ] && PI_MODEL=$(tr -d '\0' < /proc/device-tree/model)
if echo "$PI_MODEL" | grep -qi "Raspberry Pi 5"; then
    ok "Плата: ${W}$PI_MODEL${N}"
elif echo "$PI_MODEL" | grep -qi "Raspberry Pi"; then
    warn "Это ${PI_MODEL} — не Pi 5, но обычно тоже работает."
else
    warn "Похоже, это не Raspberry Pi ($PI_MODEL). Продолжаем на свой риск."
fi

ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|arm64) SB_ARCH="arm64"; ok "Архитектура: 64-бит ARM — оптимально" ;;
    armv7l|armhf)  SB_ARCH="armv7"; warn "32-бит ОС ($ARCH). Работает, но лучше 64-бит Raspberry Pi OS." ;;
    x86_64|amd64)  SB_ARCH="amd64"; warn "Это x86_64, не ARM — тоже поставим." ;;
    *) die "Неизвестная архитектура: $ARCH." "Нужна 64-бит Raspberry Pi OS. Перепрошейте карту через Raspberry Pi Imager." ;;
esac

if grep -qiE 'raspbian|raspberry' /etc/os-release 2>/dev/null; then
    ok "ОС: Raspberry Pi OS"
elif grep -qi 'debian' /etc/os-release 2>/dev/null; then
    ok "ОС: Debian-совместимая — подходит"
else
    warn "ОС не Raspberry Pi OS / Debian — возможны проблемы."
fi

# ── NetworkManager обязателен для AP-режима на Bookworm ───────────────────────
if ! systemctl is-active NetworkManager -q 2>/dev/null; then
    die "NetworkManager не активен — он нужен для Wi-Fi точки доступа." \
        "Установите/включите:  sudo apt install -y network-manager && sudo systemctl enable --now NetworkManager  (или используйте Raspberry Pi OS Bookworm)."
fi
ok "NetworkManager активен (нужен для точки доступа)"

# ── Поддержка TProxy ядром ────────────────────────────────────────────────────
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

# ── Наличие обоих интерфейсов ────────────────────────────────────────────────
[ -e /sys/class/net/eth0 ]  || die "Нет Ethernet-порта (eth0)." "Нужен Raspberry Pi с сетевым портом для интернета по кабелю."
[ -e /sys/class/net/wlan0 ] || die "Нет Wi-Fi адаптера (wlan0)." "Нужен Pi со встроенным Wi-Fi (Pi 3/4/5)."
ok "Интерфейсы на месте: eth0 (кабель) + wlan0 (Wi-Fi)"

# ═══════════════════════════════════════════════════════════════════════════════
step 2 "Интернет по кабелю (eth0) и параметры Wi-Fi сети"
# ═══════════════════════════════════════════════════════════════════════════════

info "Проверяю, что интернет приходит по кабелю (eth0)..."
DEF_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}' || true)
if ! have_net; then
    die "Нет интернета." \
        "Воткните Ethernet-кабель: домашний роутер → сетевой порт Raspberry Pi, дождитесь линка и запустите скрипт снова."
fi
if [ "$DEF_IFACE" != "eth0" ]; then
    die "Интернет идёт не по кабелю, а через '$DEF_IFACE'." \
        "Wi-Fi (wlan0) нужен для раздачи, поэтому интернет должен приходить по кабелю в eth0. Отключите Wi-Fi-клиент, воткните кабель в eth0 и запустите скрипт снова."
fi
WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
ok "Интернет (WAN): ${W}$WAN_IFACE${N} ($WAN_IP)"

# ── Параметры создаваемой Wi-Fi сети ─────────────────────────────────────────
if [ -t 0 ]; then
    echo ""
    echo -e "${W}Настройки Wi-Fi сети, которую будет раздавать Raspberry Pi:${N}"
    read -r -p "   Имя сети (SSID) [JackalRouter]: " AP_SSID; AP_SSID=${AP_SSID:-JackalRouter}
    while :; do
        read -r -s -p "   Пароль Wi-Fi (минимум 8 символов): " AP_PASS; echo ""
        [ "${#AP_PASS}" -ge 8 ] && break
        echo -e "   ${Y}Пароль слишком короткий — нужно не меньше 8 символов.${N}"
    done
    read -r -p "   Код страны для Wi-Fi [US]: " COUNTRY; COUNTRY=${COUNTRY:-US}
else
    AP_SSID="JackalRouter"; AP_PASS="Jackal$(date +%s | tail -c 6)"; COUNTRY="US"
    warn "Не интерактивно — задал: SSID=${AP_SSID}, пароль=${AP_PASS} (ОБЯЗАТЕЛЬНО смените!)"
fi
ok "Wi-Fi сеть: SSID \"${W}$AP_SSID${N}\", страна $COUNTRY"

# ── Прописываем LAN-интерфейс в server.py ────────────────────────────────────
info "Прописываю $LAN_IFACE в конфиг сервера..."
sed -i "s/INT_IFACE *= *\"[^\"]*\"/INT_IFACE    = \"$LAN_IFACE\"/" "$SCRIPT_DIR/server/server.py"
ok "Интерфейс $LAN_IFACE записан в server.py"

# ═══════════════════════════════════════════════════════════════════════════════
step 3 "Установка пакетов"
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
step 4 "Создание Wi-Fi точки доступа на $LAN_IFACE"
# ═══════════════════════════════════════════════════════════════════════════════

info "Разблокирую Wi-Fi и задаю регион ($COUNTRY)..."
rfkill unblock wifi 2>/dev/null || true
rfkill unblock all 2>/dev/null || true
raspi-config nonint do_wifi_country "$COUNTRY" 2>/dev/null || iw reg set "$COUNTRY" 2>/dev/null || true
ok "Wi-Fi разблокирован, регион $COUNTRY"

info "Создаю точку доступа \"$AP_SSID\" (WPA2) с IP $LAN_IP..."
nmcli con delete jackal-ap 2>/dev/null || true
nmcli con add type wifi ifname "$LAN_IFACE" con-name jackal-ap ssid "$AP_SSID" 2>/dev/null \
    || die "Не удалось создать Wi-Fi соединение." "Проверьте wlan0:  ip link show wlan0"
nmcli con modify jackal-ap \
    802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel 7 \
    ipv4.method manual ipv4.addresses "${LAN_IP}/24" ipv4.never-default yes \
    wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$AP_PASS" \
    connection.autoconnect yes 2>/dev/null \
    || die "Не удалось настроить точку доступа." "Проверьте, что Wi-Fi поддерживает режим AP:  iw list | grep -A6 'Supported interface modes'"
nmcli con up jackal-ap 2>/dev/null || warn "Точка доступа не поднялась сразу — проверю в конце."
sleep 3

if iw dev "$LAN_IFACE" info 2>/dev/null | grep -qi 'type AP'; then
    ok "Точка доступа активна: SSID \"${W}$AP_SSID${N}\", IP $LAN_IP"
else
    warn "wlan0 пока не в режиме AP — иногда поднимается через 5–10 секунд после старта."
fi

# ═══════════════════════════════════════════════════════════════════════════════
step 5 "DHCP-сервер для Wi-Fi клиентов (dnsmasq)"
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

# Устойчивость к порядку загрузки: dnsmasq повторяет старт, пока wlan0 (AP) не поднимется
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
# и поднимает СВОЙ dnsmasq на ${LAN_IP}:53, даже если в профиле явно стоит
# ipv4.method manual. Наш системный тогда не может занять порт, падает с
# "Address already in use", а Restart=on-failure крутит его бесконечно (на
# живой коробке в похожей ситуации досчитало до 402 перезапусков подряд).
# Драться за порт бессмысленно: DHCP от NM работает, а утечку DNS мы всё равно
# закрываем правилами TPROXY для :53 в следующем шаге — независимо от того,
# чей dnsmasq реально раздаёт.
sleep 2
if pgrep -f "dnsmasq.*${LAN_IFACE}" >/dev/null 2>&1; then
    systemctl disable dnsmasq -q 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    ok "DHCP раздаёт NetworkManager (его dnsmasq) — свой отключил, чтобы не конфликтовал"
    info "Клиенты получат DNS $LAN_IP, но запросы принудительно уходят в sing-box (следующий шаг)"
else
    systemctl enable dnsmasq -q 2>/dev/null || true
    systemctl restart dnsmasq 2>/dev/null \
        || warn "dnsmasq пока не стартовал (ждёт $LAN_IFACE) — поднимется автоматически."
    ok "DHCP раздаёт наш dnsmasq (диапазон ${DHCP_FROM}–${DHCP_TO})"
fi

# ═══════════════════════════════════════════════════════════════════════════════
step 6 "iptables — TProxy маршрутизация и защита от утечек"
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
# NetworkManager в режиме shared может выдавать клиентам DNS = $LAN_IP (сам
# себя). Без этих двух правил такие запросы попадают под "-d 10.0.0.0/8 -j
# RETURN" ниже, уходят мимо sing-box и резолвятся напрямую — то есть DNS течёт
# в обход прокси. Проверено на живой коробке в похожей топологии.
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

info "MASQUERADE и FORWARD ($LAN_IFACE ↔ любой выход в интернет)..."
# WAN-сторона намеренно НЕ привязана к имени интерфейса (! -o LAN_IFACE, а не
# -o WAN_IFACE): если интернет-адаптер сменится (кабель на другой порт, смена
# имени интерфейса) — правила не придётся переприменять.
iptables -t nat -D POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true
iptables -t nat -C POSTROUTING ! -o "$LAN_IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING ! -o "$LAN_IFACE" -j MASQUERADE
iptables -D FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -C FORWARD -i "$LAN_IFACE" ! -o "$LAN_IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$LAN_IFACE" ! -o "$LAN_IFACE" -j ACCEPT
iptables -C FORWARD ! -i "$LAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD ! -i "$LAN_IFACE" -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
ok "MASQUERADE + FORWARD настроены (переживут смену WAN-сети/адаптера)"

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
step 7 "Установка sing-box (ARM64) и JackalRouter"
# ═══════════════════════════════════════════════════════════════════════════════

info "Определяю последнюю версию sing-box..."
SINGBOX_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    2>/dev/null | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' | head -1 || true)
[ -z "${SINGBOX_VERSION:-}" ] && SINGBOX_VERSION="1.13.13"
ok "sing-box v${SINGBOX_VERSION} (linux-${SB_ARCH})"

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
tar xzf "$STMP/sing-box.tar.gz" -C "$STMP" || die "Архив sing-box не распаковался." "Повторите запуск."
install -m 755 "$STMP/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box
rm -rf "$STMP"
/usr/local/bin/sing-box version >/dev/null 2>&1 \
    && ok "sing-box установлен и запускается" \
    || die "sing-box не запускается (неверная архитектура?)." "Нужна 64-бит Raspberry Pi OS."

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
# Версии НЕ прибиты жёстко: на новых Python (3.13/3.14) у старых pydantic нет
# готовых wheel, и pip уходит собирать pydantic-core из исходников через Rust/PyO3,
# где сборка падает ("interpreter version is newer than PyO3's maximum supported").
# Нижние границы + --prefer-binary заставляют pip взять готовый wheel под этот Python.
"$DEPLOY_DIR/venv/bin/pip" install --quiet --prefer-binary \
    "fastapi>=0.111" "uvicorn[standard]>=0.29" "pydantic>=2.7" || die \
    "Не удалось установить Python-пакеты." "Проверьте интернет и повторите."
cp "$SCRIPT_DIR/server/jackalrouter.service" /etc/systemd/system/jackalrouter.service
systemctl daemon-reload; systemctl enable jackalrouter -q
ok "JackalRouter API установлен (автозапуск)"

# ═══════════════════════════════════════════════════════════════════════════════
step 8 "Запуск и проверка сервисов"
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
    || warn "dnsmasq ждёт wlan0 — поднимется автоматически (Restart=on-failure)."

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
echo -e "${W}Raspberry Pi теперь Wi-Fi роутер с защитой от утечек:${N}"
echo -e "  ${G}✓${N} Wi-Fi сеть \"${W}$AP_SSID${N}\" (WPA2) → шлюз $LAN_IP"
echo -e "  ${G}✓${N} DNS/TCP/UDP QUIC/WebRTC → sing-box TProxy → SOCKS5 прокси"
echo -e "  ${G}✓${N} MSS clamp 1280, IPv6 заблокирован"
echo -e "  ${G}✓${N} sing-box v${SINGBOX_VERSION} (${SB_ARCH}), API http://${LAN_IP}:${SERVER_PORT}"
echo ""
echo -e "${B}╔══════════════════════════════════════════════╗${N}"
echo -e "${B}║${W}   ЧТО ДЕЛАТЬ ДАЛЬШЕ                        ${B}║${N}"
echo -e "${B}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}1.${N} Убедитесь, что кабель воткнут: ${C}домашний роутер → Ethernet-порт Pi${N}"
echo ""
echo -e "${W}2.${N} На телефоне подключитесь к Wi-Fi:"
echo -e "   • Сеть:   ${W}$AP_SSID${N}"
echo -e "   • Пароль: ${W}$AP_PASS${N}"
echo ""
echo -e "${W}3.${N} На управляющем ПК (в этой же Wi-Fi сети) запустите ${W}JackalRouter клиент${N}:"
echo -e "   • IP Raspberry Pi: ${C}${LAN_IP}${N}"
echo -e "   • Вставьте SOCKS5 прокси → ${G}Route${N} → ${G}⚡ Тест канала${N}"
echo ""
echo -e "${W}4.${N} Проверка с телефона: ${C}https://ipleak.net${N} — IP прокси, DNS 8.8.8.8"
echo ""
echo -e "──────────────────────────────────────────────"
echo -e "${W}Управление:${N}"
echo -e "  sudo systemctl status jackalrouter sing-box dnsmasq"
echo -e "  nmcli con up jackal-ap      # если точка доступа не поднялась"
echo -e "  sudo journalctl -u sing-box -f"
echo -e "──────────────────────────────────────────────"
echo ""
