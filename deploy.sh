#!/bin/bash
# =============================================================================
#  JackalRouter — Автоматический деплой на Ubuntu
#  Запуск: sudo bash deploy.sh
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
SINGBOX_PORT=7893         # TProxy inbound (sing-box)
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

# ── Шапка ─────────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e "${B}╔══════════════════════════════════════════════╗${N}"
echo -e "${B}║${W}        JackalRouter — Установка             ${B}║${N}"
echo -e "${B}║${C}  Прокси-шлюз (sing-box TProxy) для роутера  ${B}║${N}"
echo -e "${B}╚══════════════════════════════════════════════╝${N}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
step 1 "Проверка системных требований"
# ═══════════════════════════════════════════════════════════════════════════════

if [ "$(id -u)" -ne 0 ]; then
    die "Скрипт должен запускаться от root." \
        "Выполните команду:  sudo bash deploy.sh"
fi
ok "Права root — есть"

if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
    warn "Система не Ubuntu — продолжаем, но возможны проблемы"
else
    UBUNTU_VER=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    ok "Ubuntu $UBUNTU_VER обнаружена"
fi

info "Проверяю доступность интернета..."
if ! curl -s --max-time 8 https://google.com -o /dev/null; then
    die "Нет доступа к интернету." \
        "Проверьте подключение ноутбука к интернету (Wi-Fi или основной LAN)."
fi
ok "Интернет доступен"

# ═══════════════════════════════════════════════════════════════════════════════
step 2 "Определение сетевых интерфейсов"
# ═══════════════════════════════════════════════════════════════════════════════

info "Ищу интерфейс с выходом в интернет..."
WAN_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
[ -z "$WAN_IFACE" ] && die \
    "Не удалось определить интернет-интерфейс." \
    "Проверьте подключение к интернету командой:  ip route"
WAN_IP=$(ip -4 addr show "$WAN_IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
ok "Интернет-интерфейс: ${W}$WAN_IFACE${N} ($WAN_IP)"

# ── Статический IP для самой коробки (стабильный адрес для клиента) ───────────
# По DHCP адрес коробки может смениться после ребута роутера, и клиент перестанет
# её находить. Фиксируем текущий IP как статический (тот же адрес → ничего не рвём).
info "Статический IP коробки (адрес, к которому подключается клиент)..."
WAN_CIDR=$(ip -4 addr show "$WAN_IFACE" | awk '/inet /{print $2; exit}')
WAN_PREFIX="${WAN_CIDR#*/}"; [ "$WAN_PREFIX" = "$WAN_CIDR" ] && WAN_PREFIX=24
WAN_GW=$(ip route show default | awk '/default/{print $3; exit}')
WAN_CON=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$WAN_IFACE" '$2==d{print $1; exit}')
STATIC_IP="$WAN_IP"
if [ -t 0 ] && [ -n "$WAN_CON" ]; then
    echo -e "    ${C}Текущий IP коробки: ${W}$WAN_IP${N}${C} (выдан роутером, может смениться).${N}"
    read -r -p "    Зафиксировать статически? [Enter=да] / другой IP / n=оставить DHCP: " ANS || ANS=""
    case "$ANS" in
        ""|[Yy]*) STATIC_IP="$WAN_IP" ;;
        [Nn]*)    STATIC_IP="" ;;
        *)        STATIC_IP="$ANS" ;;
    esac
fi
if [ -n "$STATIC_IP" ] && [ -n "$WAN_CON" ] && [ -n "$WAN_GW" ]; then
    nmcli con mod "$WAN_CON" ipv4.method manual \
        ipv4.addresses "${STATIC_IP}/${WAN_PREFIX}" ipv4.gateway "$WAN_GW" \
        ipv4.dns "8.8.8.8 1.1.1.1" 2>/dev/null \
        && nmcli con up "$WAN_CON" 2>/dev/null || warn "nmcli не смог применить — оставляю как есть."
    sleep 2
    WAN_IP=$(ip -4 addr show "$WAN_IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    ok "Статический IP коробки: ${W}$WAN_IP${N}  (шлюз $WAN_GW)"
else
    warn "Оставлен DHCP — IP коробки может смениться. Клиент придётся перенастраивать."
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

info "Ищу LAN-интерфейс для подключения роутера..."
LAN_IFACE=$(ip -o link show | awk -F': ' '{print $2}' | \
    grep -E '^(en|eth)' | grep -v "^${WAN_IFACE}$" | head -1 || true)
[ -z "${LAN_IFACE:-}" ] && die \
    "Не найден LAN-интерфейс для подключения роутера." \
    "Убедитесь что сетевая карта подключена. Список:  ip link show"

LAN_STATE=$(ip link show "$LAN_IFACE" | grep -oP 'state \K\w+')
ok "LAN-интерфейс для роутера: ${W}$LAN_IFACE${N} (состояние: $LAN_STATE)"
[ "$LAN_STATE" != "UP" ] && warn "Кабель не подключён? IP назначится при подключении."

info "Прописываю $LAN_IFACE в конфиг сервера..."
sed -i "s/INT_IFACE *= *\"[^\"]*\"/INT_IFACE    = \"$LAN_IFACE\"/" "$SCRIPT_DIR/server/server.py"
ok "Интерфейс $LAN_IFACE записан в server.py"

# ═══════════════════════════════════════════════════════════════════════════════
step 3 "Обновление системы и установка пакетов"
# ═══════════════════════════════════════════════════════════════════════════════

info "Обновляю список пакетов..."
echo -e "    ${Y}Это может занять 30-60 секунд...${N}"

BROKEN_REPOS=()
for f in /etc/apt/sources.list.d/*.list; do
    if [ -f "$f" ] && grep -q "skype\|teamviewer\|google.com/linux/chrome" "$f" 2>/dev/null; then
        BROKEN_REPOS+=("$f")
        mv "$f" "${f}.disabled_by_jackal" 2>/dev/null || true
    fi
done

apt-get update -qq 2>/dev/null || warn "Некоторые репозитории недоступны — не критично."

for f in "${BROKEN_REPOS[@]:-}"; do
    [ -f "${f}.disabled_by_jackal" ] && mv "${f}.disabled_by_jackal" "$f" 2>/dev/null || true
done
ok "Список пакетов обновлён"

echo ""
info "Устанавливаю необходимые пакеты:"
echo -e "    ${C}• python3, python3-venv — для сервера управления${N}"
echo -e "    ${C}• dnsmasq               — DHCP-сервер для роутера${N}"
echo -e "    ${C}• iptables-persistent   — сохранение правил после перезагрузки${N}"
echo -e "    ${C}• curl, wget            — загрузка sing-box${N}"
echo ""

DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing \
    python3 python3-venv dnsmasq iptables-persistent curl wget ethtool \
    2>/dev/null || die \
    "Не удалось установить пакеты." \
    "Проверьте интернет-соединение и повторите запуск скрипта."
ok "Все пакеты установлены"

# ── Остановить redsocks если запущен с прошлой версии ────────────────────────
if systemctl is-active redsocks -q 2>/dev/null; then
    info "Останавливаю старый redsocks..."
    systemctl stop redsocks 2>/dev/null || true
    systemctl disable redsocks 2>/dev/null || true
    ok "redsocks остановлен (заменяется на sing-box)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
step 4 "Настройка сети — статический IP на $LAN_IFACE"
# ═══════════════════════════════════════════════════════════════════════════════

info "Назначаю статический IP ${LAN_IP}/24 на интерфейс $LAN_IFACE..."
nmcli con delete jackal-lan 2>/dev/null || true
nmcli con add \
    type ethernet ifname "$LAN_IFACE" con-name jackal-lan \
    ipv4.method manual ipv4.addresses "${LAN_IP}/24" \
    ipv4.never-default yes connection.autoconnect yes 2>/dev/null

nmcli con up jackal-lan 2>/dev/null || \
    warn "Не удалось активировать $LAN_IFACE — кабель не подключён? IP назначится позже."

CURRENT_IP=$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | head -1)
if [ -n "$CURRENT_IP" ]; then
    ok "IP назначен: ${W}$CURRENT_IP${N} на $LAN_IFACE"
else
    warn "IP ещё не виден — активируется при подключении кабеля"
fi

# ═══════════════════════════════════════════════════════════════════════════════
step 5 "Настройка DHCP-сервера для роутера"
# ═══════════════════════════════════════════════════════════════════════════════

info "Настраиваю dnsmasq (DHCP + DNS-форвардинг на 8.8.8.8)..."

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

ok "DHCP + DNS конфиг записан"
info "Диапазон: ${DHCP_FROM} — ${DHCP_TO}  |  Шлюз: ${LAN_IP}  |  DNS: 8.8.8.8"

# systemd drop-in: dnsmasq стартует раньше, чем поднимается $LAN_IFACE, и падает
# с "unknown interface". Restart=on-failure + StartLimitIntervalSec=0 заставляют
# повторять старт бесконечно, пока LAN-интерфейс не появится (переживает ребут).
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
ok "dnsmasq сделан устойчивым к порядку загрузки (Restart=on-failure)"

systemctl restart dnsmasq || die \
    "dnsmasq не запустился." \
    "Проверьте логи: sudo journalctl -u dnsmasq -n 30"
ok "DHCP-сервер запущен"

# ═══════════════════════════════════════════════════════════════════════════════
step 6 "Настройка iptables — TProxy маршрутизация и защита от утечек"
# ═══════════════════════════════════════════════════════════════════════════════

info "Включаю IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 -q
grep -q "net.ipv4.ip_forward" /etc/sysctl.conf \
    && sed -i 's/.*net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf \
    || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
ok "IP forwarding включён (постоянно)"

# ── Policy routing для TProxy ─────────────────────────────────────────────────
info "Настраиваю policy routing (fwmark 1 → local, для TProxy)..."
ip rule del fwmark 1 table 100 2>/dev/null || true
ip rule add fwmark 1 table 100
ip route del local default dev lo table 100 2>/dev/null || true
ip route add local default dev lo table 100
ok "Policy routing: fwmark 1 → таблица 100 (локальная доставка)"

# ── Убираем старые redsocks-правила в nat (если остались) ────────────────────
iptables -t nat -D PREROUTING -i "$LAN_IFACE" -p tcp -j REDSOCKS 2>/dev/null || true
iptables -t nat -F REDSOCKS 2>/dev/null || true
iptables -t nat -X REDSOCKS 2>/dev/null || true

# ── MSS clamp 1280 (фиксим PMTUD через туннель) ──────────────────────────────
info "Устанавливаю MSS clamp 1280 на $LAN_IFACE..."
iptables -t mangle -D PREROUTING -i "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1280 2>/dev/null || true
iptables -t mangle -A PREROUTING -i "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1280
iptables -t mangle -D POSTROUTING -o "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1280 2>/dev/null || true
iptables -t mangle -A POSTROUTING -o "$LAN_IFACE" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1280
ok "MSS clamp 1280 — ingress + egress $LAN_IFACE"

# ── SING_BOX chain в mangle (TProxy) ─────────────────────────────────────────
info "Создаю TProxy цепочку SING_BOX (mangle PREROUTING)..."
iptables -t mangle -N SING_BOX 2>/dev/null || true
iptables -t mangle -F SING_BOX
for net in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 \
           172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t mangle -A SING_BOX -d "$net" -j RETURN
done
# Весь UDP (DNS :53 → FakeIP, QUIC :443, STUN…) → TProxy → sing-box →
# SOCKS5 UDP ASSOCIATE. QUIC проксируется (не блокируется): рабочий UDP/QUIC
# нужен, чтобы "резидентный" IP не получал fraud-очки за отсутствие QUIC.
iptables -t mangle -A SING_BOX -p udp -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1
# Весь TCP → TProxy → sing-box :$SINGBOX_PORT (domain по FakeIP-маппингу → SOCKS5)
iptables -t mangle -A SING_BOX -p tcp -j TPROXY --on-port "$SINGBOX_PORT" --tproxy-mark 1
iptables -t mangle -D PREROUTING -i "$LAN_IFACE" -j SING_BOX 2>/dev/null || true
iptables -t mangle -A PREROUTING -i "$LAN_IFACE" -j SING_BOX
ok "TProxy: весь UDP+TCP → sing-box :$SINGBOX_PORT  (QUIC через прокси, FakeIP)"

# ── MASQUERADE + FORWARD ──────────────────────────────────────────────────────
info "Настраиваю MASQUERADE и FORWARD..."
iptables -t nat -D POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE

iptables -D FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" \
    -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" -j ACCEPT
iptables -A FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" \
    -m state --state RELATED,ESTABLISHED -j ACCEPT
ok "MASQUERADE + FORWARD: $LAN_IFACE ↔ $WAN_IFACE"

# ── IPv6 Leak Prevention ──────────────────────────────────────────────────────
info "Блокирую IPv6 из LAN..."
ip6tables -D FORWARD -i "$LAN_IFACE" -j DROP 2>/dev/null || true
ip6tables -D FORWARD -o "$LAN_IFACE" -j DROP 2>/dev/null || true
ip6tables -A FORWARD -i "$LAN_IFACE" -j DROP
ip6tables -A FORWARD -o "$LAN_IFACE" -j DROP
ip6tables -D INPUT -i "$LAN_IFACE" -p ipv6-icmp -j DROP 2>/dev/null || true
ip6tables -A INPUT -i "$LAN_IFACE" -p ipv6-icmp -j DROP
ok "IPv6 FORWARD DROP: устройства не получат IPv6-адрес"

# ── GRO off (предотвращаем сборку сегментов >MSS на LAN-интерфейсе) ──────────
info "Отключаю GRO/GSO/TSO на $LAN_IFACE..."
ethtool -K "$LAN_IFACE" gro off gso off tso off lro off 2>/dev/null || \
    warn "ethtool не смог отключить offload — не критично"
ok "GRO/GSO/TSO отключены на $LAN_IFACE"

info "Сохраняю правила iptables..."
netfilter-persistent save -q 2>/dev/null \
    || { iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6; }
ok "Правила сохранены (переживут перезагрузку)"

# ═══════════════════════════════════════════════════════════════════════════════
step 7 "Установка sing-box и JackalRouter"
# ═══════════════════════════════════════════════════════════════════════════════

# ── sing-box ──────────────────────────────────────────────────────────────────
info "Определяю последнюю версию sing-box..."
SINGBOX_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    2>/dev/null | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' | head -1 || true)
[ -z "${SINGBOX_VERSION:-}" ] && SINGBOX_VERSION="1.13.13"
ok "sing-box v${SINGBOX_VERSION}"

info "Скачиваю sing-box..."
STMP=$(mktemp -d)
SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
curl -sL "$SINGBOX_URL" -o "$STMP/sing-box.tar.gz" || \
    die "Не удалось скачать sing-box." "Проверьте интернет и повторите."
tar xzf "$STMP/sing-box.tar.gz" -C "$STMP"
install -m 755 "$STMP/sing-box-${SINGBOX_VERSION}-linux-amd64/sing-box" /usr/local/bin/sing-box
rm -rf "$STMP"
ok "sing-box установлен в /usr/local/bin/sing-box"

# Каталог конфигов, cache и заглушка (до первого Route через клиент)
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

info "Создаю Python-окружение..."
python3 -m venv "$DEPLOY_DIR/venv" || die \
    "Не удалось создать Python venv." \
    "Попробуйте: sudo apt-get install python3-venv"
ok "Python venv создан"

info "Устанавливаю Python-зависимости..."
# Версии НЕ прибиты жёстко: на новых Python (3.13/3.14) у старых pydantic нет
# готовых wheel, и pip уходит собирать pydantic-core из исходников через Rust/PyO3,
# где сборка падает ("interpreter version is newer than PyO3's maximum supported").
# Нижние границы + --prefer-binary заставляют pip взять готовый wheel под этот Python.
"$DEPLOY_DIR/venv/bin/pip" install --quiet --prefer-binary \
    "fastapi>=0.111" "uvicorn[standard]>=0.29" "pydantic>=2.7" || die \
    "Не удалось установить Python-пакеты." \
    "Проверьте интернет-соединение и повторите."
ok "Зависимости установлены (fastapi, uvicorn)"

info "Регистрирую systemd-сервис JackalRouter..."
cp "$SCRIPT_DIR/server/jackalrouter.service" /etc/systemd/system/jackalrouter.service
systemctl daemon-reload
systemctl enable jackalrouter -q
ok "Сервис зарегистрирован (автозапуск при старте системы)"

# ═══════════════════════════════════════════════════════════════════════════════
step 8 "Запуск и проверка всех сервисов"
# ═══════════════════════════════════════════════════════════════════════════════

info "Запускаю sing-box..."
systemctl restart sing-box
sleep 2
if systemctl is-active sing-box -q; then
    ok "sing-box        — ${G}активен${N} (TProxy :$SINGBOX_PORT)"
else
    warn "sing-box не запустился. Логи:"
    journalctl -u sing-box -n 10 --no-pager 2>/dev/null || true
fi

info "Проверяю dnsmasq..."
if systemctl is-active dnsmasq -q; then
    ok "dnsmasq         — ${G}активен${N} (DHCP на $LAN_IFACE)"
else
    err "dnsmasq не запустился."
    journalctl -u dnsmasq -n 5 --no-pager 2>/dev/null || true
fi

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
if echo "$API_STATUS" | grep -q "sing_box"; then
    ok "API отвечает: $API_STATUS"
else
    warn "API пока не отвечает — возможно ещё стартует"
fi

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
echo -e "  ${G}✓${N} DNS (UDP+TCP :53)       → sing-box FakeIP → домен к прокси (нет IP-утечки)"
echo -e "  ${G}✓${N} TCP (весь трафик)       → sing-box TProxy → SOCKS5 прокси (по домену)"
echo -e "  ${G}✓${N} UDP QUIC/HTTP3 :443     → sing-box TProxy → SOCKS5 UDP ASSOCIATE (нет fraud-очков)"
echo -e "  ${G}✓${N} UDP STUN/WebRTC         → через прокси (отражает IP прокси, не реальный)"
echo -e "  ${G}✓${N} MSS clamp 1280          → нет проблем с PMTUD через туннель"
echo -e "  ${G}✓${N} GRO/GSO/TSO отключены   → нет пересборки сегментов больше MSS"
echo -e "  ${G}✓${N} IPv6                    → заблокирован"
echo ""
echo -e "${W}Что установлено:${N}"
echo -e "  • sing-box v${SINGBOX_VERSION}    → /usr/local/bin/sing-box"
echo -e "  • JackalRouter API  → http://${SERVER_IP}:${SERVER_PORT}"
echo -e "  • LAN-шлюз роутера → ${LAN_IP} (интерфейс $LAN_IFACE)"
echo -e "  • DHCP-диапазон    → ${DHCP_FROM} – ${DHCP_TO}"

echo ""
echo -e "${B}╔══════════════════════════════════════════════╗${N}"
echo -e "${B}║${W}   СЛЕДУЮЩИЙ ШАГ — НАСТРОЙКА РОУТЕРА        ${B}║${N}"
echo -e "${B}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}1.${N} Подключите кабель:"
echo -e "   ${C}Ноутбук (порт: $LAN_IFACE)  ──кабель──▶  WAN-порт роутера${N}"
echo ""
echo -e "${W}2.${N} Зайдите в Wi-Fi роутера с телефона или второго ноутбука"
echo ""
echo -e "${W}3.${N} Откройте браузер и введите адрес веб-интерфейса роутера:"
echo -e "   ${Y}→ http://192.168.0.1${N}   (TP-Link, D-Link, Netgear, Xiaomi)"
echo -e "   ${Y}→ http://192.168.1.1${N}   (ASUS, Keenetic, Zyxel, Huawei)"
echo ""
echo -e "${W}4.${N} Найдите: ${Y}WAN / Интернет / Тип подключения${N}"
echo -e "   Выберите: ${G}DHCP${N}  (Динамический IP / Автоматически)"
echo ""
echo -e "${W}5.${N} Нажмите ${G}Сохранить${N}, подождите 15 секунд"
echo ""
echo -e "${W}6.${N} Запустите ${W}JackalRouter клиент${N} на Windows:"
echo -e "   • IP Ubuntu: ${C}${SERVER_IP}${N}"
echo -e "   • Вставьте строку SOCKS5 прокси → нажмите ${G}Route${N}"
echo ""
echo -e "${W}7.${N} Проверьте с телефона (через Wi-Fi роутера):"
echo -e "   ${C}https://2ip.ru${N}          — должен быть американский IP"
echo -e "   ${C}https://ipleak.net${N}       — DNS: 8.8.8.8, IP: прокси"
echo ""
echo -e "──────────────────────────────────────────────"
echo -e "${W}Управление:${N}"
echo -e "  sudo systemctl status jackalrouter"
echo -e "  sudo systemctl status sing-box"
echo -e "  sudo journalctl -u sing-box -f"
echo -e "  sudo journalctl -u jackalrouter -f"
echo -e "──────────────────────────────────────────────"
echo ""
