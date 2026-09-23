#!/usr/bin/env bash
#
# protect.sh — защита Remnawave-ноды.
# Делает:
#   - nftables-firewall с белым списком сервисных портов
#   - SYN-flood защита, drop невалидных флагов, ICMP rate-limit
#   - rate-limit на SSH/панель
#   - блок известных ASN РКН/TSPU/сканеров (auto-update раз в неделю)
#   - блок Spamhaus DROP / FireHOL level1
#   - SAFETY-таймер: если что-то пошло не так и SSH потерялся —
#     через 5 минут правила автоматически сбрасываются.
#
# Откат: scripts/rollback.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_root
detect_os

BACKUP="$(backup_dir)"
info "Бэкап: $BACKUP"

# ─── Параметры (можно переопределить через env) ─────────────────────────────
SSH_PORT="${SSH_PORT:-$(detect_ssh_port)}"
TCP_PORTS="${TCP_PORTS:-443,2087}"           # XRay/VLESS/Reality/панель
UDP_PORTS="${UDP_PORTS:-443,2087}"           # для QUIC/Hysteria/TUIC
NODE_PORT="${NODE_PORT:-2222}"               # порт remnawave-node-agent
WHITELIST="${WHITELIST:-}"                   # IP/CIDR через запятую (мониторинг, главная панель)
SAFETY_DELAY="${SAFETY_DELAY:-300}"          # секунд до авто-сброса правил
ENABLE_SCANNER_BLOCK="${ENABLE_SCANNER_BLOCK:-1}"
WHOIS_TIMEOUT="${WHOIS_TIMEOUT:-20}"        # сек на один ASN к whois.radb.net (антивисание)
RIPESTAT_TIMEOUT="${RIPESTAT_TIMEOUT:-15}"  # curl к stat.ripe.net за один ASN
# auto|ripestat|whois — у части VPS блокируют исходящий TCP/43 (RADB); auto берёт префиксы по HTTPS
SCANNER_PREFIX_SOURCE="${SCANNER_PREFIX_SOURCE:-auto}"
ENABLE_SPAMHAUS="${ENABLE_SPAMHAUS:-1}"
ENABLE_GEOBLOCK="${ENABLE_GEOBLOCK:-1}"      # 1 = блок 22 стран-источников атак (ipdeny.com)
DRY_RUN="${DRY_RUN:-0}"                      # 1 = только сгенерировать и проверить, не применять

# Если запущено интерактивно — спросим параметры
if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" ]]; then
    title "Параметры защиты"
    read -rp "SSH порт                     [$SSH_PORT]: "                   _v && SSH_PORT="${_v:-$SSH_PORT}"
    read -rp "TCP порты Remnawave (через ,) [$TCP_PORTS]: "                 _v && TCP_PORTS="${_v:-$TCP_PORTS}"
    read -rp "UDP порты Remnawave (через ,) [$UDP_PORTS]: "                 _v && UDP_PORTS="${_v:-$UDP_PORTS}"
    read -rp "Порт node-agent              [$NODE_PORT]: "                  _v && NODE_PORT="${_v:-$NODE_PORT}"
    read -rp "Whitelist IP/CIDR панели (через ,) [обязательно]: "           _v && WHITELIST="${_v:-$WHITELIST}"
    echo
    echo "  Геоблок: CN IN BD VN ID PH NG BR EG PK TH MM KH LA ET UZ TN VE EC KE TZ UA"
    echo "  (страны-источники атак, префиксы с ipdeny.com)"
    warn "  ВАЖНО: если IP твоей панели из списка стран — добавь его в Whitelist выше!"
    read -rp "Включить геоблок этих стран? [Y/n]: " _v
    [[ "$_v" =~ ^[nNнН] ]] && ENABLE_GEOBLOCK=0
fi

# ─── Валидация ───────────────────────────────────────────────────────────────
validate_port_list() {
    # На входе "443,2087" — должно быть только цифры и запятые, каждый порт 1..65535
    local v="$1" name="$2"
    [[ -z "$v" ]] && return 0
    [[ "$v" =~ ^[0-9,]+$ ]] || { err "$name: '$v' — допустимы только цифры и запятые"; return 1; }
    local p
    for p in $(echo "$v" | tr ',' ' '); do
        [[ "$p" =~ ^[0-9]+$ ]] || { err "$name: '$p' — не число"; return 1; }
        (( p >= 1 && p <= 65535 )) || { err "$name: $p вне 1..65535"; return 1; }
    done
}

validate_single_port() {
    local v="$1" name="$2"
    [[ "$v" =~ ^[0-9]+$ ]] || { err "$name: '$v' — не число"; return 1; }
    (( v >= 1 && v <= 65535 )) || { err "$name: $v вне 1..65535"; return 1; }
}

validate_whitelist() {
    # IP или CIDR, через запятую
    local v="$1"
    [[ -z "$v" ]] && return 0
    local item
    for item in $(echo "$v" | tr ',' ' '); do
        [[ "$item" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] \
            || { err "WHITELIST: '$item' не похоже на IPv4 / CIDR"; return 1; }
    done
}

validate_single_port "$SSH_PORT"  SSH_PORT  || exit 1
validate_single_port "$NODE_PORT" NODE_PORT || exit 1
validate_port_list   "$TCP_PORTS" TCP_PORTS || exit 1
validate_port_list   "$UDP_PORTS" UDP_PORTS || exit 1
validate_whitelist   "$WHITELIST"           || exit 1
if [[ -z "$WHITELIST" ]]; then
    err "WHITELIST пуст. Порт node-agent ${NODE_PORT} у Remnawave открыт только для IP панели."
    err "Без этого protect либо отрежет панель от ноды, либо (старое правило) откроет порт всем."
    err "Пример: WHITELIST=1.2.3.4"
    exit 1
fi

# ─── Зависимости ─────────────────────────────────────────────────────────────
title "Установка зависимостей"
apt_install nftables ipset whois curl ca-certificates iproute2
ok "ok"

# ─── UFW-детект (его правила будут снесены flush ruleset) ────────────────────
if [[ "$DRY_RUN" != "1" ]] && systemctl is-active --quiet ufw 2>/dev/null; then
    warn "На сервере активен UFW. Мой 'flush ruleset' снесёт его правила."
    warn "После применения protect.sh UFW лучше отключить, чтобы не было путаницы:"
    warn "  systemctl disable --now ufw"
    if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" ]]; then
        confirm "Продолжить?" || { info "Отмена."; exit 0; }
    fi
fi

# ─── SAFETY: если заблокируем SSH — через N сек nft flush ruleset ────────────
if [[ "$DRY_RUN" != "1" ]]; then
    title "Подстраховка от блокировки SSH"
    warn "Если что-то пойдёт не так — правила сбросятся через ${SAFETY_DELAY}s."
    # Убиваем старый сейфти (если был), запускаем новый
    if [[ -f /tmp/remnawave-fw-safety.pid ]]; then
        kill "$(cat /tmp/remnawave-fw-safety.pid)" 2>/dev/null || true
        rm -f /tmp/remnawave-fw-safety.pid
    fi
    nohup sh -c "sleep ${SAFETY_DELAY}; /usr/sbin/nft flush ruleset; rm -f /tmp/remnawave-fw-safety.pid" \
        >/tmp/remnawave-fw-safety.log 2>&1 &
    echo $! > /tmp/remnawave-fw-safety.pid
    ok "safety pid: $(cat /tmp/remnawave-fw-safety.pid)"
fi

# ─── Резервное копирование текущих правил ────────────────────────────────────
if [[ "$DRY_RUN" != "1" ]]; then
    backup_file /etc/nftables.conf "$BACKUP"
    nft list ruleset > "$BACKUP/nftables.ruleset.before" 2>/dev/null || true
fi

# В DRY_RUN пишем во временный файл, чтобы не трогать /etc/
if [[ "$DRY_RUN" == "1" ]]; then
    NFT_CONF="$(mktemp /tmp/remnawave-nft.XXXXXX.conf)"
else
    NFT_CONF=/etc/nftables.conf
fi

# ─── Подготовка whitelist в nft-формат ───────────────────────────────────────
WL_NFT=""
if [[ -n "$WHITELIST" ]]; then
    WL_NFT="$(echo "$WHITELIST" | tr ',' '\n' | awk 'NF{printf "%s%s", sep, $0; sep=", "}')"
fi

# ─── Генерация правил ────────────────────────────────────────────────────────
title "Генерация nftables правил → $NFT_CONF"

cat > "$NFT_CONF" <<NFT
#!/usr/sbin/nft -f
# Сгенерировано remnawave-node-toolkit / protect.sh @ $(date -Is)

flush ruleset

table inet rwfilter {

    # Сканерные сети (TSPU/РКН/массовые сканеры) — обновляется в cron
    set scanner_v4 {
        type ipv4_addr
        flags interval
        auto-merge
    }

    # Spamhaus DROP / FireHOL level1
    set badips_v4 {
        type ipv4_addr
        flags interval
        auto-merge
    }

    # Геоблок стран-источников атак (обновляется в cron, ipdeny.com)
    set geoblock_v4 {
        type ipv4_addr
        flags interval
        auto-merge
    }

    # Динамический бан (rate-limit оверкоммит, port-scan)
    set autoban_v4 {
        type ipv4_addr
        flags timeout
        timeout 24h
    }

    # Whitelist
    set whitelist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
$([ -n "$WL_NFT" ] && echo "        elements = { $WL_NFT }")
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # Базовое
        iif lo accept
        ct state established,related accept
        ct state invalid drop

        # Whitelist всегда сверху
        ip saddr @whitelist_v4 accept

        # Сначала режем плохих
        ip saddr @autoban_v4 drop
        ip saddr @scanner_v4 drop
        ip saddr @badips_v4  drop
        ip saddr @geoblock_v4 drop

        # ICMP с rate-limit (echo-request) — пинг работает, флуд режется
        icmp type echo-request limit rate 10/second burst 20 packets accept
        icmp type echo-request drop
        icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        icmpv6 type { echo-request, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, time-exceeded, parameter-problem, destination-unreachable } accept

        # Невалидные TCP-флаги — дроп
        tcp flags & (fin|syn|rst|ack) == 0           drop
        tcp flags & (fin|syn) == (fin|syn)           drop
        tcp flags & (syn|rst) == (syn|rst)           drop
        tcp flags & (fin|rst) == (fin|rst)           drop
        tcp flags & (fin|ack) == fin                 drop
        tcp flags & (psh|ack) == psh                 drop
        tcp flags & (ack|urg) == urg                 drop
        tcp flags == (fin|psh|urg)                   drop

        # SYN-flood: на новые SYN — limit + cookies (cookies включаются sysctl'ем)
        tcp flags & (fin|syn|rst|ack) == syn limit rate 1000/second burst 2000 packets accept
        tcp flags & (fin|syn|rst|ack) == syn drop

        # SSH с rate-limit (мягкий fail2ban): >6 попыток/мин с одного IP — бан 24ч
        tcp dport ${SSH_PORT} ct state new \\
            meter ssh_meter { ip saddr timeout 10m limit rate 6/minute } \\
            accept
        tcp dport ${SSH_PORT} ct state new \\
            add @autoban_v4 { ip saddr timeout 24h } \\
            log prefix "[rwfilter ssh-ban] " level warn \\
            drop

        # Сервисные TCP-порты Remnawave (XRay/Reality/панель)
$(for p in $(echo "$TCP_PORTS" | tr ',' ' '); do
    [[ -z "$p" ]] && continue
    echo "        tcp dport ${p} ct state new limit rate 300/second burst 600 packets accept"
done)

        # Сервисные UDP (QUIC, Hysteria, TUIC)
$(for p in $(echo "$UDP_PORTS" | tr ',' ' '); do
    [[ -z "$p" ]] && continue
    echo "        udp dport ${p} limit rate 1000/second burst 2000 packets accept"
done)

        # Порт node-agent — только IP из WHITELIST (панель). В интернет не открывать.
        tcp dport ${NODE_PORT} ip saddr @whitelist_v4 accept

        # Всё остальное — тихо drop (не reject), чтобы не светить наличие сервиса
        # А SYN на закрытые порты = port-scan → автобан
        tcp flags & (fin|syn|rst|ack) == syn \\
            add @autoban_v4 { ip saddr timeout 24h } \\
            log prefix "[rwfilter portscan] " level info \\
            drop

        counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
NFT

# Проверяем синтаксис, ДО применения
if ! nft -c -f "$NFT_CONF"; then
    err "Сгенерированный конфиг не проходит проверку. Файл: $NFT_CONF"
    exit 1
fi

if [[ "$DRY_RUN" == "1" ]]; then
    ok "DRY-RUN: конфиг сгенерирован и проверен (nft -c)."
    info "Файл: $NFT_CONF"
    info "Чтобы применить — запусти без DRY_RUN."
    exit 0
fi

# Применяем
nft -f "$NFT_CONF"
systemctl enable --now nftables >/dev/null 2>&1 || systemctl restart nftables
ok "nftables применён"

# ─── Скрипт обновления ASN-блоклиста сканеров ────────────────────────────────
title "ASN-блоклист сканеров TSPU/РКН"

mkdir -p /etc/remnawave-toolkit
cat > /etc/remnawave-toolkit/scanner-asns.txt <<'ASNS'
# ASN-ы, замеченные в массовом сканировании / TSPU-пробах.
# Источники: публичные дампы antifilter.network, agpsec, личные наблюдения.
# Один ASN на строку. Комментарии (#) допускаются.
AS398324
AS398722
AS208046
AS396355
AS396982
AS62454
AS204428
AS398101
AS396998
AS211298
AS200651
AS49870
AS206264
AS60068
AS208843
AS137409
AS59890
AS398478
AS35624
AS207996
AS3214
ASNS

cat > /usr/local/sbin/remnawave-update-scanners <<'UPD'
#!/usr/bin/env bash
# Обновляет set inet rwfilter scanner_v4 префиксами ASN из scanner-asns.txt.
# Запускается из systemd timer (раз в неделю + при загрузке).

set -euo pipefail

ASN_FILE=/etc/remnawave-toolkit/scanner-asns.txt
[[ -f $ASN_FILE ]] || { echo "no $ASN_FILE"; exit 0; }

LOGDIR="${SCANNER_LOG_DIR:-/var/log/remnawave-toolkit}"
LOG="${SCANNER_UPDATE_LOG:-$LOGDIR/whois-asn.log}"
mkdir -p "$LOGDIR"

log() {
    local line="[$(date -Is)] $*"
    echo "$line" >&2
    echo "$line" >>"$LOG"
}

# whois к RADB без таймаута может висеть минутами; часть хостеров режет исходящий TCP/43 — тогда RIPEstat (443).
SCANNER_PREFIX_SOURCE="${SCANNER_PREFIX_SOURCE:-auto}"
RIPESTAT_TIMEOUT="${RIPESTAT_TIMEOUT:-15}"
WHOIS_TIMEOUT="${WHOIS_TIMEOUT:-20}"

_fetch_v4_ripestat() {
    # Только IPv4 из announced-prefixes (HTTPS, обход блокировки whois:43).
    local asn="$1" num="${asn#AS}" json
    json=$(curl -fsSL --max-time "${RIPESTAT_TIMEOUT}" --retry 1 \
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=${num}" 2>/dev/null) || return 0
    grep -qE '"status"[[:space:]]*:[[:space:]]*"ok"' <<<"$json" || return 0
    # Пустой grep при set -e/pipefail — через подоболочку
    ( printf '%s\n' "$json" | grep -oE '"prefix":"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"' | sed 's/^"prefix":"//;s/"$//' ) 2>/dev/null || true
}

_whois_radb() {
    if command -v timeout >/dev/null 2>&1; then
        timeout --kill-after=5 "${WHOIS_TIMEOUT}" whois -h whois.radb.net -- "$1" 2>/dev/null
    else
        whois -h whois.radb.net -- "$1" 2>/dev/null
    fi
}

_progress_bar() {
    # $1 текущий шаг, $2 всего (stderr, одна строка)
    local cur=$1 tot=$2 w=32 n pct
    (( tot < 1 )) && return 0
    n=$(( cur * w / tot ))
    pct=$(( cur * 100 / tot ))
    local i s=""
    for ((i = 0; i < n; i++)); do s+="#"; done
    for ((i = n; i < w; i++)); do s+="-"; done
    printf '[%s] %3d%% (%d/%d)\n' "$s" "$pct" "$cur" "$tot" >&2
}

if ! command -v timeout >/dev/null 2>&1; then
    echo "[!] remnawave-update-scanners: нет команды timeout — whois без лимита может зависнуть (apt install coreutils)" >&2
fi

declare -a ASN_LIST=()
while read -r line; do
    asn="${line%%#*}"
    asn="$(echo "$asn" | tr -d '[:space:]')"
    [[ -z $asn ]] && continue
    [[ "$asn" =~ ^AS[0-9]+$ ]] || continue
    ASN_LIST+=("$asn")
done <"$ASN_FILE"

n_asns=${#ASN_LIST[@]}
if (( n_asns < 1 )); then
    log "нет ни одного валидного ASN в $ASN_FILE"
    exit 0
fi

TMP=$(mktemp); trap 'rm -f "$TMP" "$TMP.clean"' EXIT

log "=== scanner-asn start: ${n_asns} ASN, source=${SCANNER_PREFIX_SOURCE}, ripestat=https (${RIPESTAT_TIMEOUT}s), whois.radb.net (${WHOIS_TIMEOUT}s), log=${LOG} ==="

i=0
for asn in "${ASN_LIST[@]}"; do
    ((++i))
    st=""
    ripe_v4=""
    nripe=0

    if [[ "${SCANNER_PREFIX_SOURCE}" == "whois" ]]; then
        :
    else
        SECONDS=0
        ripe_v4=$(_fetch_v4_ripestat "$asn")
        el_ripe=$SECONDS
        nripe=$(printf '%s\n' "$ripe_v4" | sed '/^$/d' | wc -l)
    fi

    if [[ "${SCANNER_PREFIX_SOURCE}" == "ripestat" ]]; then
        if ((nripe > 0)); then
            printf '%s\n' "$ripe_v4" | sed '/^$/d' >>"$TMP"
            st="ripestat ${nripe} IPv4 за ${el_ripe}s"
        else
            st="ripestat: нет IPv4 (${el_ripe}s)"
        fi
    elif [[ "${SCANNER_PREFIX_SOURCE}" == "whois" ]]; then
        SECONDS=0
        rc=0
        out=$(_whois_radb "-i origin $asn" 2>/dev/null) || rc=$?
        el=$SECONDS
        printf '%s\n' "$out" | awk '/^route:/ {print $2}' >>"$TMP"
        routes=$(printf '%s\n' "$out" | awk '/^route:/ {c++} END {print c+0}')
        if [[ $rc -eq 124 ]]; then
            st="whois TIMEOUT ${el}s (whois.radb.net:43)"
        elif [[ $rc -ne 0 ]]; then
            st="whois сбой rc=${rc} (${el}s)"
        else
            st="whois ok ${el}s, route: ${routes}"
        fi
    else
        # auto
        if ((nripe > 0)); then
            printf '%s\n' "$ripe_v4" | sed '/^$/d' >>"$TMP"
            st="ripestat ${nripe} IPv4 за ${el_ripe}s"
        else
            SECONDS=0
            rc=0
            out=$(_whois_radb "-i origin $asn" 2>/dev/null) || rc=$?
            el=$SECONDS
            printf '%s\n' "$out" | awk '/^route:/ {print $2}' >>"$TMP"
            routes=$(printf '%s\n' "$out" | awk '/^route:/ {c++} END {print c+0}')
            if [[ $rc -eq 124 ]]; then
                st="ripestat пусто → whois TIMEOUT ${el}s (:43?)"
            elif [[ $rc -ne 0 ]]; then
                st="ripestat пусто → whois rc=${rc} (${el}s)"
            else
                st="ripestat пусто → whois ok ${el}s, route: ${routes}"
            fi
        fi
    fi

    log "[$i/${n_asns}] ${asn} → ${st}"
    [[ -t 2 ]] && _progress_bar "$i" "$n_asns"
done

# Только валидные IPv4-префиксы
sort -u "$TMP" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' >"$TMP.clean" || true

COUNT=$(wc -l <"$TMP.clean")
if [[ $COUNT -lt 50 ]]; then
    log "итог: только ${COUNT} валидных префиксов — отказ (порог 50)"
    echo "scanner update: только $COUNT префиксов — отказываюсь применять (слишком мало данных с ripestat/whois)"
    exit 1
fi

{
    echo "flush set inet rwfilter scanner_v4"
    while read -r p; do
        echo "add element inet rwfilter scanner_v4 { $p }"
    done <"$TMP.clean"
} | nft -f -

log "=== scanner-asn done: в nft применено ${COUNT} префиксов ==="
echo "scanner update: применено $COUNT префиксов"
UPD
chmod +x /usr/local/sbin/remnawave-update-scanners

# ─── Скрипт Spamhaus DROP ────────────────────────────────────────────────────
cat > /usr/local/sbin/remnawave-update-spamhaus <<'SPAM'
#!/usr/bin/env bash
# Обновляет set inet rwfilter badips_v4 списком Spamhaus DROP.
set -euo pipefail

URL="${SPAMHAUS_URL:-https://www.spamhaus.org/drop/drop.txt}"
TMP=$(mktemp); trap 'rm -f "$TMP" "$TMP.clean"' EXIT

curl -fsSL --max-time 30 "$URL" -o "$TMP" || { echo "spamhaus: не скачать"; exit 1; }

awk '/^[0-9]/ {print $1}' "$TMP" \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' \
    | sort -u > "$TMP.clean"

COUNT=$(wc -l < "$TMP.clean")
[[ $COUNT -lt 100 ]] && { echo "spamhaus: только $COUNT — отказываюсь"; exit 1; }

{
    echo "flush set inet rwfilter badips_v4"
    while read -r p; do
        echo "add element inet rwfilter badips_v4 { $p }"
    done < "$TMP.clean"
} | nft -f -

echo "spamhaus: применено $COUNT префиксов"
SPAM
chmod +x /usr/local/sbin/remnawave-update-spamhaus

# ─── Скрипт геоблока стран ───────────────────────────────────────────────────
cat > /etc/remnawave-toolkit/geoblock-countries.txt <<'COUNTRIES'
# Страны-источники атак. Один cc (lowercase) на строку. # — комментарий.
# Префиксы загружаются с ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone
cn  # Китай
in  # Индия
bd  # Бангладеш
vn  # Вьетнам
id  # Индонезия
ph  # Филиппины
ng  # Нигерия
br  # Бразилия
eg  # Египет
pk  # Пакистан
th  # Таиланд
mm  # Мьянма
kh  # Камбоджа
la  # Лаос
et  # Эфиопия
uz  # Узбекистан
tn  # Тунис
ve  # Венесуэла
ec  # Эквадор
ke  # Кения
tz  # Танзания
ua  # Украина
COUNTRIES

cat > /usr/local/sbin/remnawave-update-geoblock <<'GEO'
#!/usr/bin/env bash
# Обновляет set inet rwfilter geoblock_v4 из ipdeny.com.
# Запускается из systemd timer (раз в неделю + при загрузке).

set -euo pipefail

COUNTRIES_FILE=/etc/remnawave-toolkit/geoblock-countries.txt
[[ -f $COUNTRIES_FILE ]] || { echo "no $COUNTRIES_FILE"; exit 0; }

BASE_URL="https://www.ipdeny.com/ipblocks/data/aggregated"
TMP=$(mktemp); trap 'rm -f "$TMP" "$TMP.clean"' EXIT
FAILED=0

while IFS= read -r line; do
    # Убрать комментарий и пробелы
    cc="${line%%#*}"
    cc="$(echo "$cc" | tr -d '[:space:]')"
    [[ -z "$cc" ]] && continue

    url="${BASE_URL}/${cc}-aggregated.zone"
    if ! curl -fsSL --max-time 30 --retry 2 --retry-delay 3 "$url" >> "$TMP" 2>/dev/null; then
        echo "geoblock: не скачал зону '$cc' (${url})" >&2
        FAILED=$((FAILED + 1))
    fi
done < "$COUNTRIES_FILE"

# Оставить только валидные IPv4-префиксы
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$TMP" | sort -u > "$TMP.clean" || true

COUNT=$(wc -l < "$TMP.clean")
echo "geoblock update: ${COUNT} префиксов, ошибок загрузки: ${FAILED}"

if [[ $COUNT -eq 0 ]]; then
    echo "geoblock: пустой результат — пропускаю обновление"
    exit 1
fi

{
    echo "flush set inet rwfilter geoblock_v4"
    while read -r p; do
        echo "add element inet rwfilter geoblock_v4 { $p }"
    done < "$TMP.clean"
} | nft -f -

echo "geoblock: применено ${COUNT} префиксов"
GEO
chmod +x /usr/local/sbin/remnawave-update-geoblock

# ─── systemd timer ───────────────────────────────────────────────────────────
cat > /etc/systemd/system/remnawave-blocklist.service <<'EOF'
[Unit]
Description=Remnawave: обновление блок-листов
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/remnawave-update-scanners
ExecStart=/usr/local/sbin/remnawave-update-spamhaus
ExecStart=/usr/local/sbin/remnawave-update-geoblock
EOF

cat > /etc/systemd/system/remnawave-blocklist.timer <<'EOF'
[Unit]
Description=Remnawave: еженедельное обновление блок-листов

[Timer]
OnBootSec=10min
OnCalendar=Sun 04:17:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now remnawave-blocklist.timer >/dev/null 2>&1 || true
ok "blocklist таймер активен"

# ─── Первичное обновление блок-листов (фоном) ────────────────────────────────
if [[ "$ENABLE_SCANNER_BLOCK" == "1" ]]; then
    info "Префиксы по ASN (HTTPS RIPEstat, резерв whois:43; прогресс ниже, лог: /var/log/remnawave-toolkit/whois-asn.log)..."
    /usr/local/sbin/remnawave-update-scanners || warn "ASN-обновление не удалось, попробуй позже"
fi
if [[ "$ENABLE_SPAMHAUS" == "1" ]]; then
    /usr/local/sbin/remnawave-update-spamhaus || warn "Spamhaus не скачался"
fi
if [[ "$ENABLE_GEOBLOCK" == "1" ]]; then
    info "Скачиваю геоблок-префиксы 22 стран (это займёт ~20 сек)..."
    /usr/local/sbin/remnawave-update-geoblock || warn "Геоблок не загрузился, попробуй позже: remnawave-update-geoblock"
fi

# ─── Маркер ──────────────────────────────────────────────────────────────────
mkdir -p /var/lib/remnawave-toolkit
cat > /var/lib/remnawave-toolkit/protect.installed <<EOF
installed_at=$(date -Is)
backup=$BACKUP
ssh_port=$SSH_PORT
tcp_ports=$TCP_PORTS
udp_ports=$UDP_PORTS
node_port=$NODE_PORT
geoblock=$ENABLE_GEOBLOCK
EOF

# ─── Подтверждение работы ────────────────────────────────────────────────────
title "Подтверждение"
warn "Сейчас запущен сейфти-таймер: правила сбросятся через ${SAFETY_DELAY}s,"
warn "если ты не подтвердишь, что соединение ещё живо."
echo
echo "  Открой В НОВОМ окне: ssh root@<этот сервер> и убедись, что коннект работает."
echo
# Читать с терминала: при запуске через «curl | bash» или install.sh stdin не TTY — read иначе сразу EOF и вопрос не ждёт.
if [[ -r /dev/tty ]]; then
    read -r -p "Соединение работает? [y/N]: " confirm </dev/tty
else
    read -r -p "Соединение работает? [y/N]: " confirm
fi
if [[ "$confirm" =~ ^[yYдД] ]]; then
    if [[ -f /tmp/remnawave-fw-safety.pid ]]; then
        kill "$(cat /tmp/remnawave-fw-safety.pid)" 2>/dev/null || true
        rm -f /tmp/remnawave-fw-safety.pid
    fi
    ok "Сейфти-таймер отменён. Защита активна."
else
    warn "Сейфти-таймер оставлен. Через ${SAFETY_DELAY}s правила автоматически сбросятся."
    warn "Если всё ок — отмени вручную: kill \$(cat /tmp/remnawave-fw-safety.pid)"
fi

echo
ok "Готово. nft list ruleset для проверки."
