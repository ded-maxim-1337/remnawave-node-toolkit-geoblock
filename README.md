# remnawave-node-toolkit-geoblock

Скрипты для тюнинга и защиты [Remnawave](https://remna.st)-нод (Xray/VLESS/Reality).
Два модуля, оба идемпотентны, оба откатываются одной командой.

> Поддерживается **Debian 11/12** и **Ubuntu 20.04/22.04/24.04**.
> Тестировалось на нодах с `remnawave/node` в `network_mode: host`.
### Very fast start: Способ 1 — one-liner (`curl`)

```bash
curl -fsSL "https://raw.githubusercontent.com/ded-maxim-1337/remnawave-node-toolkit-geoblock/main/install.sh?$(date +%s)" | sudo bash -s all
```
---

## Что внутри

### 1. Оптимизатор (`scripts/optimize.sh`)

Тюнит ноду под высокий PPS и тысячи одновременных соединений:

- **BBR** + `fq` qdisc, `tcp_fastopen`, отключенный slow-start после idle
- **TCP/UDP буферы** до 64 МБ, `somaxconn = 65535`, `netdev_max_backlog = 250000`
- **conntrack** до 2 000 000 записей, увеличенные buckets
- **SYN-cookies** + укороченный `synack_retries`
- **Anti-spoof**: `rp_filter`, выключенные `accept_redirects` и `source_route`
- **nofile / nproc → 1 048 576** (включая `DefaultLimit*` для systemd)
- **Swap** 2G (если ещё не было)
- **journald** ограничен 200 МБ (логи ноды не съедают диск)
- **NIC**: ring buffer 4096, GRO/GSO/TSO on, `txqueuelen 10000`
- **CPU governor** = performance
- **Transparent Huge Pages** = never
- **irqbalance** включён

### 2. Защита (`scripts/protect.sh`)

`nftables`-фаервол, заточенный под VPN-ноду. Лучше fail2ban потому, что:

- работает в **ядре** (zero overhead vs. log-scanning fail2ban),
- ловит **port-scan и невалидные TCP-флаги** до того, как они дойдут до сервиса,
- блокирует **сети сканеров** оптом по ASN, а не реактивно по факту атаки.

Что делает:

- **Politика DROP** на INPUT, белый список только для нужных портов
- **Whitelist** для IP панели/мониторинга — никогда не банится
- **Rate-limit на SSH** (≤6 попыток/мин с одного IP, иначе бан 24 ч)
- **Rate-limit на сервисные порты** (300 RPS TCP, 1000 RPS UDP burst)
- **SYN-flood**: rate-limit + cookies
- **Drop невалидных TCP-флагов** (XMAS, NULL, FIN/SYN и т. п.)
- **ASN-блоклист** TSPU/РКН-сканеров — ~21 ASN, обновление через `whois.radb.net` раз в неделю
- **Spamhaus DROP** — обновление еженедельно
- **Port-scan авто-бан**: SYN на закрытый порт = в `autoban_v4` на 24 ч
- **Stealth-режим**: всё лишнее — `drop`, не `reject` (нода не светит наличие сервиса)
- **Сейфти-таймер**: при первом запуске правила автоматически сбрасываются через 5 мин,
  если не подтвердить, что SSH ещё работает (защита от случайной самоблокировки)

---

## Установка

Репозиторий **публичный** — можно поставить одной командой с сервера.

### Способ 1 — one-liner (`curl`)

```bash
curl -fsSL "https://raw.githubusercontent.com/ded-maxim-1337/remnawave-node-toolkit-geoblock/main/install.sh?$(date +%s)" | sudo bash -s all
```
### Способ 2 — клон + меню

```bash
git clone https://github.com/ded-maxim-1337/remnawave-node-toolkit-geoblock.git
cd remnawave-node-toolkit-geoblock
sudo bash install.sh
```

### Способ 3 — отдельные модули

```bash
sudo bash scripts/optimize.sh
sudo bash scripts/protect.sh
```
### Неинтерактивный режим

```bash
sudo SSH_PORT=22 \
     TCP_PORTS=443,2087 \
     UDP_PORTS=443,2087 \
     NODE_PORT=2222 \
     WHITELIST="1.2.3.4,5.6.7.0/24" \
     REMNAWAVE_NONINTERACTIVE=1 \
     bash scripts/protect.sh
```

---

## Параметры protect.sh

| Переменная | По умолч. | Что |
|---|---|---|
| `SSH_PORT` | авто-детект из `ss`/`sshd_config` | порт SSH |
| `TCP_PORTS` | `443,2087` | сервисные TCP-порты Xray/панели |
| `UDP_PORTS` | `443,2087` | UDP-порты для QUIC/Hysteria/TUIC |
| `NODE_PORT` | `2222` | порт агента ноды; открыт только для IP из `WHITELIST` |
| `WHITELIST` | _обязателен_ | IP/CIDR панели. Пустой список — `protect.sh` завершится с ошибкой |
| `SAFETY_DELAY` | `300` | сек до авто-сброса правил (если не подтвердить) |
| `ENABLE_SCANNER_BLOCK` | `1` | обновлять ASN-блоклист при установке |
| `SCANNER_PREFIX_SOURCE` | `auto` | `auto` — RIPEstat HTTPS, при пустом ответе whois RADB; `ripestat` / `whois` — только один источник |
| `RIPESTAT_TIMEOUT` | `15` | сек на один запрос к stat.ripe.net |
| `ENABLE_SPAMHAUS` | `1` | качать Spamhaus DROP при установке |
| `DRY_RUN` | `0` | `1` — только сгенерировать /etc/nftables.conf и проверить через `nft -c`, без применения |

---

## Откат

```bash
sudo bash install.sh rollback all          # всё
sudo bash install.sh rollback optimize     # только оптимизатор
sudo bash install.sh rollback protect      # только защита
```

Бэкапы оригиналов в `/var/backups/remnawave-toolkit/<timestamp>/`.

---

## Проверка после установки

```bash
# BBR активен?
sysctl net.ipv4.tcp_congestion_control      # → bbr

# Лимиты подняты?
sysctl fs.file-max                           # → 2097152

# nftables правила?
sudo nft list ruleset

# Сколько ASN-префиксов в блок-листе?
sudo nft list set inet rwfilter scanner_v4 | grep -c '/'

# Динамические баны
sudo nft list set inet rwfilter autoban_v4
```

---

## Структура

```
remnawave-node-toolkit-geoblock/
├── install.sh              # точка входа, меню
├── scripts/
│   ├── lib/
│   │   └── common.sh       # общие функции
│   ├── optimize.sh         # модуль 1
│   ├── protect.sh          # модуль 2
│   └── rollback.sh         # откат
├── README.md
└── LICENSE                 # MIT
```

---

## Расширение ASN-листа

Список сканеров в `/etc/remnawave-toolkit/scanner-asns.txt` (создаётся при установке защиты).
Один ASN на строку, комментарии через `#`. Применить новый список:

```bash
sudo /usr/local/sbin/remnawave-update-scanners
```

---

## Лицензия

MIT — делайте что хотите, гарантий нет.
