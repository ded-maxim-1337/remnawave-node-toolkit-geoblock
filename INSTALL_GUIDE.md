# Гайд для установки на Remnawave-ноду

Это короткая инструкция. Полная справка — в `README.md`.

## Что внутри

- **Оптимизатор** (`scripts/optimize.sh`) — BBR, тюнинг sysctl/лимитов/буферов/swap. Без рисков.
- **Защита** (`scripts/protect.sh`) — nftables-фаервол с блок-листом сканеров TSPU/РКН и Spamhaus.
- **Откат** (`scripts/rollback.sh`) — снимает всё.

Поддерживаются Ubuntu 20.04+/24.04, Debian 11/12.

---

## 1. Залить на ноду

С твоей машины (где лежит распакованный toolkit):

```bash
scp -r remnawave-node-toolkit-geoblock root@<IP>:/root/
```

Или через `git clone` с GitHub (см. ниже).

---

## 1б. Репозиторий на GitHub

**Репозиторий:** [github.com/ded-maxim-1337/remnawave-node-toolkit-geoblock](https://github.com/ded-maxim-1337/remnawave-node-toolkit-geoblock) (публичный).

В **`install.sh`** по умолчанию `REPO_URL` указывает на этот же репо на `raw.githubusercontent.com` — удобно для `curl | bash`.

**Установка на VPS (one-liner):**

```bash
curl -fsSL "https://raw.githubusercontent.com/ded-maxim-1337/remnawave-node-toolkit-geoblock/main/install.sh?$(date +%s)" | sudo bash -s all
```

Чтобы **не попадать на старый кэш** `raw.githubusercontent.com`: в URL первого `curl` добавь уникальный query (`?$(date +%s)` — как выше). Сам `install.sh` при скачивании `scripts/*.sh` добавляет свой `nocache=…` (если не отключить `REMNAWAVE_CACHE_BUST=0`).

```text
# старый вариант без bust — CDN мог отдать вчерашний install.sh
curl -fsSL https://raw.githubusercontent.com/ded-maxim-1337/remnawave-node-toolkit-geoblock/main/install.sh | sudo bash -s all
```

Или клон и меню:

```bash
git clone https://github.com/ded-maxim-1337/remnawave-node-toolkit-geoblock.git
cd remnawave-node-toolkit-geoblock
sudo bash install.sh all
```

Первый push с ПК (если настраиваешь репо с нуля):

```bash
git remote add origin https://github.com/ded-maxim-1337/remnawave-node-toolkit-geoblock.git
git branch -M main
git push -u origin main
```

**Если репозиторий снова сделать приватным**, raw-URL перестанет отдавать файлы без авторизации (404) — тогда только `git clone` с ключом или токеном.

---

## 2. Запустить меню

```bash
ssh root@<IP>
cd /root/remnawave-node-toolkit-geoblock
sudo bash install.sh
```

Меню:

```
1) Оптимизатор системы
2) Защита ноды
3) Установить ВСЁ (1 + 2)
4) Откат
0) Выход
```

Сначала жми **1**, потом **2**. Или **3** — за раз.

---

## 3. Что спросит «Защита» (пункт 2)

| Параметр | Что вводить |
|---|---|
| SSH порт | то же что в `/etc/ssh/sshd_config` (по умолчанию 22) |
| TCP порты | через запятую: порты XRay/панели. Обычно `443` |
| UDP порты | UDP-порты для QUIC/Hysteria/TUIC. Обычно `443` |
| Порт node-agent | по умолч. `2222` (порт связи с панелью Remnawave) |
| Whitelist | можно оставить пустым. IP панели скрипт возьмёт сам, если нода уже подключена |

Порядок: сначала обычная нода Remnawave на `2222` и подключение в панели, потом тулкит. Protect смотрит, кто уже сидит на этом порту (и старые allow в ufw/iptables), и оставляет `2222` только для этих IP. В интернет порт не открывается.

**Whitelist** — дополнительные IP, которые никогда не банятся (дом, мониторинг). IP панели туда попадает сам.

Пример: `1.2.3.4,5.6.7.8/32,10.0.0.0/24`

Если активен **UFW** — скрипт предупредит. После установки `protect.sh` UFW лучше отключить:

```bash
systemctl disable --now ufw
```

---

## 4. Сейфти-таймер

Когда `protect.sh` применяет правила, запускается таймер на **5 минут**.
Если SSH соединение отвалится (например, ты случайно забыл whitelist'нуть себя) — через 5 мин правила автоматически сбросятся, и ты снова попадёшь на сервер.

Скрипт спросит «Соединение работает? [y/N]:» — открой ВТОРОЕ окно SSH с другого терминала, проверь что коннект живой, и только потом в **этом же** сеансе, где идёт `protect.sh`, нажми `y`. Это отменит таймер.

Вопрос читается с настоящего терминала (`/dev/tty`), чтобы при установке через `curl | bash` скрипт не «проматывал» `read` из пустого stdin и не пропускал подтверждение.

Если что-то совсем плохое — не паникуй, через 5 мин SSH снова будет.

---

## 5. Проверка после установки

```bash
# BBR активен?
sysctl net.ipv4.tcp_congestion_control      # → bbr

# Лимиты подняты?
sysctl fs.file-max                           # → 2097152

# Фаервол работает?
sudo nft list ruleset | head -40

# Сколько ASN-префиксов TSPU/РКН в блок-листе?
sudo nft list set inet rwfilter scanner_v4 | grep -c '/'
# обычно 5000–15000

# Кого автоматически забанили (за SSH-флуд / port-scan)?
sudo nft list set inet rwfilter autoban_v4
```

---

## 6. Параметры в неинтерактивном режиме

Если ставишь по SSH из своего скрипта/CI, передавай через env:

```bash
sudo SSH_PORT=22 \
     TCP_PORTS=443,8443 \
     UDP_PORTS=443 \
     NODE_PORT=2222 \
     WHITELIST="1.2.3.4,5.6.7.0/24" \
     REMNAWAVE_NONINTERACTIVE=1 \
     bash scripts/protect.sh
```

Доступные переменные:

- `SSH_PORT` — порт SSH (если 0, авто-детект)
- `TCP_PORTS` / `UDP_PORTS` — сервисные порты
- `NODE_PORT` — порт node-agent (2222 по умолч.). Protect оставляет его только для панели
- `WHITELIST` — необязательный доп. список IP/CIDR. Если нода уже подключена к панели, её IP определяется сам
- `SAFETY_DELAY` — секунд до авто-сброса (300 по умолч.)
- `ENABLE_SCANNER_BLOCK=0` — выключить ASN-блок
- `ENABLE_SPAMHAUS=0` — выключить Spamhaus
- `DRY_RUN=1` — только сгенерировать конфиг, не применять
- `REMNAWAVE_NONINTERACTIVE=1` — не задавать вопросов

---

## 7. Откат

Если что-то не нравится:

```bash
sudo bash install.sh rollback all          # снять всё
sudo bash install.sh rollback optimize     # снять только оптимизатор
sudo bash install.sh rollback protect      # снять только защиту
```

Бэкапы оригиналов остаются в `/var/backups/remnawave-toolkit/`.

---

## 8. Возможные проблемы

**SSH отвалился сразу после применения protect.sh:**
Подожди 5 минут, сейфти-таймер сбросит правила.
Потом запусти ещё раз с правильным `WHITELIST`.

**Панель Remnawave не видит ноду после установки:**
Скорее всего IP главной панели не в whitelist. Добавь его:

```bash
sudo nft add element inet rwfilter whitelist_v4 "{ 1.2.3.4 }"
```

И добавь в `/etc/remnawave-toolkit/` если нужно постоянно — проще запустить `protect.sh` ещё раз с обновлённым `WHITELIST`.

**Конфликт с UFW:**
После применения `protect.sh` UFW нужно отключить:

```bash
systemctl disable --now ufw
```

**Скрипт не качает ASN-префиксы:**
По умолчанию префиксы берутся с **HTTPS RIPEstat** (`stat.ripe.net`), резерв — `whois.radb.net:43`. Если у хостера заблокирован исходящий порт 43, ripestat всё равно должен сработать. Режим: переменная `SCANNER_PREFIX_SOURCE` (`auto` / `ripestat` / `whois`).

`whois.radb.net` при режиме `whois` или как запас может тормозить — запусти позже:

```bash
sudo /usr/local/sbin/remnawave-update-scanners
```

**Понять, на каком ASN «висит» или что отвалилось:** в терминале идёт прогресс `[i/N]` и полоска; полный журнал:

```bash
sudo tail -f /var/log/remnawave-toolkit/whois-asn.log
```

---

## 9. Что под капотом (короткое объяснение)

**Оптимизатор:**
BBR + fq_codel вместо CUBIC = +20-40% к скорости TCP.
sysctl-буферы 64M = меньше потерь на жирных каналах.
file-max 2M = тысячи одновременных соединений.

**Защита:**
nftables в ядре = быстрее fail2ban (тот гоняет логи на каждом read).
ASN-блок TSPU/РКН-сканеров = они даже не доходят до сервиса.
Spamhaus DROP = ботнеты сразу в чёрный.
SYN на закрытый порт → авто-бан 24ч = классические сканеры (zmap, masscan) в первом же пакете попадают в blacklist.
6 SSH-попыток/мин с одного IP = бан 24ч (всё это БЕЗ fail2ban).
Stealth-режим: всё лишнее `drop`, не `reject` — сервер не светит наличие.

---

## 10. Лицензия

MIT. Делайте что хотите, гарантий нет.
