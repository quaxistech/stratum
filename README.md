# Stratum Server (Bitcoin Core)

Этот проект — упрощённый Stratum-сервер для работы с Bitcoin Core и ASIC-майнерами.
Он **не ведёт учёт наград и статистики**, но реализует базовую работу с заданиями,
проверку шар и отправку найденных блоков в сеть. Код снабжён подробными
комментариями на русском языке.

## Возможности

- Подключение к Bitcoin Core через JSON-RPC.
- Раздача заданий по протоколу Stratum (mining.subscribe / mining.authorize / mining.notify).
- Проверка долей (shares) по целевому уровню сложности.
- Отправка найденных блоков в сеть через `submitblock`.
- Поддержка **auxmining/merged mining**: если Bitcoin Core отдаёт поле `auxiliary`
  в `getblocktemplate`, данные передаются майнерам как дополнительный параметр
  в `mining.notify`.
- Поддержка segwit: используется `default_witness_commitment` из шаблона блока.

## Рекомендованные монеты для merged mining

Ниже приведён список популярных сетей, которые чаще всего используются для merged
mining с Bitcoin (ориентировочно отсортированы по значимости и доходности):

1. **Fractal Bitcoin (FB)** — главный новичок 2025–2026, позиционируется как
   решение для масштабирования Bitcoin.
2. **Rootstock (RSK / RBTC)** — наиболее стабильный источник дополнительного
   дохода. Награда выдаётся в RBTC (Smart Bitcoin), привязанном 1:1 к BTC.
3. **Классическое «трио»**:
   - **Syscoin (SYS)** — активно развивается и использует двухуровневую
     архитектуру (NEVM).
   - **Namecoin (NMC)** — первая сеть с merged mining, остаётся актуальной.
   - **Elastos (ELA)** — проект «интернет-ОС», также майнится вместе с BTC.

Список используется сервером в методе `mining.get_merged_mining_coins`. Его можно
переопределить через параметр `merged_mining_coins` в конфиге.

Для полноценного merged mining также задаётся список aux-цепочек в параметре
`merged_mining_chains`. Для каждой цепочки указываются RPC-параметры и адрес
кошелька, а сервер запрашивает `getauxblock` и передаёт данные майнерам в
`mining.notify` (поле `aux_chains`). Посмотреть список цепочек без секретов можно
через `mining.get_merged_mining_chains`. При отправке доли можно добавить массив
auxpow в `mining.submit` как 6-й параметр:

```json
[
  "worker",
  "job_id",
  "extranonce2",
  "ntime",
  "nonce",
  [
    {"name": "Namecoin", "auxpow": "<hex>"},
    {"name": "Syscoin", "auxpow": "<hex>"}
  ]
]
```

## Сборка

Требования (Ubuntu 24.04):

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libboost-system-dev libcurl4-openssl-dev libssl-dev
```

Сборка:

```bash
cmake -S . -B build
cmake --build build -j
```

## Конфигурация

Пример файла конфигурации: `config.example.json`.

```json
{
  "rpc_url": "http://127.0.0.1:8332",
  "rpc_user": "bitcoinrpc",
  "rpc_password": "secret",
  "bind_address": "0.0.0.0",
  "port": 3333,
  "poll_interval_seconds": 5,
  "default_difficulty": 32,
  "payout_address": "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp0a6f3",
  "extranonce1_size": 4,
  "extranonce2_size": 8,
  "enable_auxpow": true,
  "merged_mining_coins": [
    {
      "rank": 1,
      "name": "Fractal Bitcoin",
      "ticker": "FB",
      "description": "Главная новинка 2025–2026, позиционируется как решение для масштабирования Bitcoin."
    },
    {
      "rank": 2,
      "name": "Rootstock",
      "ticker": "RSK/RBTC",
      "description": "Наиболее стабильный источник дополнительного дохода; RBTC привязан 1:1 к BTC."
    }
  ],
  "merged_mining_chains": [
    {
      "name": "Rootstock",
      "ticker": "RSK",
      "rpc_url": "http://127.0.0.1:4444",
      "rpc_user": "rskrpc",
      "rpc_password": "secret",
      "payout_address": "1RootstockPayoutAddress..."
    },
    {
      "name": "Namecoin",
      "ticker": "NMC",
      "rpc_url": "http://127.0.0.1:8336",
      "rpc_user": "namecoinrpc",
      "rpc_password": "secret",
      "payout_address": "NNamecoinPayoutAddress..."
    }
  ]
}
```

`payout_address` — адрес кошелька для награды (P2PKH/P2SH/Bech32). Сервер сам
конвертирует его в scriptPubKey. Можно указать `payout_script_hex`, чтобы задать
готовый скрипт выплаты вручную.

## Запуск

```bash
./build/stratum_server /path/to/config.json
```

## Systemd сервис

Готовый пример в `deploy/stratum-server.service`. Скопируйте и отредактируйте
пути и пользователя.

```bash
sudo cp deploy/stratum-server.service /etc/systemd/system/stratum-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now stratum-server.service
```

## Важные замечания

- Это упрощённая версия: нет учёта пользователей, выплат и статистики.
- В production окружении важно ограничить доступ к RPC и Stratum по сети.
- Для безопасности используйте отдельного пользователя и firewall.
