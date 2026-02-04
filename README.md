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
  "payout_script_hex": "76a914000000000000000000000000000000000000000088ac",
  "extranonce1_size": 4,
  "extranonce2_size": 8,
  "enable_auxpow": true
}
```

`payout_script_hex` — это скрипт выплаты в формате hex (например, P2PKH/P2WPKH/P2SH).

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

