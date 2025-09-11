# CellFrame Compose Module (dap_chain_tx_compose.h)

## Обзор

Модуль `dap_chain_tx_compose` предоставляет высокоуровневый API для создания различных типов транзакций в экосистеме CellFrame. Он включает в себя:

- **Универсальные транзакции** - переводы токенов между адресами
- **Обменные операции** - создание ордеров на обмен и их исполнение
- **Условные транзакции** - транзакции с условиями выполнения
- **Staking операции** - блокировка и разблокировка токенов
- **Голосование** - создание и участие в голосованиях
- **Сервисные операции** - взаимодействие с сервисами сети

## Архитектурная роль

Compose модуль является центральным компонентом для создания транзакций в CellFrame SDK:

```
┌─────────────────┐    ┌─────────────────┐
│   CellFrame     │───▶│   Compose       │
│   SDK           │    │   Module        │
└─────────────────┘    └─────────────────┘
         │                       │
    ┌────▼────┐             ┌────▼────┐
    │Транзакции │             │RPC        │
    │разных     │             │запросы    │
    │типов      │             └─────────┘
    └─────────┘
         │
    ┌────▼────┐
    │Подписанные│
    │транзакции │
    │для отправки│
    └─────────┘
```

## Основные структуры данных

### `NetInfo`
```c
typedef struct {
    char name[20];                                    // Имя сети
    char native_ticker[DAP_CHAIN_TICKER_SIZE_MAX];    // Нативный тикер
    dap_chain_net_id_t net_id;                        // ID сети
    char url[128];                                    // URL узла
    uint16_t port;                                     // Порт
} NetInfo;
```

### `compose_config_t`
```c
typedef struct {
    const char *net_name;                    // Имя сети
    const char *url_str;                     // URL для запросов
    const char *cert_path;                   // Путь к сертификату
    uint16_t port;                           // Порт
    bool enc;                                // Шифрование
    json_object *response_handler;           // Обработчик ответов
} compose_config_t;
```

## Предустановленные сети

```c
static NetInfo netinfo[NET_COUNT] = {
    {"riemann",  "tKEL",  {.uint64 = 0x000000000000dddd}, "45.76.140.191", 8081},
    {"raiden",   "tCELL", {.uint64 = 0x000000000000bbbb}, "http://rpc.cellframe.net", 8081},
    {"KelVPN",   "KEL",   {.uint64 = 0x1807202300000000}, "http://rpc.cellframe.net", 8081},
    {"Backbone", "CELL",  {.uint64 = 0x0404202200000000}, "http://rpc.cellframe.net", 8081},
    {"mileena",  "tMIL",  {.uint64 = 0x000000000000cccc}, "http://rpc.cellframe.net", 8081},
    {"subzero",  "tCELL", {.uint64 = 0x000000000000acca}, "http://rpc.cellframe.net", 8081}
};
```

## Основные функции

### Получение информации о сети

#### `dap_compose_get_net_url()`
```c
const char* dap_compose_get_net_url(const char* name);
```

**Параметры:**
- `name` - имя сети

**Возвращаемое значение:**
- URL сети или NULL при ошибке

#### `dap_compose_get_net_port()`
```c
uint16_t dap_compose_get_net_port(const char* name);
```

**Параметры:**
- `name` - имя сети

**Возвращаемое значение:**
- Порт сети

#### `dap_get_net_id()`
```c
dap_chain_net_id_t dap_get_net_id(const char* name);
```

**Параметры:**
- `name` - имя сети

**Возвращаемое значение:**
- ID сети

### Создание транзакций

#### `dap_tx_create_compose()`
```c
json_object* dap_tx_create_compose(const char *l_net_str,
                                 const char *l_token_ticker,
                                 const char *l_value_str,
                                 const char *l_fee_str,
                                 const char *addr_base58_to,
                                 dap_chain_addr_t *l_addr_from,
                                 const char *l_url_str,
                                 uint16_t l_port,
                                 const char *l_enc_cert);
```

Создает базовую транзакцию перевода токенов.

**Параметры:**
- `l_net_str` - имя сети
- `l_token_ticker` - тикер токена
- `l_value_str` - сумма перевода
- `l_fee_str` - комиссия
- `addr_base58_to` - адрес получателя (base58)
- `l_addr_from` - адрес отправителя
- `l_url_str` - URL RPC сервера
- `l_port` - порт RPC сервера
- `l_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект транзакции или NULL при ошибке

#### `dap_tx_create_xchange_compose()`
```c
json_object* dap_tx_create_xchange_compose(const char *l_net_str,
                                         const char *l_token_sell,
                                         const char *l_token_buy,
                                         dap_chain_addr_t *l_wallet_addr,
                                         const char *l_value_str,
                                         const char *l_rate_str,
                                         const char *l_fee_str,
                                         const char *l_url_str,
                                         uint16_t l_port,
                                         const char *l_enc_cert);
```

Создает транзакцию обмена токенов.

**Параметры:**
- `l_net_str` - имя сети
- `l_token_sell` - тикер продаваемого токена
- `l_token_buy` - тикер покупаемого токена
- `l_wallet_addr` - адрес кошелька
- `l_value_str` - сумма продажи
- `l_rate_str` - курс обмена
- `l_fee_str` - комиссия
- `l_url_str` - URL RPC сервера
- `l_port` - порт RPC сервера
- `l_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект транзакции обмена или NULL при ошибке

#### `dap_tx_cond_create_compose()`
```c
json_object* dap_tx_cond_create_compose(const char *a_net_name,
                                      const char *a_token_ticker,
                                      dap_chain_addr_t *a_wallet_addr,
                                      const char *a_cert_str,
                                      const char *a_value_datoshi_str,
                                      const char *a_value_fee_str,
                                      const char *a_unit_str,
                                      const char *a_value_per_unit_max_str,
                                      const char *a_srv_uid_str,
                                      const char *a_url_str,
                                      uint16_t a_port,
                                      const char *a_enc_cert);
```

Создает условную транзакцию для сервисов.

**Параметры:**
- `a_net_name` - имя сети
- `a_token_ticker` - тикер токена
- `a_wallet_addr` - адрес кошелька
- `a_cert_str` - сертификат
- `a_value_datoshi_str` - сумма в датошах
- `a_value_fee_str` - комиссия
- `a_unit_str` - единица измерения
- `a_value_per_unit_max_str` - максимальная цена за единицу
- `a_srv_uid_str` - UID сервиса
- `a_url_str` - URL RPC сервера
- `a_port` - порт RPC сервера
- `a_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект условной транзакции или NULL при ошибке

### Работа с кошельком

#### `dap_get_remote_wallet_outs_and_count()`
```c
bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from,
                                        const char *a_token_ticker,
                                        json_object **l_outs,
                                        int *l_outputs_count,
                                        compose_config_t *a_config);
```

Получает выходы кошелька и их количество для указанного токена.

**Параметры:**
- `a_addr_from` - адрес кошелька
- `a_token_ticker` - тикер токена
- `l_outs` - указатель для массива выходов
- `l_outputs_count` - указатель для количества выходов
- `a_config` - конфигурация compose

**Возвращаемое значение:**
- `true` при успехе, `false` при ошибке

#### `dap_get_remote_net_fee_and_address()`
```c
bool dap_get_remote_net_fee_and_address(uint256_t *a_net_fee,
                                      dap_chain_addr_t **l_addr_fee,
                                      compose_config_t *a_config);
```

Получает сетевую комиссию и адрес для сборов.

**Параметры:**
- `a_net_fee` - указатель для сетевой комиссии
- `l_addr_fee` - указатель для адреса сборов
- `a_config` - конфигурация compose

**Возвращаемое значение:**
- `true` при успехе, `false` при ошибке

### Работа с RPC

#### `dap_request_command_to_rpc()`
```c
json_object* dap_request_command_to_rpc(const char *request,
                                      compose_config_t *a_config);
```

Отправляет команду на RPC сервер.

**Параметры:**
- `request` - JSON запрос
- `a_config` - конфигурация compose

**Возвращаемое значение:**
- JSON ответ от сервера или NULL при ошибке

#### `dap_request_command_to_rpc_with_params()`
```c
json_object* dap_request_command_to_rpc_with_params(compose_config_t *a_config,
                                                  const char *a_method,
                                                  const char *msg, ...);
```

Отправляет команду с параметрами на RPC сервер.

**Параметры:**
- `a_config` - конфигурация compose
- `a_method` - метод RPC
- `msg` - сообщение с параметрами
- `...` - дополнительные параметры

**Возвращаемое значение:**
- JSON ответ от сервера или NULL при ошибке

## RPC коммуникации

### `dap_enc_request_command_to_rpc()`
```c
json_object* dap_enc_request_command_to_rpc(const char *a_request,
                                           const char *a_url,
                                           uint16_t a_port,
                                           const char *a_cert_path);
```

Отправляет зашифрованный RPC запрос.

**Параметры:**
- `a_request` - RPC запрос
- `a_url` - URL узла
- `a_port` - порт
- `a_cert_path` - путь к сертификату

**Возвращаемое значение:**
- JSON ответ или NULL при ошибке

### `dap_request_command_to_rpc()`
```c
json_object* dap_request_command_to_rpc(const char *request,
                                       compose_config_t *a_config);
```

Отправляет RPC запрос с конфигурацией.

**Параметры:**
- `request` - RPC запрос
- `a_config` - конфигурация compose

**Возвращаемое значение:**
- JSON ответ или NULL при ошибке

### `dap_request_command_to_rpc_with_params()`
```c
json_object* dap_request_command_to_rpc_with_params(compose_config_t *a_config,
                                                   const char *a_method,
                                                   const char *msg, ...);
```

Отправляет RPC запрос с параметрами.

**Параметры:**
- `a_config` - конфигурация compose
- `a_method` - RPC метод
- `msg` - сообщение
- `...` - дополнительные параметры

**Возвращаемое значение:**
- JSON ответ или NULL при ошибке

## Работа с сетевыми данными

### `dap_get_remote_net_fee_and_address()`
```c
bool dap_get_remote_net_fee_and_address(uint256_t *a_net_fee,
                                       dap_chain_addr_t **l_addr_fee,
                                       compose_config_t *a_config);
```

Получает сетевую комиссию и адрес для сборов.

**Параметры:**
- `a_net_fee` - указатель для сетевой комиссии
- `l_addr_fee` - указатель для адреса сборов
- `a_config` - конфигурация compose

**Возвращаемое значение:**
- `true` - успешное получение
- `false` - ошибка

### `dap_get_remote_wallet_outs_and_count()`
```c
bool dap_get_remote_wallet_outs_and_count(dap_chain_addr_t *a_addr_from,
                                         const char *a_token_ticker,
                                         json_object **l_outs,
                                         int *l_outputs_count,
                                         compose_config_t *a_config);
```

Получает выходы кошелька и их количество.

**Параметры:**
- `a_addr_from` - адрес отправителя
- `a_token_ticker` - тикер токена
- `l_outs` - указатель для выходов
- `l_outputs_count` - указатель для количества выходов
- `a_config` - конфигурация compose

**Возвращаемое значение:**
- `true` - успешное получение
- `false` - ошибка

## Создание базовых транзакций

### `dap_tx_create_compose()`
```c
json_object* dap_tx_create_compose(const char *l_net_str,
                                  const char *l_token_ticker,
                                  const char *l_value_str,
                                  const char *l_fee_str,
                                  const char *addr_base58_to,
                                  dap_chain_addr_t *l_addr_from,
                                  const char *l_url_str,
                                  uint16_t l_port,
                                  const char *l_enc_cert);
```

Создает базовую транзакцию перевода.

**Параметры:**
- `l_net_str` - имя сети
- `l_token_ticker` - тикер токена
- `l_value_str` - сумма перевода (строка)
- `l_fee_str` - комиссия (строка)
- `addr_base58_to` - адрес получателя (base58)
- `l_addr_from` - адрес отправителя
- `l_url_str` - URL узла
- `l_port` - порт
- `l_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект транзакции или NULL при ошибке

### `dap_chain_datum_tx_create_compose()`
```c
dap_chain_datum_tx_t* dap_chain_datum_tx_create_compose(
    dap_chain_addr_t* a_addr_from,
    dap_chain_addr_t** a_addr_to,
    const char* a_token_ticker,
    uint256_t *a_value,
    uint256_t a_value_fee,
    size_t a_tx_num,
    compose_config_t *a_config);
```

Создает datum транзакции для перевода.

**Параметры:**
- `a_addr_from` - адрес отправителя
- `a_addr_to` - массив адресов получателей
- `a_token_ticker` - тикер токена
- `a_value` - сумма
- `a_value_fee` - комиссия
- `a_tx_num` - количество транзакций
- `a_config` - конфигурация compose

**Возвращаемое значение:**
- Сформированная транзакция или NULL при ошибке

## Обменные операции

### `dap_tx_create_xchange_compose()`
```c
json_object* dap_tx_create_xchange_compose(const char *l_net_str,
                                          const char *l_token_sell,
                                          const char *l_token_buy,
                                          dap_chain_addr_t *l_wallet_addr,
                                          const char *l_value_str,
                                          const char *l_rate_str,
                                          const char *l_fee_str,
                                          const char *l_url_str,
                                          uint16_t l_port,
                                          const char *l_enc_cert);
```

Создает ордер на обмен токенов.

**Параметры:**
- `l_net_str` - имя сети
- `l_token_sell` - токен для продажи
- `l_token_buy` - токен для покупки
- `l_wallet_addr` - адрес кошелька
- `l_value_str` - сумма для продажи
- `l_rate_str` - курс обмена
- `l_fee_str` - комиссия
- `l_url_str` - URL узла
- `l_port` - порт
- `l_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект ордера или NULL при ошибке

### `dap_chain_net_srv_xchange_create_compose()`
```c
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(
    const char *a_token_buy,
    const char *a_token_sell,
    uint256_t a_datoshi_sell,
    uint256_t a_rate,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr,
    compose_config_t *a_config);
```

Создает datum для обменного сервиса.

**Параметры:**
- `a_token_buy` - токен для покупки
- `a_token_sell` - токен для продажи
- `a_datoshi_sell` - сумма продажи в датоси
- `a_rate` - курс обмена
- `a_fee` - комиссия
- `a_wallet_addr` - адрес кошелька
- `a_config` - конфигурация compose

**Возвращаемое значение:**
- Сформированная транзакция или NULL при ошибке

### `dap_cli_xchange_purchase_compose()`
```c
json_object* dap_cli_xchange_purchase_compose(const char *a_net_name,
                                             const char *a_order_hash,
                                             const char* a_value,
                                             const char* a_fee,
                                             const char *a_wallet_name,
                                             const char *a_wallet_path,
                                             const char *a_url_str,
                                             uint16_t a_port,
                                             const char *a_enc_cert);
```

Создает покупку по существующему ордеру.

**Параметры:**
- `a_net_name` - имя сети
- `a_order_hash` - хэш ордера
- `a_value` - сумма покупки
- `a_fee` - комиссия
- `a_wallet_name` - имя кошелька
- `a_wallet_path` - путь к кошельку
- `a_url_str` - URL узла
- `a_port` - порт
- `a_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект транзакции покупки или NULL при ошибке

## Условные транзакции

### `dap_tx_cond_create_compose()`
```c
json_object* dap_tx_cond_create_compose(const char *a_net_name,
                                       const char *a_token_ticker,
                                       dap_chain_addr_t *a_wallet_addr,
                                       const char *a_cert_str,
                                       const char *a_value_datoshi_str,
                                       const char *a_value_fee_str,
                                       const char *a_unit_str,
                                       const char *a_value_per_unit_max_str,
                                       const char *a_srv_uid_str,
                                       const char *a_url_str,
                                       uint16_t a_port,
                                       const char *a_enc_cert);
```

Создает условную транзакцию.

**Параметры:**
- `a_net_name` - имя сети
- `a_token_ticker` - тикер токена
- `a_wallet_addr` - адрес кошелька
- `a_cert_str` - сертификат
- `a_value_datoshi_str` - сумма в датоси
- `a_value_fee_str` - комиссия
- `a_unit_str` - единица измерения
- `a_value_per_unit_max_str` - максимальная цена за единицу
- `a_srv_uid_str` - UID сервиса
- `a_url_str` - URL узла
- `a_port` - порт
- `a_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект условной транзакции или NULL при ошибке

## Staking операции

### `dap_cli_hold_compose()`
```c
json_object* dap_cli_hold_compose(const char *a_net_name,
                                 const char *a_chain_id_str,
                                 const char *a_ticker_str,
                                 dap_chain_addr_t *a_wallet_addr,
                                 const char *a_coins_str,
                                 const char *a_time_staking_str,
                                 const char *a_cert_str,
                                 const char *a_value_fee_str,
                                 const char *a_reinvest_percent_str,
                                 const char *a_url_str,
                                 uint16_t a_port,
                                 const char *a_enc_cert);
```

Создает транзакцию блокировки токенов для staking.

**Параметры:**
- `a_net_name` - имя сети
- `a_chain_id_str` - ID цепочки
- `a_ticker_str` - тикер токена
- `a_wallet_addr` - адрес кошелька
- `a_coins_str` - сумма блокировки
- `a_time_staking_str` - время staking
- `a_cert_str` - сертификат
- `a_value_fee_str` - комиссия
- `a_reinvest_percent_str` - процент реинвестирования
- `a_url_str` - URL узла
- `a_port` - порт
- `a_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект staking транзакции или NULL при ошибке

### `dap_cli_take_compose()`
```c
json_object* dap_cli_take_compose(const char *a_net_name,
                                 const char *a_chain_id_str,
                                 dap_chain_addr_t *a_wallet_addr,
                                 const char *a_tx_str,
                                 const char *a_value_fee_str,
                                 const char *a_url_str,
                                 uint16_t a_port,
                                 const char *a_enc_cert);
```

Создает транзакцию разблокировки staking.

**Параметры:**
- `a_net_name` - имя сети
- `a_chain_id_str` - ID цепочки
- `a_wallet_addr` - адрес кошелька
- `a_tx_str` - хэш staking транзакции
- `a_value_fee_str` - комиссия
- `a_url_str` - URL узла
- `a_port` - порт
- `a_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект транзакции разблокировки или NULL при ошибке

### `dap_cli_srv_stake_delegate_compose()`
```c
json_object* dap_cli_srv_stake_delegate_compose(const char* a_net_str,
                                               dap_chain_addr_t *a_wallet_addr,
                                               const char* a_cert_str,
                                               const char* a_pkey_full_str,
                                               const char* a_value_str,
                                               const char* a_node_addr_str,
                                               const char* a_order_hash_str,
                                               const char* a_url_str,
                                               uint16_t a_port,
                                               const char* a_sovereign_addr_str,
                                               const char* a_fee_str,
                                               const char *a_enc_cert);
```

Создает делегированный staking.

**Параметры:**
- `a_net_str` - имя сети
- `a_wallet_addr` - адрес кошелька
- `a_cert_str` - сертификат
- `a_pkey_full_str` - полный публичный ключ
- `a_value_str` - сумма делегирования
- `a_node_addr_str` - адрес ноды
- `a_order_hash_str` - хэш ордера
- `a_url_str` - URL узла
- `a_port` - порт
- `a_sovereign_addr_str` - суверенный адрес
- `a_fee_str` - комиссия
- `a_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект делегированного staking или NULL при ошибке

## Голосование

### `dap_cli_voting_compose()`
```c
json_object* dap_cli_voting_compose(const char *a_net_name,
                                   const char *a_question_str,
                                   const char *a_options_list_str,
                                   const char *a_voting_expire_str,
                                   const char *a_max_votes_count_str,
                                   const char *a_fee_str,
                                   bool a_is_delegated_key,
                                   bool a_is_vote_changing_allowed,
                                   dap_chain_addr_t *a_wallet_addr,
                                   const char *a_token_str,
                                   const char *a_url_str,
                                   uint16_t a_port,
                                   const char *a_enc_cert);
```

Создает голосование.

**Параметры:**
- `a_net_name` - имя сети
- `a_question_str` - вопрос голосования
- `a_options_list_str` - список вариантов ответа
- `a_voting_expire_str` - время окончания голосования
- `a_max_votes_count_str` - максимальное количество голосов
- `a_fee_str` - комиссия
- `a_is_delegated_key` - использовать делегированный ключ
- `a_is_vote_changing_allowed` - разрешить изменение голоса
- `a_wallet_addr` - адрес кошелька
- `a_token_str` - токен для голосования
- `a_url_str` - URL узла
- `a_port` - порт
- `a_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект голосования или NULL при ошибке

### `dap_cli_vote_compose()`
```c
json_object* dap_cli_vote_compose(const char *a_net_str,
                                 const char *a_hash_str,
                                 const char *a_cert_name,
                                 const char *a_fee_str,
                                 dap_chain_addr_t *a_wallet_addr,
                                 const char *a_option_idx_str,
                                 const char *a_url_str,
                                 uint16_t a_port,
                                 const char *a_enc_cert);
```

Создает голос в существующем голосовании.

**Параметры:**
- `a_net_str` - имя сети
- `a_hash_str` - хэш голосования
- `a_cert_name` - имя сертификата
- `a_fee_str` - комиссия
- `a_wallet_addr` - адрес кошелька
- `a_option_idx_str` - индекс выбранного варианта
- `a_url_str` - URL узла
- `a_port` - порт
- `a_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект голоса или NULL при ошибке

## Сервисные операции

### `dap_cli_srv_stake_order_create_staker_compose()`
```c
json_object* dap_cli_srv_stake_order_create_staker_compose(
    const char *l_net_str,
    const char *l_value_str,
    const char *l_fee_str,
    const char *l_tax_str,
    const char *l_addr_str,
    dap_chain_addr_t *a_wallet_addr,
    const char *l_url_str,
    uint16_t l_port,
    const char *l_enc_cert);
```

Создает ордер на staking для сервиса.

**Параметры:**
- `l_net_str` - имя сети
- `l_value_str` - сумма staking
- `l_fee_str` - комиссия
- `l_tax_str` - налог
- `l_addr_str` - адрес
- `a_wallet_addr` - адрес кошелька
- `l_url_str` - URL узла
- `l_port` - порт
- `l_enc_cert` - сертификат шифрования

**Возвращаемое значение:**
- JSON объект ордера staking или NULL при ошибке

## Вспомогательные функции

### `dap_tx_json_tsd_add()`
```c
int dap_tx_json_tsd_add(json_object *json_tx, json_object *json_add);
```

Добавляет TSD к JSON транзакции.

**Параметры:**
- `json_tx` - JSON транзакция
- `json_add` - JSON для добавления

**Возвращаемое значение:**
- Код результата операции

### `check_token_in_ledger()`
```c
bool check_token_in_ledger(json_object *l_json_coins, const char *a_token);
```

Проверяет наличие токена в ledger.

**Параметры:**
- `l_json_coins` - JSON с монетами
- `a_token` - имя токена

**Возвращаемое значение:**
- `true` - токен найден
- `false` - токен не найден

### `dap_ledger_get_list_tx_outs_from_json()`
```c
dap_list_t *dap_ledger_get_list_tx_outs_from_json(json_object *a_outputs_array,
                                                 int a_outputs_count,
                                                 uint256_t a_value_need,
                                                 uint256_t *a_value_transfer);
```

Получает список выходов транзакций из JSON.

**Параметры:**
- `a_outputs_array` - массив выходов
- `a_outputs_count` - количество выходов
- `a_value_need` - требуемая сумма
- `a_value_transfer` - указатель для суммы перевода

**Возвращаемое значение:**
- Список выходов или NULL при ошибке

## Использование

### Базовый перевод токенов

```c
#include "dap_chain_tx_compose.h"

// Настройка конфигурации
compose_config_t config = {
    .net_name = "KelVPN",
    .url_str = "http://rpc.cellframe.net",
    .port = 8081,
    .enc = false
};

// Создание транзакции перевода
json_object *tx = dap_tx_create_compose(
    "KelVPN",           // сеть
    "KEL",              // токен
    "100.0",            // сумма
    "0.001",            // комиссия
    "base58_address",   // адрес получателя
    &sender_addr,       // адрес отправителя
    config.url_str,     // URL узла
    config.port,        // порт
    NULL                // сертификат
);

if (tx) {
    // Отправка транзакции в сеть
    // ...
    json_object_put(tx);
}
```

### Создание ордера на обмен

```c
// Создание ордера на обмен KEL -> CELL
json_object *order = dap_tx_create_xchange_compose(
    "KelVPN",           // сеть
    "KEL",              // продаем
    "CELL",             // покупаем
    &wallet_addr,       // адрес кошелька
    "50.0",             // сумма продажи
    "2.5",              // курс (1 KEL = 2.5 CELL)
    "0.001",            // комиссия
    config.url_str,
    config.port,
    NULL
);

if (order) {
    // Публикация ордера
    // ...
    json_object_put(order);
}
```

### Staking токенов

```c
// Создание staking транзакции
json_object *stake_tx = dap_cli_hold_compose(
    "KelVPN",           // сеть
    "main",             // цепочка
    "KEL",              // токен
    &wallet_addr,       // адрес кошелька
    "1000.0",           // сумма блокировки
    "2592000",          // время в секундах (30 дней)
    "cert.pem",         // сертификат
    "0.01",             // комиссия
    "10",               // процент реинвестирования
    config.url_str,
    config.port,
    NULL
);

if (stake_tx) {
    // Подписание и отправка транзакции
    // ...
    json_object_put(stake_tx);
}
```

### Создание голосования

```c
// Создание голосования
json_object *voting = dap_cli_voting_compose(
    "KelVPN",                               // сеть
    "Should we increase block size?",       // вопрос
    "Yes,No,Abstain",                       // варианты
    "1640995200",                           // время окончания (timestamp)
    "10000",                                // максимум голосов
    "0.01",                                 // комиссия
    false,                                  // не делегированный ключ
    true,                                   // разрешить изменение голоса
    &wallet_addr,                           // адрес кошелька
    "KEL",                                  // токен для голосования
    config.url_str,
    config.port,
    NULL
);

if (voting) {
    // Публикация голосования
    // ...
    json_object_put(voting);
}
```

### `dap_xchange_tx_create_request_compose()`

Создает запрос на обмен токенов на основе цены продавца.

```c
dap_chain_datum_tx_t* dap_xchange_tx_create_request_compose(
    dap_chain_net_srv_xchange_price_t *a_price,        // Цена продавца
    dap_chain_addr_t *a_seller_addr,                   // Адрес продавца
    const char *a_native_ticker,                       // Нативный тикер
    compose_config_t *a_config                         // Конфигурация compose
);
```

### `dap_chain_mempool_tx_create_cond_compose()`

Создает условную транзакцию в mempool с заданными условиями.

```c
dap_chain_datum_tx_t* dap_chain_mempool_tx_create_cond_compose(
    dap_chain_addr_t *a_wallet_addr,                         // Адрес кошелька
    dap_pkey_t *a_key_cond,                                 // Ключ условия
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],   // Тикер токена
    uint256_t a_value,                                      // Сумма
    uint256_t a_value_per_unit_max,                         // Максимальная сумма за единицу
    dap_chain_net_srv_price_unit_uid_t a_unit,              // Единица измерения цены
    dap_chain_net_srv_uid_t a_srv_uid,                      // UID сервиса
    uint256_t a_value_fee,                                  // Комиссия
    const void *a_cond,                                     // Условие
    size_t a_cond_size,                                     // Размер условия
    compose_config_t *a_config                              // Конфигурация compose
);
```

### `dap_stake_lock_datum_create_compose()`

Создает datum для блокировки токенов в staking с возможностью делегирования.

```c
dap_chain_datum_tx_t* dap_stake_lock_datum_create_compose(
    dap_chain_addr_t *a_wallet_addr,          // Адрес кошелька
    const char *a_main_ticker,               // Основной тикер
    uint256_t a_value,                       // Сумма блокировки
    uint256_t a_value_fee,                   // Комиссия
    dap_time_t a_time_staking,               // Время staking
    uint256_t a_reinvest_percent,            // Процент реинвестирования
    const char *a_delegated_ticker_str,      // Делегированный тикер
    uint256_t a_delegated_value,             // Делегированная сумма
    const char *a_chain_id_str,              // ID цепочки
    compose_config_t *a_config               // Конфигурация compose
);
```

### `dap_stake_unlock_datum_create_compose()`

Создает datum для разблокировки ранее застейканных токенов.

```c
dap_chain_datum_tx_t* dap_stake_unlock_datum_create_compose(
    dap_chain_addr_t *a_wallet_addr,          // Адрес кошелька
    dap_hash_fast_t *a_stake_tx_hash,        // Хеш staking транзакции
    uint32_t a_prev_cond_idx,                // Индекс предыдущего условия
    const char *a_main_ticker,               // Основной тикер
    uint256_t a_value,                       // Сумма разблокировки
    uint256_t a_value_fee,                   // Комиссия
    const char *a_delegated_ticker_str,      // Делегированный тикер
    uint256_t a_delegated_value,             // Делегированная сумма
    compose_config_t *a_config               // Конфигурация compose
);
```

### `dap_chain_net_vote_create_compose()`

Создает голосование в сети с заданными параметрами.

```c
dap_chain_datum_tx_t* dap_chain_net_vote_create_compose(
    const char *a_question,                    // Вопрос голосования
    dap_list_t *a_options,                    // Список вариантов
    dap_time_t a_expire_vote,                 // Время окончания
    uint64_t a_max_vote,                      // Максимальное количество голосов
    uint256_t a_fee,                          // Комиссия
    bool a_delegated_key_required,            // Требуется делегированный ключ
    bool a_vote_changing_allowed,             // Разрешено менять голос
    dap_chain_addr_t *a_wallet_addr,          // Адрес кошелька
    const char *a_token_ticker,               // Тикер токена
    compose_config_t *a_config                // Конфигурация compose
);
```

### `dap_stake_tx_create_compose()`

Создает транзакцию staking с поддержкой делегирования и налогов.

```c
dap_chain_datum_tx_t* dap_stake_tx_create_compose(
    dap_chain_addr_t *a_wallet_addr,          // Адрес кошелька
    uint256_t a_value,                       // Сумма staking
    uint256_t a_fee,                         // Комиссия
    dap_chain_addr_t *a_signing_addr,        // Адрес для подписи
    dap_chain_node_addr_t *a_node_addr,      // Адрес узла
    dap_chain_addr_t *a_sovereign_addr,      // Суверенный адрес
    uint256_t a_sovereign_tax,               // Суверенный налог
    dap_chain_datum_tx_t *a_prev_tx,         // Предыдущая транзакция
    dap_pkey_t *a_pkey,                      // Приватный ключ
    compose_config_t *a_config               // Конфигурация compose
);
```

### `dap_chain_net_srv_xchange_purchase_compose()`

Создает транзакцию покупки через сервис обмена с возвратом хеша.

```c
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_purchase_compose(
    dap_hash_fast_t *a_order_hash,            // Хеш ордера
    uint256_t a_value,                       // Сумма покупки
    uint256_t a_fee,                         // Комиссия
    dap_chain_addr_t *a_wallet_addr,          // Адрес кошелька
    char **a_hash_out,                       // Выходной хеш
    compose_config_t *a_config               // Конфигурация compose
);
```

### `dap_xchange_tx_create_exchange_compose()`

Создает транзакцию обмена с условными выходами.

```c
dap_chain_datum_tx_t* dap_xchange_tx_create_exchange_compose(
    dap_chain_net_srv_xchange_price_t *a_price,      // Цена обмена
    dap_chain_addr_t *a_buyer_addr,                  // Адрес покупателя
    uint256_t a_datoshi_buy,                         // Сумма покупки в датоси
    uint256_t a_datoshi_fee,                         // Комиссия в датоси
    dap_chain_tx_out_cond_t* a_cond_tx,              // Условная транзакция
    uint32_t a_prev_cond_idx,                        // Индекс предыдущего условия
    compose_config_t *a_config                       // Конфигурация compose
);
```

## Заключение

Модуль `dap_chain_tx_compose` предоставляет полный набор функций для создания различных типов транзакций в экосистеме CellFrame. Его гибкий API позволяет разработчикам создавать сложные финансовые операции, управлять staking'ом, участвовать в голосованиях и взаимодействовать с сервисами сети.
