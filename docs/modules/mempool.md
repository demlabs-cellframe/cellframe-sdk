# CellFrame Mempool Module (dap_chain_mempool.h)

## Обзор

Модуль `dap_chain_mempool` управляет пулом неподтвержденных транзакций (mempool) в сети CellFrame. Он обеспечивает:

- **Хранение неподтвержденных транзакций** - временное хранение транзакций до включения в блок
- **Фильтрацию и валидацию** - проверка корректности транзакций перед добавлением
- **RPC интерфейс** - удаленный доступ к mempool через JSON-RPC
- **Сериализация данных** - сохранение и восстановление состояния mempool
- **Управление конфликтами** - разрешение конфликтов между транзакциями

## Архитектурная роль

Mempool является буфером между транзакциями пользователей и блокчейн сетью:

```
┌─────────────────┐    ┌─────────────────┐
│   Пользователи  │───▶│   Mempool       │
│   Транзакции    │    └─────────────────┘
         │                       │
    ┌────▼────┐             ┌────▼────┐
    │Валидация  │             │Фильтрация │
    │и проверка │             │& очистка  │
    └─────────┘             └─────────┘
         │                       │
    ┌────▼────┐             ┌────▼────┐
    │Блокчейн   │◄────────────►│База       │
    │сеть       │             │данных     │
    └─────────┘             └─────────┘
```

## Основные структуры данных

### `dap_datum_mempool_t`
```c
typedef struct dap_datum_mempool {
    uint16_t version;                    // Версия структуры
    uint16_t datum_count;                // Количество datum'ов
    dap_chain_datum_t **data;           // Массив datum'ов
} DAP_ALIGN_PACKED dap_datum_mempool_t;
```

Основная структура для хранения массива неподтвержденных datum'ов.

## Константы и статусы

### Версии
```c
#define DAP_DATUM_MEMPOOL_VERSION "01"   // Версия формата mempool
```

### Статусы возврата
```c
#define DAP_CHAIN_MEMPOOl_RET_STATUS_SUCCESS                   0
#define DAP_CHAIN_MEMPOOL_RET_STATUS_BAD_ARGUMENTS           -100
#define DAP_CHAIN_MEMPOOl_RET_STATUS_WRONG_ADDR              -101
#define DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_FIND_FINAL_TX_HASH -102
#define DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_NATIVE_TOKEN        -103
#define DAP_CHAIN_MEMPOOl_RET_STATUS_NO_COND_OUT             -104
#define DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_ENOUGH              -105
#define DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_TX_OUT         -106
#define DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_SIGN           -107
```

### Действия с mempool
```c
enum {
    DAP_DATUM_MEMPOOL_NONE = 0,    // Нет действия
    DAP_DATUM_MEMPOOL_ADD,         // Добавить
    DAP_DATUM_MEMPOOL_CHECK,       // Проверить
    DAP_DATUM_MEMPOOL_DEL          // Удалить
};
```

## Основные функции

### Инициализация и управление

#### `dap_datum_mempool_init()`
```c
int dap_datum_mempool_init(void);
```

Инициализирует систему mempool.

**Возвращаемые значения:**
- `0` - успешная инициализация
- `-1` - ошибка инициализации

### Сериализация и десериализация

#### `dap_datum_mempool_serialize()`
```c
uint8_t* dap_datum_mempool_serialize(dap_datum_mempool_t *datum_mempool,
                                   size_t *size);
```

Сериализует mempool в бинарный формат.

**Параметры:**
- `datum_mempool` - структура mempool для сериализации
- `size` - указатель для размера сериализованных данных

**Возвращаемое значение:**
- Указатель на сериализованные данные или NULL при ошибке

#### `dap_datum_mempool_deserialize()`
```c
dap_datum_mempool_t *dap_datum_mempool_deserialize(uint8_t *datum_mempool_str,
                                                 size_t size);
```

Десериализует mempool из бинарного формата.

**Параметры:**
- `datum_mempool_str` - сериализованные данные
- `size` - размер данных

**Возвращаемое значение:**
- Указатель на восстановленную структуру или NULL при ошибке

### Управление памятью

#### `dap_datum_mempool_clean()`
```c
void dap_datum_mempool_clean(dap_datum_mempool_t *datum);
```

Очищает содержимое mempool без освобождения структуры.

**Параметры:**
- `datum` - структура mempool для очистки

#### `dap_datum_mempool_free()`
```c
void dap_datum_mempool_free(dap_datum_mempool_t *datum);
```

Полностью освобождает структуру mempool и все связанные ресурсы.

**Параметры:**
- `datum` - структура mempool для освобождения

### Добавление datum'ов

#### `dap_chain_mempool_datum_add()`
```c
char *dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum,
                                 dap_chain_t *a_chain,
                                 const char *a_hash_out_type);
```

Добавляет datum в mempool цепочки.

**Параметры:**
- `a_datum` - datum для добавления
- `a_chain` - цепочка для добавления
- `a_hash_out_type` - тип выходного хэша

**Возвращаемое значение:**
- Строка с хэшем добавленного datum'а или NULL при ошибке

### Создание транзакций

#### `dap_chain_mempool_tx_create()`
```c
char *dap_chain_mempool_tx_create(dap_chain_t *a_chain,
                                 dap_enc_key_t *a_key_from,
                                 const dap_chain_addr_t *a_addr_from,
                                 const dap_chain_addr_t **a_addr_to,
                                 const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                 uint256_t* a_value,
                                 uint256_t a_value_fee,
                                 const char *a_hash_out_type,
                                 size_t a_tx_num,
                                 dap_time_t a_time_unlock);
```

Создает и добавляет транзакцию перевода в mempool.

**Параметры:**
- `a_chain` - цепочка
- `a_key_from` - ключ отправителя
- `a_addr_from` - адрес отправителя
- `a_addr_to` - массив адресов получателей
- `a_token_ticker` - тикер токена
- `a_value` - сумма перевода
- `a_value_fee` - комиссия
- `a_hash_out_type` - тип выходного хэша
- `a_tx_num` - количество транзакций
- `a_time_unlock` - время разблокировки (0 для немедленной)

**Возвращаемое значение:**
- Хэш созданной транзакции или NULL при ошибке

#### `dap_chain_mempool_tx_create_cond()`
```c
char* dap_chain_mempool_tx_create_cond(dap_chain_net_t *a_net,
                                      dap_enc_key_t *a_key_from,
                                      dap_pkey_t *a_key_cond,
                                      const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                      uint256_t a_value,
                                      uint256_t a_value_per_unit_max,
                                      dap_chain_net_srv_price_unit_uid_t a_unit,
                                      dap_chain_net_srv_uid_t a_srv_uid,
                                      uint256_t a_value_fee,
                                      const void *a_cond,
                                      size_t a_cond_size,
                                      const char *a_hash_out_type);
```

Создает условную транзакцию.

**Параметры:**
- `a_net` - сеть
- `a_key_from` - ключ отправителя
- `a_key_cond` - ключ условия
- `a_token_ticker` - тикер токена
- `a_value` - сумма
- `a_value_per_unit_max` - максимальная цена за единицу
- `a_unit` - единица измерения
- `a_srv_uid` - UID сервиса
- `a_value_fee` - комиссия
- `a_cond` - условие выполнения
- `a_cond_size` - размер условия
- `a_hash_out_type` - тип выходного хэша

**Возвращаемое значение:**
- Хэш созданной условной транзакции или NULL при ошибке

#### `dap_chain_mempool_tx_create_cond_input()`
```c
char *dap_chain_mempool_tx_create_cond_input(dap_chain_net_t *a_net,
                                           dap_chain_hash_fast_t *a_tx_prev_hash,
                                           const dap_chain_addr_t *a_addr_to,
                                           dap_enc_key_t *a_key_tx_sign,
                                           dap_chain_datum_tx_receipt_t *a_receipt,
                                           const char *a_hash_out_type,
                                           int *a_ret_status);
```

Создает транзакцию на основе условной транзакции.

**Параметры:**
- `a_net` - сеть
- `a_tx_prev_hash` - хэш предыдущей транзакции
- `a_addr_to` - адрес получателя
- `a_key_tx_sign` - ключ для подписи транзакции
- `a_receipt` - квитанция транзакции
- `a_hash_out_type` - тип выходного хэша
- `a_ret_status` - указатель для статуса возврата

**Возвращаемое значение:**
- Хэш созданной транзакции или NULL при ошибке

### Массовые операции

#### `dap_chain_mempool_tx_create_massive()`
```c
int dap_chain_mempool_tx_create_massive(dap_chain_t *a_chain,
                                       dap_enc_key_t *a_key_from,
                                       const dap_chain_addr_t* a_addr_from,
                                       const dap_chain_addr_t* a_addr_to,
                                       const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                       uint256_t a_value,
                                       uint256_t a_value_fee,
                                       size_t a_tx_num);
```

Создает множество одинаковых транзакций.

**Параметры:**
- `a_chain` - цепочка
- `a_key_from` - ключ отправителя
- `a_addr_from` - адрес отправителя
- `a_addr_to` - адрес получателя
- `a_token_ticker` - тикер токена
- `a_value` - сумма на транзакцию
- `a_value_fee` - комиссия на транзакцию
- `a_tx_num` - количество транзакций

**Возвращаемое значение:**
- Код результата операции

### Базовые транзакции

#### `dap_chain_mempool_base_tx_create()`
```c
char *dap_chain_mempool_base_tx_create(dap_chain_t *a_chain,
                                      dap_chain_hash_fast_t *a_emission_hash,
                                      dap_chain_id_t a_emission_chain_id,
                                      uint256_t a_emission_value,
                                      const char *a_ticker,
                                      dap_chain_addr_t *a_addr_to,
                                      dap_enc_key_t *a_private_key,
                                      const char *a_hash_out_type,
                                      uint256_t a_value_fee);
```

Создает базовую транзакцию эмиссии.

**Параметры:**
- `a_chain` - цепочка
- `a_emission_hash` - хэш эмиссии
- `a_emission_chain_id` - ID цепочки эмиссии
- `a_emission_value` - сумма эмиссии
- `a_ticker` - тикер токена
- `a_addr_to` - адрес получателя
- `a_private_key` - приватный ключ для подписи
- `a_hash_out_type` - тип выходного хэша
- `a_value_fee` - комиссия

**Возвращаемое значение:**
- Хэш созданной базовой транзакции или NULL при ошибке

### Получение данных

#### `dap_chain_mempool_datum_get()`
```c
dap_chain_datum_t *dap_chain_mempool_datum_get(dap_chain_t *a_chain,
                                             const char *a_emission_hash_str);
```

Получает datum из mempool по хэшу эмиссии.

**Параметры:**
- `a_chain` - цепочка
- `a_emission_hash_str` - строковое представление хэша

**Возвращаемое значение:**
- Указатель на найденный datum или NULL

#### `dap_chain_mempool_emission_get()`
```c
dap_chain_datum_token_emission_t *dap_chain_mempool_emission_get(
    dap_chain_t *a_chain, const char *a_emission_hash_str);
```

Получает данные эмиссии токена из mempool.

**Параметры:**
- `a_chain` - цепочка
- `a_emission_hash_str` - строковое представление хэша эмиссии

**Возвращаемое значение:**
- Указатель на данные эмиссии или NULL

### Специализированные транзакции

#### `dap_chain_mempool_tx_coll_fee_create()`
```c
char *dap_chain_mempool_tx_coll_fee_create(dap_chain_cs_blocks_t *a_blocks,
                                          dap_enc_key_t *a_key_from,
                                          const dap_chain_addr_t* a_addr_to,
                                          dap_list_t *a_block_list,
                                          uint256_t a_value_fee,
                                          const char *a_hash_out_type);
```

Создает транзакцию сбора комиссий.

**Параметры:**
- `a_blocks` - структура блоков
- `a_key_from` - ключ отправителя
- `a_addr_to` - адрес получателя
- `a_block_list` - список блоков
- `a_value_fee` - сумма комиссии
- `a_hash_out_type` - тип выходного хэша

**Возвращаемое значение:**
- Хэш транзакции сбора комиссий или NULL при ошибке

#### `dap_chain_mempool_tx_reward_create()`
```c
char *dap_chain_mempool_tx_reward_create(dap_chain_cs_blocks_t *a_blocks,
                                        dap_enc_key_t *a_sign_key,
                                        dap_chain_addr_t *a_addr_to,
                                        dap_list_t *a_block_list,
                                        uint256_t a_value_fee,
                                        const char *a_hash_out_type);
```

Создает транзакцию награды за блоки.

**Параметры:**
- `a_blocks` - структура блоков
- `a_sign_key` - ключ для подписи
- `a_addr_to` - адрес получателя награды
- `a_block_list` - список блоков
- `a_value_fee` - комиссия
- `a_hash_out_type` - тип выходного хэша

**Возвращаемое значение:**
- Хэш транзакции награды или NULL при ошибке

## HTTP интерфейс

#### `dap_chain_mempool_add_proc()`
```c
void dap_chain_mempool_add_proc(dap_http_server_t *a_http_server,
                               const char *a_url);
```

Добавляет HTTP обработчики для mempool.

**Параметры:**
- `a_http_server` - HTTP сервер
- `a_url` - базовый URL для mempool API

### Фильтрация

#### `dap_chain_mempool_filter()`
```c
void dap_chain_mempool_filter(dap_chain_t *a_chain, int *a_removed);
```

Фильтрует mempool, удаляя конфликтующие или недействительные транзакции.

**Параметры:**
- `a_chain` - цепочка для фильтрации
- `a_removed` - указатель для количества удаленных элементов

## RPC интерфейс

### Инициализация

#### `dap_chain_mempool_rpc_init()`
```c
int dap_chain_mempool_rpc_init(void);
```

Инициализирует RPC интерфейс для mempool.

**Возвращаемые значения:**
- `0` - успешная инициализация
- `-1` - ошибка инициализации

### Обработчики RPC

#### `dap_chain_mempool_rpc_handler_list()`
```c
void dap_chain_mempool_rpc_handler_list(dap_json_rpc_params_t *a_params,
                                       dap_json_rpc_response_t *a_response,
                                       const char *a_method);
```

Обработчик RPC для получения списка элементов mempool.

**Параметры:**
- `a_params` - параметры RPC запроса
- `a_response` - структура для ответа
- `a_method` - имя RPC метода

#### `dap_chain_mempool_rpc_handler_test()`
```c
void dap_chain_mempool_rpc_handler_test(dap_json_rpc_params_t *a_params,
                                       dap_json_rpc_response_t *a_response,
                                       const char *a_method);
```

Обработчик RPC для тестирования mempool.

**Параметры:**
- `a_params` - параметры RPC запроса
- `a_response` - структура для ответа
- `a_method` - имя RPC метода

## Использование

### Базовое использование mempool

```c
#include "dap_chain_mempool.h"

// Инициализация mempool
if (dap_datum_mempool_init() != 0) {
    fprintf(stderr, "Failed to initialize mempool\n");
    return -1;
}

// Создание простой транзакции
char *tx_hash = dap_chain_mempool_tx_create(
    chain,              // цепочка
    sender_key,         // ключ отправителя
    &sender_addr,       // адрес отправителя
    &recipient_addr,    // адрес получателя
    "KEL",              // тикер токена
    &amount,            // сумма
    fee,                // комиссия
    "hex",              // тип хэша
    1,                  // количество транзакций
    0                   // немедленная разблокировка
);

if (tx_hash) {
    printf("Transaction created with hash: %s\n", tx_hash);
    free(tx_hash);
} else {
    fprintf(stderr, "Failed to create transaction\n");
}
```

### Работа с условными транзакциями

```c
// Создание условной транзакции
char *cond_tx_hash = dap_chain_mempool_tx_create_cond(
    network,            // сеть
    sender_key,         // ключ отправителя
    condition_key,      // ключ условия
    "KEL",              // тикер токена
    amount,             // сумма
    max_price_per_unit, // максимальная цена
    UNIT_KEL,           // единица измерения
    SERVICE_VPN,        // UID сервиса
    fee,                // комиссия
    condition_data,     // данные условия
    condition_size,     // размер условия
    "hex"               // тип хэша
);

if (cond_tx_hash) {
    printf("Conditional transaction created: %s\n", cond_tx_hash);
    free(cond_tx_hash);
}
```

### Сериализация и хранение

```c
// Сериализация mempool для сохранения
size_t serialized_size;
uint8_t *serialized_data = dap_datum_mempool_serialize(
    mempool, &serialized_size);

if (serialized_data) {
    // Сохранение в файл или базу данных
    save_mempool_data(serialized_data, serialized_size);
    free(serialized_data);
}

// Восстановление mempool
dap_datum_mempool_t *restored_mempool = dap_datum_mempool_deserialize(
    saved_data, saved_size);

if (restored_mempool) {
    // Использование восстановленного mempool
    // ...
    dap_datum_mempool_free(restored_mempool);
}
```

### RPC взаимодействие

```c
// Инициализация RPC интерфейса
if (dap_chain_mempool_rpc_init() != 0) {
    fprintf(stderr, "Failed to initialize mempool RPC\n");
    return -1;
}

// Добавление HTTP обработчиков
dap_http_server_t *http_server = dap_http_server_create("mempool_api");
dap_chain_mempool_add_proc(http_server, "/api/v1/mempool");

// Теперь доступны RPC методы:
// GET /api/v1/mempool/list - получить список транзакций
// POST /api/v1/mempool/test - протестировать транзакцию
```

### Фильтрация и очистка

```c
// Фильтрация mempool для удаления конфликтующих транзакций
int removed_count = 0;
dap_chain_mempool_filter(chain, &removed_count);

if (removed_count > 0) {
    printf("Removed %d conflicting transactions from mempool\n", removed_count);
}

// Очистка mempool
dap_datum_mempool_clean(mempool);
```

## Производительность и оптимизации

### Масштабирование
- **Индексация по хэшам** - быстрый поиск транзакций
- **LRU кэширование** - оптимизация часто используемых данных
- **Пакетная обработка** - групповая обработка транзакций
- **Асинхронные операции** - неблокирующие вызовы

### Мониторинг
```c
// Получение статистики mempool
size_t tx_count = get_mempool_transaction_count(chain);
size_t total_size = get_mempool_total_size(chain);
double avg_fee = get_mempool_average_fee(chain);

// Логирование важных событий
log_info("Mempool: %zu transactions, %zu bytes, avg fee: %.8f",
         tx_count, total_size, avg_fee);
```

## Интеграция с другими модулями

### DAP Chain
- Получение подтвержденных транзакций
- Синхронизация с состоянием блокчейна
- Валидация транзакций

### DAP Ledger
- Проверка балансов отправителей
- Верификация токенов
- Отслеживание неподтвержденных транзакций

### DAP HTTP Server
- REST API для внешнего доступа
- WebSocket для real-time обновлений
- Аутентификация и авторизация

### DAP Global DB
- Хранение состояния mempool
- Кэширование часто используемых данных
- Репликация между узлами

## Типичные проблемы

### 1. Конфликты транзакций
```
Симптом: Транзакции отвергаются из-за конфликтов
Решение: Использовать фильтрацию и правильное управление UTXO
```

### 2. Переполнение памяти
```
Симптом: Рост потребления памяти при высокой нагрузке
Решение: Регулярная очистка и лимиты на размер mempool
```

### 3. Задержки подтверждения
```
Симптом: Долгое время ожидания включения в блок
Решение: Оптимизация приоритетов и комиссий
```

### Дополнительные функции создания транзакций

#### `dap_chain_mempool_base_tx_create()`

Создает базовую транзакцию с поддержкой эмиссии токенов.

```c
char *dap_chain_mempool_base_tx_create(
    dap_chain_t *a_chain,                    // Цепочка
    dap_chain_hash_fast_t *a_emission_hash,  // Хеш эмиссии
    dap_chain_id_t a_emission_chain_id,      // ID цепочки эмиссии
    uint256_t a_emission_value,              // Сумма эмиссии
    const char *a_ticker,                    // Тикер токена
    dap_chain_addr_t *a_addr_to,             // Адрес получателя
    dap_enc_key_t *a_private_key,            // Приватный ключ
    const char *a_hash_out_type,             // Тип выходного хеша
    uint256_t a_value_fee                    // Комиссия
);
```

**Особенности:**
- Поддержка эмиссии новых токенов
- Автоматическая валидация параметров эмиссии
- Интеграция с системой эмиссий токенов

#### `dap_chain_mempool_tx_coll_fee_create()`

Создает транзакцию сбора комиссий от коллектора блоков.

```c
char *dap_chain_mempool_tx_coll_fee_create(
    dap_chain_cs_blocks_t *a_blocks,         // Коллектор блоков
    dap_enc_key_t *a_key_from,               // Ключ отправителя
    const dap_chain_addr_t* a_addr_to,       // Адрес получателя
    dap_list_t *a_block_list,                // Список блоков
    uint256_t a_value_fee,                   // Сумма комиссии
    const char *a_hash_out_type              // Тип выходного хеша
);
```

**Использование:**
- Автоматический сбор комиссий от майнинга
- Распределение вознаграждений валидаторам
- Управление экономикой сети

#### `dap_chain_mempool_tx_reward_create()`

Создает транзакцию вознаграждения за найденные блоки.

```c
char *dap_chain_mempool_tx_reward_create(
    dap_chain_cs_blocks_t *a_blocks,         // Коллектор блоков
    dap_enc_key_t *a_sign_key,               // Ключ для подписи
    dap_chain_addr_t *a_addr_to,             // Адрес получателя вознаграждения
    dap_list_t *a_block_list,                // Список блоков
    uint256_t a_value_fee,                   // Комиссия
    const char *a_hash_out_type              // Тип выходного хеша
);
```

**Особенности:**
- Расчет вознаграждений на основе сложности
- Поддержка различных алгоритмов консенсуса
- Автоматическое распределение наград

### Функции управления и фильтрации

#### `dap_chain_mempool_filter()`

Фильтрует и очищает mempool от устаревших или конфликтующих транзакций.

```c
void dap_chain_mempool_filter(
    dap_chain_t *a_chain,    // Цепочка для фильтрации
    int *a_removed          // Количество удаленных транзакций
);
```

**Алгоритм работы:**
1. Проверка конфликтов транзакций
2. Удаление устаревших транзакций
3. Освобождение памяти
4. Обновление статистики

#### `dap_chain_mempool_datum_get()`

Получает datum из mempool по хешу эмиссии.

```c
dap_chain_datum_t *dap_chain_mempool_datum_get(
    dap_chain_t *a_chain,              // Цепочка
    const char *a_emission_hash_str    // Хеш эмиссии в строковом формате
);
```

#### `dap_chain_mempool_emission_get()`

Получает информацию об эмиссии токена из mempool.

```c
dap_chain_datum_token_emission_t *dap_chain_mempool_emission_get(
    dap_chain_t *a_chain,              // Цепочка
    const char *a_emission_hash_str    // Хеш эмиссии
);
```

#### `dap_chain_mempool_datum_emission_extract()`

Извлекает информацию об эмиссии из бинарных данных.

```c
dap_chain_datum_token_emission_t *dap_chain_mempool_datum_emission_extract(
    dap_chain_t *a_chain,     // Цепочка
    byte_t *a_data,          // Бинарные данные
    size_t a_size            // Размер данных
);
```

### Массовые операции

#### `dap_chain_mempool_tx_create_massive()`

Создает большое количество однотипных транзакций для тестирования.

```c
int dap_chain_mempool_tx_create_massive(
    dap_chain_t * a_chain,                      // Цепочка
    dap_enc_key_t *a_key_from,                  // Ключ отправителя
    const dap_chain_addr_t* a_addr_from,        // Адрес отправителя
    const dap_chain_addr_t* a_addr_to,          // Адрес получателя
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX], // Тикер токена
    uint256_t a_value,                          // Сумма перевода
    uint256_t a_value_fee,                      // Комиссия
    size_t a_tx_num                             // Количество транзакций
);
```

**Использование:**
- Нагрузочное тестирование сети
- Генерация тестовых данных
- Симуляция высокой активности

### Операции с datum

#### `dap_chain_mempool_datum_add()`

Добавляет datum в mempool с указанным типом выходного хеша.

```c
char *dap_chain_mempool_datum_add(
    const dap_chain_datum_t *a_datum,    // Datum для добавления
    dap_chain_t *a_chain,               // Цепочка
    const char *a_hash_out_type         // Тип выходного хеша
);
```

**Возвращает:**
- Хеш добавленного datum в указанном формате
- NULL при ошибке

### Утилиты для управления памятью

#### `dap_datum_mempool_clean()`

Очищает содержимое mempool без освобождения структуры.

```c
void dap_datum_mempool_clean(dap_datum_mempool_t *datum);
```

#### `dap_datum_mempool_free()`

Полностью освобождает память, занятую mempool.

```c
void dap_datum_mempool_free(dap_datum_mempool_t *datum);
```

## Заключение

Модуль `dap_chain_mempool` предоставляет надежную и эффективную систему управления неподтвержденными транзакциями в сети CellFrame. Его архитектура обеспечивает высокую производительность, надежность и интеграцию со всей экосистемой блокчейн платформы.
