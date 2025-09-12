# Common Module - Общие компоненты CellFrame SDK

## Обзор

Common Module предоставляет общие структуры данных, утилиты и базовую функциональность, используемую всеми остальными модулями CellFrame SDK. Этот модуль содержит фундаментальные типы данных и вспомогательные функции.

## Структура модуля

```
modules/common/
├── include/                    # Заголовочные файлы
│   ├── dap_chain_common.h      # Общие структуры цепочки
│   ├── dap_chain_datum.h       # Структуры данных
│   ├── dap_chain_datum_anchor.h # Якоря данных
│   ├── dap_chain_datum_decree.h # Декреты
│   ├── dap_chain_datum_hashtree_roots.h # Корни хеш-деревьев
│   ├── dap_chain_datum_poll.h  # Опросы
│   ├── dap_chain_datum_token.h # Токены
│   ├── dap_chain_datum_tx_receipt.h # Квитанции транзакций
│   ├── dap_chain_datum_tx_voting.h # Голосования
│   └── dap_chain_datum_tx.h    # Основные структуры транзакций
├── src/                        # Исходный код
│   ├── dap_chain_common.c
│   ├── dap_chain_datum.c
│   └── [другие реализации]
├── tests/                      # Тесты
└── docs/                       # Документация
```

## Основные структуры данных

### Базовые типы и константы

```c
// Основные типы данных
typedef uint64_t dap_chain_id_t;
typedef uint64_t dap_chain_cell_id_t;
typedef uint64_t dap_chain_net_id_t;
typedef uint256_t dap_chain_hash_t;
typedef uint64_t dap_chain_addr_t;
typedef uint64_t dap_chain_time_t;

// Константы размеров
#define DAP_CHAIN_HASH_SIZE 32
#define DAP_CHAIN_ADDR_SIZE 20
#define DAP_CHAIN_ID_SIZE 8
#define DAP_CHAIN_CELL_ID_SIZE 8
```

### Структура хеша

```c
typedef union dap_chain_hash {
    uint8_t raw[DAP_CHAIN_HASH_SIZE];    // Сырые байты хеша
    struct {
        uint64_t part1;                  // Первая часть (для сравнения)
        uint64_t part2;                  // Вторая часть
        uint64_t part3;                  // Третья часть
        uint64_t part4;                  // Четвертая часть
    } parts;
} dap_chain_hash_t;
```

### Структура адреса

```c
typedef struct dap_chain_addr {
    uint8_t addr[DAP_CHAIN_ADDR_SIZE];   // Байты адреса
    uint8_t type;                        // Тип адреса
} dap_chain_addr_t;
```

## Данные цепочки (Datum)

### Базовая структура данных

```c
typedef struct dap_chain_datum {
    uint8_t version;                     // Версия структуры
    dap_chain_datum_type_t type;         // Тип данных
    uint64_t timestamp;                  // Временная метка
    uint64_t data_size;                  // Размер данных
    uint8_t data[];                      // Данные (flexible array)
} dap_chain_datum_t;

typedef enum dap_chain_datum_type {
    DAP_CHAIN_DATUM_TOKEN = 1,           // Токен
    DAP_CHAIN_DATUM_TX = 2,              // Транзакция
    DAP_CHAIN_DATUM_DECREE = 3,          // Декрет
    DAP_CHAIN_DATUM_ANCHOR = 4,          // Якорь
    DAP_CHAIN_DATUM_VOTING = 5,          // Голосование
    DAP_CHAIN_DATUM_HASHTREE_ROOTS = 6,  // Корни хеш-деревьев
    DAP_CHAIN_DATUM_POLL = 7             // Опрос
} dap_chain_datum_type_t;
```

### Токены (Token)

```c
typedef struct dap_chain_datum_token {
    dap_chain_datum_t datum;             // Базовая структура
    uint256_t emission_total;            // Общий объем эмиссии
    uint256_t emission_current;          // Текущий объем в обращении
    char ticker[DAP_CHAIN_TICKER_SIZE]; // Тикер токена
    uint16_t signs_count;                // Количество подписей
    uint16_t flags;                      // Флаги токена
    // ... дополнительные поля
} dap_chain_datum_token_t;
```

### Транзакции (Transaction)

```c
typedef struct dap_chain_datum_tx {
    dap_chain_datum_t datum;             // Базовая структура
    uint32_t tx_items_count;             // Количество элементов транзакции
    uint64_t tx_items_size;              // Общий размер элементов
    dap_chain_tx_item_t tx_items[];      // Массив элементов транзакции
} dap_chain_datum_tx_t;

typedef struct dap_chain_tx_item {
    dap_chain_tx_item_type_t type;       // Тип элемента
    uint64_t value;                      // Значение
    // ... дополнительные поля
} dap_chain_tx_item_t;
```

## API Reference

### Управление данными

#### Создание datum

```c
// Создание нового datum
dap_chain_datum_t* dap_chain_datum_create(dap_chain_datum_type_t a_type,
                                        const void* a_data,
                                        size_t a_data_size);

// Удаление datum
void dap_chain_datum_delete(dap_chain_datum_t* a_datum);

// Сериализация datum
uint8_t* dap_chain_datum_serialize(dap_chain_datum_t* a_datum,
                                 size_t* a_serialized_size);

// Десериализация datum
dap_chain_datum_t* dap_chain_datum_deserialize(const uint8_t* a_data,
                                             size_t a_data_size);
```

#### Работа с хешами

```c
// Вычисление хеша данных
bool dap_chain_hash_data(dap_chain_hash_t* a_hash,
                        const void* a_data,
                        size_t a_data_size);

// Вычисление хеша datum
bool dap_chain_datum_hash(dap_chain_hash_t* a_hash,
                         dap_chain_datum_t* a_datum);

// Сравнение хешей
int dap_chain_hash_compare(dap_chain_hash_t* a_hash1,
                          dap_chain_hash_t* a_hash2);
```

#### Работа с адресами

```c
// Создание адреса из публичного ключа
bool dap_chain_addr_from_pub_key(dap_chain_addr_t* a_addr,
                                const void* a_pub_key,
                                size_t a_pub_key_size);

// Преобразование адреса в строку
char* dap_chain_addr_to_str(dap_chain_addr_t* a_addr);

// Преобразование строки в адрес
bool dap_chain_addr_from_str(dap_chain_addr_t* a_addr,
                            const char* a_str);
```

## Специализированные данные

### Декреты (Decrees)

```c
typedef struct dap_chain_datum_decree {
    dap_chain_datum_t datum;             // Базовая структура
    uint64_t decree_id;                  // ID декрета
    uint32_t decree_type;                // Тип декрета
    uint32_t data_size;                  // Размер данных декрета
    uint8_t data[];                      // Данные декрета
} dap_chain_datum_decree_t;
```

### Якоря (Anchors)

```c
typedef struct dap_chain_datum_anchor {
    dap_chain_datum_t datum;             // Базовая структура
    dap_chain_hash_t block_hash;         // Хеш блока
    uint64_t block_number;               // Номер блока
    uint32_t anchors_count;              // Количество якорей
    dap_chain_hash_t anchors[];          // Массив якорей
} dap_chain_datum_anchor_t;
```

### Голосования (Voting)

```c
typedef struct dap_chain_datum_tx_voting {
    dap_chain_datum_t datum;             // Базовая структура
    uint64_t voting_id;                  // ID голосования
    uint32_t question_count;             // Количество вопросов
    uint32_t answers_count;              // Количество ответов
    // ... дополнительные поля для голосования
} dap_chain_datum_tx_voting_t;
```

## Примеры использования

### Пример 1: Создание токена

```c
#include "dap_chain_datum_token.h"

dap_chain_datum_token_t* create_token(const char* a_ticker,
                                     uint256_t a_emission_total) {
    // Создание структуры токена
    dap_chain_datum_token_t* token = DAP_NEW(dap_chain_datum_token_t);

    // Инициализация базовых полей
    token->datum.version = 1;
    token->datum.type = DAP_CHAIN_DATUM_TOKEN;
    token->datum.timestamp = dap_time_now();

    // Настройка параметров токена
    token->emission_total = a_emission_total;
    token->emission_current = a_emission_total;
    strncpy(token->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE - 1);

    // Настройка флагов
    token->flags = DAP_CHAIN_TOKEN_FLAG_NONE;

    return token;
}
```

### Пример 2: Работа с транзакциями

```c
#include "dap_chain_datum_tx.h"

dap_chain_datum_tx_t* create_transaction(dap_chain_addr_t* a_from,
                                        dap_chain_addr_t* a_to,
                                        uint256_t a_amount) {
    // Создание транзакции с одним элементом
    size_t tx_size = sizeof(dap_chain_datum_tx_t) + sizeof(dap_chain_tx_item_t);
    dap_chain_datum_tx_t* tx = DAP_NEW_SIZE(dap_chain_datum_tx_t, tx_size);

    // Инициализация базовых полей
    tx->datum.version = 1;
    tx->datum.type = DAP_CHAIN_DATUM_TX;
    tx->datum.timestamp = dap_time_now();

    // Настройка элементов транзакции
    tx->tx_items_count = 1;
    tx->tx_items_size = sizeof(dap_chain_tx_item_t);

    // Настройка первого элемента (перевод средств)
    dap_chain_tx_item_t* item = &tx->tx_items[0];
    item->type = TX_ITEM_TYPE_OUT;
    item->value = a_amount;
    // Копирование адресов отправителя и получателя
    memcpy(&item->addr_from, a_from, sizeof(dap_chain_addr_t));
    memcpy(&item->addr_to, a_to, sizeof(dap_chain_addr_t));

    return tx;
}
```

### Пример 3: Работа с хешами

```c
#include "dap_chain_common.h"

void hash_example() {
    // Данные для хеширования
    const char* data = "Hello, CellFrame!";
    size_t data_size = strlen(data);

    // Вычисление хеша
    dap_chain_hash_t hash;
    if (dap_chain_hash_data(&hash, data, data_size)) {
        // Преобразование хеша в строку для вывода
        char hash_str[64];
        dap_chain_hash_to_str(&hash, hash_str, sizeof(hash_str));

        printf("Hash: %s\n", hash_str);
    } else {
        printf("Failed to compute hash\n");
    }
}
```

## Тестирование

### Запуск тестов

```bash
# Сборка с тестами
cmake -DBUILD_CELLFRAME_SDK_TESTS=ON ..
make

# Запуск тестов common модуля
./test/common/test_datum
./test/common/test_hash
./test/common/test_addr
```

### Пример теста

```c
#include "dap_test.h"
#include "dap_chain_datum.h"

void test_datum_creation() {
    // Создание тестовых данных
    const char* test_data = "test datum";
    size_t data_size = strlen(test_data);

    // Создание datum
    dap_chain_datum_t* datum = dap_chain_datum_create(
        DAP_CHAIN_DATUM_TOKEN,
        test_data,
        data_size
    );

    // Проверка создания
    DAP_ASSERT(datum != NULL);
    DAP_ASSERT(datum->type == DAP_CHAIN_DATUM_TOKEN);
    DAP_ASSERT(datum->data_size == data_size);

    // Проверка сериализации
    size_t serialized_size;
    uint8_t* serialized = dap_chain_datum_serialize(datum, &serialized_size);
    DAP_ASSERT(serialized != NULL);
    DAP_ASSERT(serialized_size > 0);

    // Проверка десериализации
    dap_chain_datum_t* deserialized = dap_chain_datum_deserialize(
        serialized, serialized_size
    );
    DAP_ASSERT(deserialized != NULL);
    DAP_ASSERT(deserialized->type == datum->type);

    // Очистка
    dap_chain_datum_delete(datum);
    DAP_FREE(serialized);
    dap_chain_datum_delete(deserialized);
}
```

## Производительность

### Бенчмарки операций

| Операция | Производительность | Примечание |
|----------|-------------------|------------|
| Создание datum | ~1M ops/sec | Intel Core i7 |
| Сериализация datum | ~500K ops/sec | Зависит от размера |
| Вычисление хеша | ~100MB/sec | SHA-256 |
| Сравнение хешей | ~10M ops/sec | 256-bit |

### Оптимизации

#### Пул объектов
```c
// Пул для переиспользования datum объектов
typedef struct datum_pool {
    dap_list_t* free_datums;     // Свободные объекты
    size_t pool_size;            // Размер пула
    pthread_mutex_t mutex;       // Синхронизация
} datum_pool_t;
```

#### Zero-copy операции
```c
// Создание datum без копирования данных
dap_chain_datum_t* dap_chain_datum_create_zero_copy(
    dap_chain_datum_type_t a_type,
    void* a_data,
    size_t a_data_size
);
```

## Безопасность

### Валидация данных

```c
// Проверка корректности datum
bool dap_chain_datum_validate(dap_chain_datum_t* a_datum) {
    // Проверка версии
    if (a_datum->version == 0) return false;

    // Проверка типа
    if (a_datum->type >= DAP_CHAIN_DATUM_MAX) return false;

    // Проверка размера
    if (a_datum->data_size == 0) return false;

    // Проверка временной метки
    if (a_datum->timestamp == 0) return false;

    return true;
}
```

### Защита от переполнения

```c
// Безопасное копирование данных
bool dap_chain_datum_copy_data_safe(dap_chain_datum_t* a_dest,
                                   const void* a_src,
                                   size_t a_size) {
    // Проверка границ
    if (a_size > DAP_CHAIN_DATUM_MAX_SIZE) {
        return false;
    }

    // Проверка указателей
    if (!a_dest || !a_src) {
        return false;
    }

    memcpy(a_dest->data, a_src, a_size);
    a_dest->data_size = a_size;

    return true;
}
```

### Вспомогательные функции

#### Конвертация числовых типов

```c
// Конвертация из uint64_t в uint128_t
DAP_STATIC_INLINE uint128_t dap_chain_uint128_from(uint64_t a_from) {
    uint128_t l_ret;
    l_ret.lo = a_from;
    l_ret.hi = 0;
    return l_ret;
}

// Конвертация из uint256_t в uint128_t
uint128_t dap_chain_uint128_from_uint256(uint256_t a_from);

// Конвертация из uint64_t в uint256_t
DAP_STATIC_INLINE uint256_t dap_chain_uint256_from(uint64_t a_from) {
    return GET_256_FROM_64(a_from);
}

// Конвертация из uint128_t в uint256_t
DAP_STATIC_INLINE uint256_t dap_chain_uint256_from_uint128(uint128_t a_from) {
    return GET_256_FROM_128(a_from);
}
```

#### Работа с балансами

```c
// Конвертация баланса в coins (uint64_t)
DAP_STATIC_INLINE uint64_t dap_chain_balance_to_coins_uint64(uint256_t val) {
    DIV_256_COIN(val, dap_chain_coins_to_balance("1000000000000000000.0"), &val);
    return val._lo.a;
}

// Макросы для работы с балансами
#define dap_chain_balance_print dap_uint256_uninteger_to_char
#define dap_chain_balance_scan(a_balance) \
    (strchr(a_balance, '.') && !strchr(a_balance, '+')) ? \
    dap_uint256_scan_decimal(a_balance) : dap_uint256_scan_uninteger(a_balance)
#define dap_chain_balance_to_coins dap_uint256_decimal_to_char
#define dap_chain_coins_to_balance dap_uint256_scan_decimal
#define dap_chain_uint256_to dap_uint256_to_uint64
```

#### Работа с хешами

```c
// Конвертация медленного хеша в строку (с автоматическим выделением памяти)
static inline char *dap_chain_hash_slow_to_str_new(dap_chain_hash_slow_t *a_hash) {
    const size_t c_hash_str_size = sizeof(*a_hash) * 2 + 1 + 2;
    char *ret = DAP_NEW_Z_SIZE(char, c_hash_str_size);
    dap_chain_hash_slow_to_str(a_hash, ret, c_hash_str_size);
    return ret;
}

// Проверка качества медленного хеша
static inline dap_chain_hash_slow_kind_t dap_chain_hash_slow_kind_check(
    dap_chain_hash_slow_t *a_hash, const uint8_t a_valuable_head) {
    uint8_t i;
    uint8_t l_hash_first = a_hash->raw[0];
    uint8_t *l_hash_data = a_hash->raw;
    for (i = 1; i < a_valuable_head; ++i) {
        if (l_hash_data[i] != l_hash_first)
            return HASH_USELESS;
    }
    if (l_hash_first == 0)
        return HASH_GOLD;
    else
        return HASH_SILVER;
}
```

## Заключение

Common Module предоставляет фундаментальную функциональность для работы с данными в CellFrame SDK. Он включает базовые структуры, утилиты для сериализации/десериализации и вспомогательные функции, необходимые для всех остальных модулей системы.

### Ключевые особенности:
- **Универсальность**: Поддержка различных типов данных цепочки
- **Производительность**: Оптимизированные структуры и алгоритмы
- **Безопасность**: Валидация данных и защита от переполнения
- **Расширяемость**: Легкое добавление новых типов данных

Для получения дополнительной информации смотрите:
- `dap_chain_common.h` - основные структуры и функции
- `dap_chain_datum.h` - работа с данными цепочки
- `dap_chain_datum_token.h` - структуры токенов
- `dap_chain_datum_tx.h` - структуры транзакций
- Примеры в директории `examples/common/`
- Тесты в директории `test/common/`
