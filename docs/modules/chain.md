# Chain Module - Блокчейн цепочка

## Обзор

Chain Module является основным модулем CellFrame SDK и предоставляет базовую функциональность блокчейн цепочки, включая работу с блоками, транзакциями, DAG структурой и управлением состоянием цепочки.

## Структура модуля

```
modules/chain/
├── include/              # Заголовочные файлы
│   ├── dap_chain.h       # Основные структуры цепочки
│   ├── dap_chain_datum.h # Данные цепочки
│   ├── dap_chain_tx.h    # Транзакции
│   └── ...
├── src/                  # Исходный код
│   ├── dap_chain.c       # Основная логика цепочки
│   ├── dap_chain_tx.c    # Обработка транзакций
│   ├── dap_chain_datum.c # Работа с данными
│   └── ...
├── tests/               # Тесты
└── docs/                # Документация
```

## Основные структуры данных

### Структура цепочки

```c
typedef struct dap_chain {
    char *name;                          // Имя цепочки
    dap_chain_id_t id;                   // Уникальный идентификатор
    dap_chain_net_t *net;                // Сетевая информация
    dap_chain_cs_t *cs;                  // Алгоритм консенсуса
    void *ledger;                        // Леджер (бухгалтерская книга)
    dap_chain_cell_t *cells;             // Ячейки цепочки

    // Callbacks
    dap_chain_callback_t callback_created;  // Создание цепочки
    dap_chain_callback_t callback_pinned;   // Закрепление цепочки

    // Статистика
    uint64_t stats_blocks_processed;       // Обработано блоков
    uint64_t stats_transactions_processed; // Обработано транзакций
} dap_chain_t;
```

### Атомарный элемент

```c
typedef const void * dap_chain_atom_ptr_t;

typedef struct dap_chain_atom {
    dap_chain_atom_type_t type;          // Тип атома
    void *data;                          // Данные атома
    size_t data_size;                    // Размер данных
    dap_chain_hash_t hash;               // Хеш атома
    uint64_t timestamp;                  // Временная метка
} dap_chain_atom_t;

typedef enum dap_chain_atom_type {
    ATOM_TYPE_TX = 1,                   // Транзакция
    ATOM_TYPE_BLOCK = 2,                // Блок
    ATOM_TYPE_DATUM = 3,                // Данные
    ATOM_TYPE_EVENT = 4                 // Событие
} dap_chain_atom_type_t;
```

### Ячейка цепочки

```c
typedef struct dap_chain_cell {
    char *name;                         // Имя ячейки
    dap_chain_cell_id_t id;             // Идентификатор ячейки
    dap_chain_t *chain;                 // Родительская цепочка
    dap_hash_t hash;                    // Хеш ячейки

    // Хранение данных
    void *storage;                      // Хранилище данных
    size_t storage_size;                // Размер хранилища

    // Статистика
    uint64_t atoms_count;               // Количество атомов
    uint64_t last_atom_time;            // Время последнего атома
} dap_chain_cell_t;
```

## API Reference

### Управление цепочкой

#### Создание цепочки

```c
// Создание новой цепочки
dap_chain_t* dap_chain_new(const char *a_name);

// Создание цепочки с конфигурацией
dap_chain_t* dap_chain_new_with_config(const char *a_name,
                                     dap_config_t *a_config);

// Удаление цепочки
void dap_chain_free(dap_chain_t *a_chain);
```

#### Инициализация и деинициализация

```c
// Инициализация модуля цепочки
int dap_chain_init(void);

// Деинициализация модуля цепочки
void dap_chain_deinit(void);

// Проверка инициализации
bool dap_chain_is_initialized(void);
```

### Работа с атомами

#### Добавление атома

```c
// Добавление атома в цепочку
int dap_chain_atom_add(dap_chain_t *a_chain,
                      dap_chain_cell_t *a_cell,
                      dap_chain_atom_ptr_t a_atom,
                      size_t a_atom_size);

// Получение атома по хешу
dap_chain_atom_ptr_t dap_chain_atom_get(dap_chain_t *a_chain,
                                       dap_chain_hash_t *a_hash);

// Удаление атома
int dap_chain_atom_remove(dap_chain_t *a_chain,
                         dap_chain_hash_t *a_hash);
```

#### Итерация по атомам

```c
typedef struct dap_chain_atom_iter {
    dap_chain_t *chain;                 // Цепочка
    dap_chain_cell_t *cell;             // Ячейка
    void *iter_context;                 // Контекст итератора
} dap_chain_atom_iter_t;

// Создание итератора
dap_chain_atom_iter_t* dap_chain_atom_iter_create(dap_chain_t *a_chain,
                                                 dap_chain_cell_t *a_cell);

// Получение следующего атома
dap_chain_atom_ptr_t dap_chain_atom_iter_next(dap_chain_atom_iter_t *a_iter);

// Удаление итератора
void dap_chain_atom_iter_free(dap_chain_atom_iter_t *a_iter);
```

### Работа с транзакциями

#### Структура транзакции

```c
typedef struct dap_chain_tx {
    uint32_t version;                   // Версия транзакции
    uint64_t timestamp;                 // Временная метка
    dap_chain_addr_t sender;            // Отправитель
    dap_chain_addr_t receiver;          // Получатель
    uint256_t value;                    // Сумма
    uint256_t fee;                      // Комиссия

    // Данные транзакции
    void *data;                         // Произвольные данные
    size_t data_size;                   // Размер данных

    // Подписи
    dap_sign_t *sign;                   // Подпись
    size_t sign_size;                   // Размер подписи

    // Хеш
    dap_chain_hash_t hash;              // Хеш транзакции
} dap_chain_tx_t;
```

#### Создание транзакции

```c
// Создание новой транзакции
dap_chain_tx_t* dap_chain_tx_create(dap_chain_addr_t *a_sender,
                                   dap_chain_addr_t *a_receiver,
                                   uint256_t a_value);

// Добавление данных к транзакции
int dap_chain_tx_add_data(dap_chain_tx_t *a_tx,
                         void *a_data,
                         size_t a_data_size);

// Подписание транзакции
int dap_chain_tx_sign(dap_chain_tx_t *a_tx,
                     dap_enc_key_t *a_key);

// Валидация транзакции
bool dap_chain_tx_validate(dap_chain_tx_t *a_tx);
```

### Работа с данными (Datum)

#### Структура данных

```c
typedef struct dap_chain_datum {
    dap_chain_datum_type_t type;        // Тип данных
    uint64_t timestamp;                 // Временная метка
    void *data;                         // Данные
    size_t data_size;                   // Размер данных
    dap_sign_t *sign;                   // Подпись
} dap_chain_datum_t;

typedef enum dap_chain_datum_type {
    DATUM_TYPE_TOKEN = 1,              // Токен
    DATUM_TYPE_TOKEN_EMISSION = 2,     // Эмиссия токена
    DATUM_TYPE_SMART_CONTRACT = 3,     // Смарт-контракт
    DATUM_TYPE_ANCHOR = 4,             // Якорь
    DATUM_TYPE_DECREE = 5              // Декрет
} dap_chain_datum_type_t;
```

#### Управление данными

```c
// Создание данных
dap_chain_datum_t* dap_chain_datum_create(dap_chain_datum_type_t a_type,
                                        void *a_data,
                                        size_t a_data_size);

// Подписание данных
int dap_chain_datum_sign(dap_chain_datum_t *a_datum,
                        dap_enc_key_t *a_key);

// Валидация данных
bool dap_chain_datum_validate(dap_chain_datum_t *a_datum);

// Сохранение данных
int dap_chain_datum_save(dap_chain_t *a_chain,
                        dap_chain_datum_t *a_datum);
```

## Примеры использования

### Базовое использование цепочки

```c
#include "dap_chain.h"

int main() {
    // Инициализация
    if (dap_chain_init() != 0) {
        fprintf(stderr, "Failed to initialize chain module\n");
        return 1;
    }

    // Создание цепочки
    dap_chain_t *chain = dap_chain_new("my_chain");
    if (!chain) {
        fprintf(stderr, "Failed to create chain\n");
        return 1;
    }

    // Создание ячейки
    dap_chain_cell_t *cell = dap_chain_cell_new(chain, "cell1");
    if (!cell) {
        fprintf(stderr, "Failed to create cell\n");
        dap_chain_free(chain);
        return 1;
    }

    // Ваш код работы с цепочкой здесь

    // Очистка
    dap_chain_cell_free(cell);
    dap_chain_free(chain);
    dap_chain_deinit();

    return 0;
}
```

### Работа с транзакциями

```c
#include "dap_chain.h"
#include "dap_chain_tx.h"
#include "dap_chain_wallet.h"

int create_and_send_transaction() {
    // Получение кошельков отправителя и получателя
    dap_chain_wallet_t *sender_wallet = dap_chain_wallet_get("sender_wallet");
    dap_chain_wallet_t *receiver_wallet = dap_chain_wallet_get("receiver_wallet");

    if (!sender_wallet || !receiver_wallet) {
        return -1;
    }

    // Создание транзакции
    uint256_t amount = uint256_from_uint64(1000000); // 1 токен
    dap_chain_tx_t *tx = dap_chain_tx_create(&sender_wallet->addr,
                                           &receiver_wallet->addr,
                                           amount);

    if (!tx) {
        return -1;
    }

    // Подписание транзакции
    if (dap_chain_tx_sign(tx, sender_wallet->key) != 0) {
        dap_chain_tx_free(tx);
        return -1;
    }

    // Добавление в цепочку
    if (dap_chain_tx_add(chain, cell, tx) != 0) {
        dap_chain_tx_free(tx);
        return -1;
    }

    // Освобождение памяти (транзакция теперь в цепочке)
    dap_chain_tx_free(tx);

    return 0;
}
```

### Итерация по атомам

```c
#include "dap_chain.h"

void process_all_atoms(dap_chain_t *chain, dap_chain_cell_t *cell) {
    // Создание итератора
    dap_chain_atom_iter_t *iter = dap_chain_atom_iter_create(chain, cell);
    if (!iter) {
        return;
    }

    // Итерация по всем атомам
    dap_chain_atom_ptr_t atom;
    while ((atom = dap_chain_atom_iter_next(iter)) != NULL) {
        // Обработка атома в зависимости от типа
        dap_chain_atom_header_t *header = (dap_chain_atom_header_t *)atom;

        switch (header->type) {
            case ATOM_TYPE_TX:
                printf("Found transaction atom\n");
                // Обработка транзакции
                break;

            case ATOM_TYPE_BLOCK:
                printf("Found block atom\n");
                // Обработка блока
                break;

            case ATOM_TYPE_DATUM:
                printf("Found datum atom\n");
                // Обработка данных
                break;

            default:
                printf("Unknown atom type: %d\n", header->type);
                break;
        }
    }

    // Освобождение итератора
    dap_chain_atom_iter_free(iter);
}
```

## Производительность

### Оптимизации

#### Кэширование атомов
```c
// LRU кэш для часто используемых атомов
typedef struct atom_cache {
    dap_chain_hash_t hash;
    dap_chain_atom_ptr_t atom;
    time_t last_access;
    struct atom_cache *next;
    struct atom_cache *prev;
} atom_cache_t;
```

#### Пакетная обработка
```c
// Обработка нескольких атомов одновременно
int dap_chain_atom_add_batch(dap_chain_t *a_chain,
                           dap_chain_cell_t *a_cell,
                           dap_chain_atom_ptr_t *a_atoms,
                           size_t *a_atom_sizes,
                           size_t a_count);
```

#### Асинхронные операции
```c
// Асинхронное добавление атома
typedef void (*dap_chain_atom_callback_t)(int result, void *arg);

int dap_chain_atom_add_async(dap_chain_t *a_chain,
                           dap_chain_cell_t *a_cell,
                           dap_chain_atom_ptr_t a_atom,
                           size_t a_atom_size,
                           dap_chain_atom_callback_t callback,
                           void *callback_arg);
```

### Бенчмарки

| Операция | Производительность | Примечание |
|----------|-------------------|------------|
| Добавление атома | ~10,000 ops/sec | Синхронная операция |
| Поиск атома по хешу | ~100,000 ops/sec | С кэшированием |
| Валидация транзакции | ~50,000 ops/sec | Без криптографии |
| Создание блока | ~1,000 ops/sec | С полными проверками |

## Безопасность

### Валидация данных

```c
// Комплексная валидация атома
bool dap_chain_atom_validate(dap_chain_t *a_chain,
                           dap_chain_atom_ptr_t a_atom,
                           size_t a_atom_size) {
    // Проверка размера
    if (a_atom_size > DAP_CHAIN_ATOM_MAX_SIZE) {
        return false;
    }

    // Проверка хеша
    dap_chain_hash_t calculated_hash;
    dap_hash(a_atom, a_atom_size, &calculated_hash, DAP_HASH_SHA3_256);

    if (memcmp(&calculated_hash, &atom_header->hash, sizeof(dap_chain_hash_t)) != 0) {
        return false;
    }

    // Специфическая валидация по типу
    switch (atom_header->type) {
        case ATOM_TYPE_TX:
            return dap_chain_tx_validate((dap_chain_tx_t*)a_atom);
        case ATOM_TYPE_BLOCK:
            return dap_chain_block_validate((dap_chain_block_t*)a_atom);
        // ...
    }

    return true;
}
```

### Защита от атак

- **Double spending**: Проверка баланса отправителя
- **Replay attacks**: Проверка временных меток и nonce
- **Invalid transactions**: Криптографическая валидация подписей
- **Malformed data**: Проверка структуры и размера данных

## Тестирование

### Запуск тестов

```bash
# Сборка с тестами
cmake -DBUILD_CELLFRAME_SDK_TESTS=ON ..
make

# Запуск тестов chain модуля
./test/chain/test_chain_basic
./test/chain/test_chain_tx
./test/chain/test_chain_datum
./test/chain/test_chain_performance
```

### Пример теста

```c
#include "dap_test.h"
#include "dap_chain.h"

void test_chain_creation() {
    // Инициализация
    DAP_ASSERT(dap_chain_init() == 0);

    // Создание цепочки
    dap_chain_t *chain = dap_chain_new("test_chain");
    DAP_ASSERT(chain != NULL);
    DAP_ASSERT(strcmp(chain->name, "test_chain") == 0);

    // Создание ячейки
    dap_chain_cell_t *cell = dap_chain_cell_new(chain, "test_cell");
    DAP_ASSERT(cell != NULL);
    DAP_ASSERT(cell->chain == chain);

    // Очистка
    dap_chain_cell_free(cell);
    dap_chain_free(chain);
    dap_chain_deinit();
}
```

## Заключение

Chain Module предоставляет мощную и гибкую основу для построения блокчейн-систем. Модуль обеспечивает эффективную работу с атомами, транзакциями и данными, поддерживает различные алгоритмы консенсуса и обеспечивает высокий уровень безопасности и производительности.
