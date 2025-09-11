# CellFrame SDK API Reference

## Обзор

API Reference содержит полную документацию по всем функциям, структурам данных и константам CellFrame SDK. Этот справочник предназначен для разработчиков блокчейн-приложений и включает высокоуровневые API для работы с цепочками, кошельками, транзакциями и консенсусом.

## Структура API

### Chain Module API
Функции для работы с блокчейн-цепочками.

#### Управление цепочками
```c
// Создание цепочки
dap_chain_t* dap_chain_new(const char* name);

// Удаление цепочки
void dap_chain_free(dap_chain_t* chain);

// Получение цепочки по имени
dap_chain_t* dap_chain_find_by_name(const char* name);
```

#### Структура цепочки
```c
typedef struct dap_chain {
    char* name;                         // Имя цепочки
    dap_chain_id_t id;                  // Уникальный ID
    dap_chain_net_t* net;               // Сетевая информация
    dap_chain_cs_t* cs;                 // Алгоритм консенсуса
    void* ledger;                       // Леджер
    dap_chain_cell_t* cells;            // Ячейки цепочки

    // Callbacks
    dap_chain_callback_t callback_created;
    dap_chain_callback_t callback_pinned;

    // Статистика
    uint64_t stats_blocks_processed;
    uint64_t stats_transactions_processed;
} dap_chain_t;
```

### Wallet Module API
Функции для управления криптовалютными кошельками.

#### Создание и управление кошельками
```c
// Создание кошелька
dap_chain_wallet_t* dap_chain_wallet_create(const char* name,
                                          dap_chain_net_t* net);

// Создание кошелька с ключом
dap_chain_wallet_t* dap_chain_wallet_create_with_key(const char* name,
                                                   dap_chain_net_t* net,
                                                   dap_enc_key_type_t key_type);

// Удаление кошелька
void dap_chain_wallet_delete(dap_chain_wallet_t* wallet);
```

#### Операции с кошельком
```c
// Получение баланса
uint256_t dap_chain_wallet_get_balance(dap_chain_wallet_t* wallet,
                                     const char* ticker);

// Создание транзакции перевода
dap_chain_datum_tx_t* dap_chain_wallet_create_transfer(dap_chain_wallet_t* wallet,
                                                     const char* to_addr,
                                                     const char* ticker,
                                                     uint256_t amount);

// Подписание транзакции
bool dap_chain_wallet_sign_tx(dap_chain_wallet_t* wallet,
                            dap_chain_datum_tx_t* tx);
```

#### Структура кошелька
```c
typedef struct dap_chain_wallet {
    char* name;                         // Имя кошелька
    dap_chain_addr_t addr;              // Адрес кошелька
    dap_chain_wallet_key_t* key;        // Ключ кошелька
    dap_chain_wallet_cache_t* cache;    // Кэш кошелька

    // Балансы
    dap_list_t* balances;               // Список балансов
    uint256_t total_balance;            // Общий баланс

    // Настройки
    bool is_protected;                  // Защита кошелька
    char* password_hash;                // Хеш пароля
} dap_chain_wallet_t;
```

### Transaction Module API
Функции для работы с транзакциями.

#### Создание транзакций
```c
// Создание транзакции
dap_chain_datum_tx_t* dap_chain_datum_tx_create(void);

// Добавление элемента в транзакцию
bool dap_chain_datum_tx_add_item(dap_chain_datum_tx_t* tx,
                               dap_chain_tx_item_t* item);

// Сериализация транзакции
uint8_t* dap_chain_datum_tx_serialize(dap_chain_datum_tx_t* tx,
                                    size_t* serialized_size);
```

#### Структура транзакции
```c
typedef struct dap_chain_datum_tx {
    dap_chain_datum_t datum;            // Базовая структура
    uint32_t tx_items_count;            // Количество элементов
    uint64_t tx_items_size;             // Общий размер элементов
    dap_chain_tx_item_t tx_items[];     // Массив элементов
} dap_chain_datum_tx_t;

typedef struct dap_chain_tx_item {
    dap_chain_tx_item_type_t type;      // Тип элемента
    uint64_t value;                     // Значение
    // ... дополнительные поля
} dap_chain_tx_item_t;
```

### Network Module API
Сетевые функции и коммуникации.

#### Управление сетью
```c
// Создание сети
dap_chain_net_t* dap_chain_net_create(const char* name);

// Запуск сети
int dap_chain_net_start(dap_chain_net_t* net);

// Остановка сети
void dap_chain_net_stop(dap_chain_net_t* net);
```

#### Структура сети
```c
typedef struct dap_chain_net {
    char* name;                         // Имя сети
    dap_chain_net_id_t id;              // ID сети
    dap_chain_node_list_t* nodes;       // Список узлов

    // Настройки
    uint16_t port;                      // Порт
    bool is_running;                    // Статус работы

    // Статистика
    uint64_t stats_connections;
    uint64_t stats_transactions;
} dap_chain_net_t;
```

## Consensus Algorithms API

### DAG PoA (Proof of Authority)
```c
// Создание DAG PoA консенсуса
dap_chain_cs_t* dap_chain_cs_dag_poa_create(dap_chain_t* chain);

// Добавление валидатора
bool dap_chain_cs_dag_poa_add_validator(dap_chain_cs_t* cs,
                                      dap_chain_addr_t* validator_addr);

// Создание события
int dap_chain_cs_dag_poa_create_event(dap_chain_cs_t* cs,
                                    const void* data,
                                    size_t data_size);
```

### DAG PoS (Proof of Stake)
```c
// Создание DAG PoS консенсуса
dap_chain_cs_t* dap_chain_cs_dag_pos_create(dap_chain_t* chain,
                                          uint256_t min_stake);

// Валидация ставки
bool dap_chain_cs_dag_pos_validate_stake(dap_chain_cs_t* cs,
                                       dap_chain_addr_t* addr,
                                       uint256_t stake_amount);
```

### Block PoW (Proof of Work)
```c
// Создание Block PoW консенсуса
dap_chain_cs_t* dap_chain_cs_block_pow_create(dap_chain_t* chain,
                                           uint32_t difficulty);

// Майнинг блока
int dap_chain_cs_block_pow_mine(dap_chain_cs_t* cs,
                              dap_chain_block_t* block);
```

## Типы данных

### Основные типы
```c
// Идентификаторы
typedef uint64_t dap_chain_id_t;
typedef uint64_t dap_chain_cell_id_t;
typedef uint64_t dap_chain_net_id_t;

// Адреса и хеши
typedef uint256_t dap_chain_hash_t;
typedef uint64_t dap_chain_addr_t;
typedef uint64_t dap_chain_time_t;
```

### Перечисления
```c
// Типы данных цепочки
typedef enum dap_chain_datum_type {
    DAP_CHAIN_DATUM_TOKEN = 1,          // Токен
    DAP_CHAIN_DATUM_TX = 2,             // Транзакция
    DAP_CHAIN_DATUM_DECREE = 3,         // Декрет
    DAP_CHAIN_DATUM_ANCHOR = 4,         // Якорь
    DAP_CHAIN_DATUM_VOTING = 5,         // Голосование
} dap_chain_datum_type_t;

// Типы элементов транзакции
typedef enum dap_chain_tx_item_type {
    TX_ITEM_TYPE_IN = 1,                // Входящий перевод
    TX_ITEM_TYPE_OUT = 2,               // Исходящий перевод
    TX_ITEM_TYPE_PKEY = 3,              // Публичный ключ
} dap_chain_tx_item_type_t;
```

## Константы

### Лимиты и размеры
```c
#define DAP_CHAIN_TICKER_SIZE 10        // Размер тикера токена
#define DAP_CHAIN_ADDR_SIZE 20          // Размер адреса
#define DAP_CHAIN_HASH_SIZE 32          // Размер хеша
#define DAP_CHAIN_MAX_TX_SIZE 65536     // Максимальный размер транзакции
```

### Коды ошибок
```c
#define DAP_CHAIN_SUCCESS 0             // Успешное выполнение
#define DAP_CHAIN_ERROR_INVALID_PARAM -1 // Неверный параметр
#define DAP_CHAIN_ERROR_NOT_FOUND -2    // Объект не найден
#define DAP_CHAIN_ERROR_NO_MEMORY -3    // Недостаточно памяти
#define DAP_CHAIN_ERROR_NETWORK -4      // Сетевая ошибка
```

## Макросы и утилиты

### Управление памятью
```c
// Безопасное выделение памяти
#define DAP_CHAIN_NEW(type) ((type*)dap_malloc(sizeof(type)))
#define DAP_CHAIN_DELETE(ptr) do { dap_free(ptr); ptr = NULL; } while(0)
```

### Конвертация типов
```c
// Конвертация uint256 в строку
char* uint256_to_str(uint256_t value, char* str, size_t str_size);

// Конвертация строки в uint256
uint256_t uint256_from_str(const char* str);
```

### Работа с адресами
```c
// Преобразование адреса в строку
char* dap_chain_addr_to_str(dap_chain_addr_t* addr, char* str, size_t str_size);

// Преобразование строки в адрес
bool dap_chain_addr_from_str(dap_chain_addr_t* addr, const char* str);
```

## Функции обратного вызова

### Типы callback функций
```c
// Callback для новых блоков
typedef void (*dap_chain_block_callback_t)(dap_chain_t* chain,
                                         dap_chain_block_t* block,
                                         void* arg);

// Callback для новых транзакций
typedef void (*dap_chain_tx_callback_t)(dap_chain_t* chain,
                                      dap_chain_datum_tx_t* tx,
                                      void* arg);

// Callback для сетевых событий
typedef void (*dap_chain_net_callback_t)(dap_chain_net_t* net,
                                       int event_type,
                                       void* arg);
```

## Производительность

### Бенчмарки операций
| Операция | Производительность | Примечание |
|----------|-------------------|------------|
| Создание транзакции | ~10,000 tx/sec | Intel Core i7 |
| Валидация транзакции | ~5,000 tx/sec | С проверкой подписи |
| Создание блока | ~1,000 blocks/sec | DAG PoA |
| Синхронизация | ~100 MB/sec | P2P сеть |

### Оптимизации
- Используйте кэширование для частых операций
- Предварительно выделяйте память для транзакций
- Используйте асинхронные операции для сети

## Потокобезопасность

### Thread-safe функции
- Создание и удаление объектов
- Чтение данных (состояние цепочки)
- Сетевые операции (с ограничениями)

### Thread-unsafe функции
- Модификация состояния цепочки
- Криптографические операции с ключами
- Некоторые операции с кошельком

## Совместимость

### Поддерживаемые алгоритмы консенсуса
- **DAG PoA**: Proof of Authority на основе DAG
- **DAG PoS**: Proof of Stake на основе DAG
- **Block PoW**: Классический Proof of Work
- **ESBOCS**: Enhanced Scalable Blockchain Consensus

### Поддерживаемые платформы
- **Linux**: Полная поддержка
- **macOS**: Полная поддержка
- **Windows**: Ограниченная поддержка

## Примеры использования

### Полный пример работы с кошельком
```c
#include "dap_chain_wallet.h"
#include "dap_chain_net.h"

int wallet_operations_example() {
    // Инициализация
    if (dap_chain_init() != 0) return -1;

    // Создание сети
    dap_chain_net_t* net = dap_chain_net_create("testnet");
    if (!net) {
        dap_chain_deinit();
        return -1;
    }

    // Создание кошелька
    dap_chain_wallet_t* wallet = dap_chain_wallet_create_with_key(
        "my_wallet", net, DAP_ENC_KEY_TYPE_SIG_DILITHIUM
    );
    if (!wallet) {
        dap_chain_net_delete(net);
        dap_chain_deinit();
        return -1;
    }

    // Получение адреса
    char addr_str[128];
    dap_chain_addr_to_str(&wallet->addr, addr_str, sizeof(addr_str));
    printf("Wallet address: %s\n", addr_str);

    // Создание транзакции
    dap_chain_datum_tx_t* tx = dap_chain_wallet_create_transfer(
        wallet, "recipient_address", "CELL", uint256_from_str("1000000")
    );

    if (tx) {
        // Подписание транзакции
        if (dap_chain_wallet_sign_tx(wallet, tx)) {
            printf("Transaction signed successfully\n");

            // Отправка в сеть
            if (dap_chain_net_tx_add(net, tx) == 0) {
                printf("Transaction sent to network\n");
            }
        }

        dap_chain_datum_tx_delete(tx);
    }

    // Очистка
    dap_chain_wallet_delete(wallet);
    dap_chain_net_delete(net);
    dap_chain_deinit();

    return 0;
}
```

## Навигация

- **[Chain Module](../modules/chain.md)** - Работа с блокчейн-цепочками
- **[Wallet Module](../modules/wallet.md)** - Управление кошельками
- **[Common Module](../modules/common.md)** - Общие структуры данных
- **[Примеры](../examples/)** - Практические примеры
