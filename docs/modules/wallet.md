# Wallet Module - Кошелек CellFrame SDK

## Обзор

Wallet Module предоставляет полную функциональность для управления криптовалютными кошельками в CellFrame SDK. Модуль поддерживает различные типы ключей, мультиподпись, управление балансами и безопасное хранение средств.

## Структура модуля

```
modules/wallet/
├── include/                    # Заголовочные файлы
│   ├── dap_chain_wallet.h      # Основной API кошелька
│   ├── dap_chain_wallet_cache.h # Кэширование кошельков
│   ├── dap_chain_wallet_ops.h  # Операции с кошельком
│   ├── dap_chain_wallet_shared.h # Общие структуры
│   └── dap_chain_coin.h        # Работа с монетами
├── src/                        # Исходный код
│   ├── dap_chain_wallet.c
│   ├── dap_chain_wallet_cache.c
│   ├── dap_chain_wallet_ops.c
│   └── dap_chain_coin.c
├── tests/                      # Тесты
└── docs/                       # Документация
```

## Основные структуры данных

### Структура кошелька

```c
typedef struct dap_chain_wallet {
    char *name;                         // Имя кошелька
    dap_chain_addr_t addr;              // Адрес кошелька
    dap_chain_wallet_key_t *key;        // Ключ кошелька
    dap_chain_wallet_cache_t *cache;    // Кэш кошелька

    // Балансы
    dap_list_t *balances;               // Список балансов по токенам
    uint256_t total_balance;            // Общий баланс

    // Настройки
    bool is_protected;                  // Защита кошелька
    char *password_hash;                // Хеш пароля

    // Метаданные
    uint64_t created_timestamp;         // Время создания
    uint64_t last_used_timestamp;       // Последнее использование
} dap_chain_wallet_t;
```

### Структура ключа кошелька

```c
typedef struct dap_chain_wallet_key {
    dap_enc_key_type_t type;            // Тип криптографического ключа
    union {
        dap_enc_key_t *enc_key;         // Стандартный ключ
        struct {
            size_t key_count;           // Количество ключей для мультиподписи
            dap_enc_key_t **keys;       // Массив ключей
            size_t threshold;           // Порог подписей
        } multisig;
    } key_data;

    // Метаданные
    char *name;                         // Имя ключа
    uint64_t created_timestamp;         // Время создания
} dap_chain_wallet_key_t;
```

### Структура баланса

```c
typedef struct dap_chain_wallet_balance {
    char ticker[DAP_CHAIN_TICKER_SIZE]; // Тикер токена
    uint256_t balance;                  // Баланс токена
    uint256_t locked_balance;           // Заблокированный баланс
    uint64_t last_update;               // Последнее обновление
} dap_chain_wallet_balance_t;
```

## API Reference

### Создание и управление кошельками

#### Создание кошелька

```c
// Создание нового кошелька
dap_chain_wallet_t* dap_chain_wallet_create(const char *a_name,
                                          dap_chain_net_t *a_net);

// Создание кошелька с ключом
dap_chain_wallet_t* dap_chain_wallet_create_with_key(const char *a_name,
                                                   dap_chain_net_t *a_net,
                                                   dap_enc_key_type_t a_key_type);

// Удаление кошелька
void dap_chain_wallet_delete(dap_chain_wallet_t *a_wallet);
```

#### Управление ключами

```c
// Генерация нового ключа
dap_chain_wallet_key_t* dap_chain_wallet_key_generate(dap_enc_key_type_t a_type,
                                                    const char *a_name);

// Загрузка ключа из файла
dap_chain_wallet_key_t* dap_chain_wallet_key_load_from_file(const char *a_file_path,
                                                          const char *a_password);

// Сохранение ключа в файл
bool dap_chain_wallet_key_save_to_file(dap_chain_wallet_key_t *a_key,
                                     const char *a_file_path,
                                     const char *a_password);
```

#### Мультиподпись

```c
// Создание мультиподписного кошелька
dap_chain_wallet_t* dap_chain_wallet_create_multisig(const char *a_name,
                                                   dap_chain_net_t *a_net,
                                                   size_t a_key_count,
                                                   size_t a_threshold);

// Добавление ключа в мультиподписной кошелек
bool dap_chain_wallet_multisig_add_key(dap_chain_wallet_t *a_wallet,
                                      dap_enc_key_t *a_key);

// Создание подписи для мультиподписи
bool dap_chain_wallet_multisig_sign(dap_chain_wallet_t *a_wallet,
                                   const void *a_data,
                                   size_t a_data_size,
                                   uint8_t *a_signature,
                                   size_t *a_signature_size);
```

## Операции с кошельком

### Управление балансами

```c
// Получение баланса токена
uint256_t dap_chain_wallet_get_balance(dap_chain_wallet_t *a_wallet,
                                     const char *a_ticker);

// Получение всех балансов
dap_list_t* dap_chain_wallet_get_all_balances(dap_chain_wallet_t *a_wallet);

// Обновление баланса
bool dap_chain_wallet_update_balance(dap_chain_wallet_t *a_wallet,
                                   const char *a_ticker,
                                   uint256_t a_new_balance);
```

### Создание транзакций

```c
// Создание транзакции перевода
dap_chain_datum_tx_t* dap_chain_wallet_create_transfer(dap_chain_wallet_t *a_wallet,
                                                     const char *a_to_addr,
                                                     const char *a_ticker,
                                                     uint256_t a_amount);

// Создание транзакции с данными
dap_chain_datum_tx_t* dap_chain_wallet_create_tx_with_data(dap_chain_wallet_t *a_wallet,
                                                         const char *a_to_addr,
                                                         const char *a_ticker,
                                                         uint256_t a_amount,
                                                         const void *a_data,
                                                         size_t a_data_size);

// Подписание транзакции
bool dap_chain_wallet_sign_tx(dap_chain_wallet_t *a_wallet,
                            dap_chain_datum_tx_t *a_tx);
```

### Работа с монетами

```c
// Создание монеты
dap_chain_coin_t* dap_chain_coin_create(const char *a_ticker,
                                      uint256_t a_emission);

// Добавление монеты в кошелек
bool dap_chain_wallet_add_coin(dap_chain_wallet_t *a_wallet,
                             dap_chain_coin_t *a_coin);

// Получение информации о монете
dap_chain_coin_info_t* dap_chain_wallet_get_coin_info(dap_chain_wallet_t *a_wallet,
                                                    const char *a_ticker);
```

## Примеры использования

### Пример 1: Создание и использование кошелька

```c
#include "dap_chain_wallet.h"
#include "dap_chain_net.h"

int wallet_example() {
    // Получение сети
    dap_chain_net_t *net = dap_chain_net_by_name("mainnet");
    if (!net) {
        printf("Network not found\n");
        return -1;
    }

    // Создание кошелька с ECDSA ключом
    dap_chain_wallet_t *wallet = dap_chain_wallet_create_with_key(
        "my_wallet",
        net,
        DAP_ENC_KEY_TYPE_SIG_ECDSA
    );

    if (!wallet) {
        printf("Failed to create wallet\n");
        return -1;
    }

    // Вывод адреса кошелька
    char addr_str[128];
    dap_chain_addr_to_str(&wallet->addr, addr_str, sizeof(addr_str));
    printf("Wallet address: %s\n", addr_str);

    // Получение баланса (предположим, что токен CELL)
    uint256_t balance = dap_chain_wallet_get_balance(wallet, "CELL");
    char balance_str[64];
    uint256_to_str(balance, balance_str, sizeof(balance_str));
    printf("Balance: %s CELL\n", balance_str);

    // Очистка
    dap_chain_wallet_delete(wallet);

    return 0;
}
```

### Пример 2: Мультиподписной кошелек

```c
#include "dap_chain_wallet.h"

int multisig_wallet_example() {
    // Создание мультиподписного кошелька (2 из 3)
    dap_chain_wallet_t *wallet = dap_chain_wallet_create_multisig(
        "multisig_wallet",
        net,
        3,  // 3 ключа всего
        2   // нужно 2 подписи
    );

    // Добавление ключей участников
    dap_enc_key_t *key1 = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, "seed1", 5, 0);
    dap_enc_key_t *key2 = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, "seed2", 5, 0);
    dap_enc_key_t *key3 = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, "seed3", 5, 0);

    dap_chain_wallet_multisig_add_key(wallet, key1);
    dap_chain_wallet_multisig_add_key(wallet, key2);
    dap_chain_wallet_multisig_add_key(wallet, key3);

    // Создание транзакции
    dap_chain_datum_tx_t *tx = dap_chain_wallet_create_transfer(
        wallet,
        "recipient_address",
        "CELL",
        uint256_from_str("1000000000")  // 1000 CELL
    );

    // Подписание транзакции (нужно 2 из 3 подписей)
    if (dap_chain_wallet_sign_tx(wallet, tx)) {
        printf("Transaction signed successfully\n");
    }

    // Очистка
    dap_chain_datum_tx_delete(tx);
    dap_chain_wallet_delete(wallet);
    dap_enc_key_delete(key1);
    dap_enc_key_delete(key2);
    dap_enc_key_delete(key3);

    return 0;
}
```

### Пример 3: Работа с токенами

```c
#include "dap_chain_wallet.h"
#include "dap_chain_coin.h"

int token_example() {
    // Создание кастомного токена
    dap_chain_coin_t *token = dap_chain_coin_create(
        "MYTOKEN",
        uint256_from_str("1000000000000")  // Общая эмиссия
    );

    // Добавление токена в кошелек
    dap_chain_wallet_add_coin(wallet, token);

    // Проверка баланса токена
    uint256_t balance = dap_chain_wallet_get_balance(wallet, "MYTOKEN");
    if (uint256_is_zero(balance)) {
        printf("No MYTOKEN balance\n");
    } else {
        char balance_str[64];
        uint256_to_str(balance, balance_str, sizeof(balance_str));
        printf("MYTOKEN balance: %s\n", balance_str);
    }

    // Создание транзакции с токеном
    dap_chain_datum_tx_t *tx = dap_chain_wallet_create_transfer(
        wallet,
        "recipient_address",
        "MYTOKEN",
        uint256_from_str("500000000")  // 500 MYTOKEN
    );

    // Подписание и отправка
    if (dap_chain_wallet_sign_tx(wallet, tx)) {
        // Отправка в сеть
        dap_chain_net_tx_add(net, tx);
        printf("Token transfer sent\n");
    }

    return 0;
}
```

## Кэширование и производительность

### Кэш кошелька

```c
typedef struct dap_chain_wallet_cache {
    // Кэшированные балансы
    dap_hash_t balances_hash;           // Хеш состояния балансов
    time_t balances_timestamp;          // Время последнего обновления

    // Кэшированные транзакции
    dap_list_t *recent_txs;             // Недавние транзакции
    size_t max_cached_txs;              // Максимум кэшированных TX

    // Кэшированные адреса
    dap_hash_t addr_book_hash;          // Хеш адресной книги
    dap_list_t *addr_book;              // Адресная книга

    // Настройки кэша
    size_t max_cache_size;              // Максимальный размер кэша
    time_t cache_ttl;                   // Время жизни кэша
} dap_chain_wallet_cache_t;
```

### Оптимизации производительности

```c
// Предварительная загрузка данных кошелька
bool dap_chain_wallet_cache_preload(dap_chain_wallet_t *a_wallet);

// Очистка устаревшего кэша
void dap_chain_wallet_cache_cleanup(dap_chain_wallet_t *a_wallet,
                                  time_t a_max_age);

// Проверка актуальности кэша
bool dap_chain_wallet_cache_is_valid(dap_chain_wallet_t *a_wallet);
```

## Безопасность

### Защита кошелька

```c
// Установка пароля на кошелек
bool dap_chain_wallet_set_password(dap_chain_wallet_t *a_wallet,
                                 const char *a_password);

// Проверка пароля
bool dap_chain_wallet_verify_password(dap_chain_wallet_t *a_wallet,
                                    const char *a_password);

// Шифрование чувствительных данных
bool dap_chain_wallet_encrypt_sensitive_data(dap_chain_wallet_t *a_wallet);

// Безопасное удаление ключа из памяти
void dap_chain_wallet_secure_erase_key(dap_chain_wallet_key_t *a_key);
```

### Аудит операций

```c
// Логирование операций кошелька
void dap_chain_wallet_log_operation(dap_chain_wallet_t *a_wallet,
                                  const char *a_operation,
                                  const char *a_details);

// Получение истории операций
dap_list_t* dap_chain_wallet_get_operation_history(dap_chain_wallet_t *a_wallet,
                                                 time_t a_from_time,
                                                 time_t a_to_time);
```

## Тестирование

### Запуск тестов

```bash
# Сборка с тестами
cmake -DBUILD_CELLFRAME_SDK_TESTS=ON ..
make

# Запуск тестов wallet модуля
./test/wallet/test_wallet_basic
./test/wallet/test_wallet_multisig
./test/wallet/test_wallet_cache
./test/wallet/test_coin_operations
```

### Пример теста

```c
#include "dap_test.h"
#include "dap_chain_wallet.h"

void test_wallet_creation() {
    // Создание тестовой сети
    dap_chain_net_t *net = dap_chain_net_create("testnet");
    DAP_ASSERT(net != NULL);

    // Создание кошелька
    dap_chain_wallet_t *wallet = dap_chain_wallet_create("test_wallet", net);
    DAP_ASSERT(wallet != NULL);
    DAP_ASSERT(wallet->name != NULL);
    DAP_ASSERT(strcmp(wallet->name, "test_wallet") == 0);

    // Проверка адреса
    DAP_ASSERT(!dap_chain_addr_is_empty(&wallet->addr));

    // Проверка начального баланса
    uint256_t balance = dap_chain_wallet_get_balance(wallet, "CELL");
    DAP_ASSERT(uint256_is_zero(balance));

    // Очистка
    dap_chain_wallet_delete(wallet);
    dap_chain_net_delete(net);
}
```

## Производительность

### Бенчмарки операций

| Операция | Производительность | Примечание |
|----------|-------------------|------------|
| Создание кошелька | ~1000 ops/sec | Intel Core i7 |
| Подпись транзакции | ~500 ops/sec | Dilithium |
| Проверка баланса | ~10K ops/sec | С кэшем |
| Создание мультиподписи | ~100 ops/sec | 3 из 5 |

### Оптимизации

#### Параллельная обработка
```c
// Параллельная генерация ключей
typedef struct key_gen_task {
    dap_enc_key_type_t type;
    const char *seed;
    dap_enc_key_t *result;
} key_gen_task_t;

// Пул потоков для генерации ключей
void dap_chain_wallet_parallel_key_gen(dap_list_t *a_tasks,
                                     size_t a_thread_count);
```

#### Batch операции
```c
// Пакетная обработка транзакций
typedef struct tx_batch {
    dap_chain_wallet_t *wallet;
    dap_list_t *transactions;
    size_t batch_size;
} tx_batch_t;

// Пакетное подписание транзакций
bool dap_chain_wallet_batch_sign(dap_chain_wallet_t *a_wallet,
                               dap_list_t *a_transactions);
```

## Интеграция с другими модулями

### Связь с Net модулем

```c
// Отправка транзакции через сеть
bool dap_chain_wallet_send_tx(dap_chain_wallet_t *a_wallet,
                            dap_chain_datum_tx_t *a_tx) {
    // Получение сетевого соединения
    dap_chain_net_t *net = a_wallet->net;

    // Добавление транзакции в mempool
    return dap_chain_net_tx_add(net, a_tx);
}
```

### Связь с Chain модулем

```c
// Синхронизация состояния кошелька
bool dap_chain_wallet_sync_state(dap_chain_wallet_t *a_wallet) {
    // Получение последней информации из цепочки
    dap_chain_t *chain = a_wallet->net->chain;

    // Обновление балансов
    return dap_chain_wallet_update_balances_from_chain(a_wallet, chain);
}
```

## Заключение

Wallet Module предоставляет комплексное решение для управления криптовалютными кошельками в CellFrame SDK:

### Ключевые возможности:
- **Множественные типы ключей**: Поддержка классических и пост-квантовых алгоритмов
- **Мультиподпись**: Гибкая настройка порогов подписей
- **Управление токенами**: Поддержка различных типов токенов
- **Безопасность**: Шифрование и защита чувствительных данных
- **Производительность**: Кэширование и оптимизации для высокой скорости

### Рекомендации по использованию:
1. **Для личного использования**: Используйте Dilithium или Falcon для подписей
2. **Для организаций**: Настройте мультиподписные кошельки
3. **Для высокой безопасности**: Используйте аппаратные кошельки
4. **Для производительности**: Включите кэширование балансов

Для получения дополнительной информации смотрите:
- `dap_chain_wallet.h` - основной API кошелька
- `dap_chain_wallet_key.h` - работа с ключами
- `dap_chain_coin.h` - управление монетами
- Примеры в директории `examples/wallet/`
- Тесты в директории `test/wallet/`
