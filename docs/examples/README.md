# Примеры использования CellFrame SDK

## Обзор

В этой директории находятся практические примеры использования CellFrame SDK. Каждый пример демонстрирует конкретную функциональность блокчейн-системы и может быть использован как отправная точка для разработки приложений.

## Структура примеров

### Базовые примеры
- `hello_cellframe/` - Простейший пример инициализации SDK
- `basic_wallet/` - Основы работы с кошельком
- `simple_transaction/` - Создание простой транзакции

### Продвинутые примеры
- `blockchain_operations/` - Операции с блокчейном
- `consensus_demo/` - Демонстрация алгоритмов консенсуса
- `network_node/` - Создание сетевого узла

### Специализированные примеры
- `multisig_wallet/` - Мультиподписной кошелек
- `token_creation/` - Создание кастомного токена
- `decentralized_app/` - Простое dApp

## Быстрый старт

### Компиляция примеров

```bash
# Перейти в директорию примера
cd examples/hello_cellframe

# Создать билд директорию
mkdir build && cd build

# Сконфигурировать и собрать
cmake ..
make

# Запустить
./hello_cellframe
```

### Общая структура примера

Каждый пример содержит:
- `CMakeLists.txt` - Скрипт сборки
- `main.c` - Основной код примера
- `README.md` - Описание примера и инструкции

## Основные примеры

### 1. Hello CellFrame

```c
#include "dap_chain.h"

int main() {
    // Инициализация CellFrame SDK
    if (dap_chain_init() != 0) {
        printf("Failed to initialize CellFrame SDK\n");
        return -1;
    }

    printf("Hello, CellFrame World!\n");

    // Очистка ресурсов
    dap_chain_deinit();
    return 0;
}
```

### 2. Работа с кошельком

```c
#include "dap_chain_wallet.h"

int wallet_example() {
    // Инициализация
    dap_chain_init();

    // Создание сети
    dap_chain_net_t *net = dap_chain_net_create("testnet");

    // Создание кошелька
    dap_chain_wallet_t *wallet = dap_chain_wallet_create(
        "my_wallet", net, DAP_ENC_KEY_TYPE_SIG_DILITHIUM
    );

    // Получение адреса
    char addr_str[128];
    dap_chain_addr_to_str(&wallet->addr, addr_str, sizeof(addr_str));
    printf("Wallet address: %s\n", addr_str);

    // Очистка
    dap_chain_wallet_delete(wallet);
    dap_chain_deinit();

    return 0;
}
```

### 3. Создание транзакции

```c
#include "dap_chain_wallet.h"
#include "dap_chain_datum_tx.h"

int transaction_example() {
    // Инициализация
    dap_chain_init();

    // Создание транзакции
    dap_chain_datum_tx_t *tx = dap_chain_wallet_create_transfer(
        wallet,
        "recipient_address",
        "CELL",
        uint256_from_str("1000000")  // 1 CELL
    );

    // Подписание
    dap_chain_wallet_sign_tx(wallet, tx);

    // Отправка в сеть
    dap_chain_net_tx_add(net, tx);

    // Очистка
    dap_chain_datum_tx_delete(tx);
    dap_chain_deinit();

    return 0;
}
```

## Сборка всех примеров

```bash
# Из корневой директории CellFrame SDK
mkdir build && cd build
cmake -DBUILD_CELLFRAME_SDK_EXAMPLES=ON ..
make

# Запуск конкретного примера
./examples/hello_cellframe/hello_cellframe
./examples/basic_wallet/wallet_demo
```

## Требования

- **Компилятор**: GCC 7.0+ или Clang 5.0+
- **CMake**: 3.10+
- **DAP SDK**: Должен быть установлен

## Советы по разработке

### 1. Всегда используйте пост-квантовые алгоритмы

```c
// Рекомендуется для новых проектов
DAP_ENC_KEY_TYPE_SIG_DILITHIUM    // Подписи
DAP_ENC_KEY_TYPE_SIG_FALCON       // Альтернативные подписи

// Избегайте в новых проектах
DAP_ENC_KEY_TYPE_SIG_ECDSA        // Уязвим к квантовым атакам
```

### 2. Правильно управляйте ресурсами

```c
dap_chain_wallet_t *wallet = dap_chain_wallet_create(...);
// Использование кошелька
dap_chain_wallet_delete(wallet); // Важно: очистка ресурсов
```

### 3. Проверяйте возвращаемые значения

```c
if (dap_chain_wallet_sign_tx(wallet, tx) != 0) {
    // Обработка ошибки
    return -1;
}
```

## Алгоритмы консенсуса

### DAG PoA (Proof of Authority)

```c
// Создание сети с DAG PoA
dap_chain_net_t *net = dap_chain_net_create("my_network");
dap_chain_cs_t *consensus = dap_chain_cs_dag_poa_create(net);

// Настройка валидаторов
dap_chain_cs_dag_poa_add_validator(consensus, validator_addr);
```

### Block PoW (Proof of Work)

```c
// Создание сети с Block PoW
dap_chain_net_t *net = dap_chain_net_create("mining_network");
dap_chain_cs_t *consensus = dap_chain_cs_block_pow_create(net, 20); // difficulty
```

## Получение помощи

- **Документация**: [docs/README.md](../README.md)
- **API Reference**: [docs/modules/](../modules/)
- **Архитектура**: [docs/architecture.md](../architecture.md)

## Лицензия

Примеры распространяются под той же лицензией, что и CellFrame SDK.
