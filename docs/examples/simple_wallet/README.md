# Simple Wallet - Простой кошелек CellFrame SDK

Это простой пример создания и использования кошелька в CellFrame SDK. Пример демонстрирует основные операции с кошельками и может служить основой для более сложных приложений.

## Сборка и запуск

### Сборка

```bash
# Переход в директорию примера
cd cellframe-sdk/docs/examples/simple_wallet

# Создание директории сборки
mkdir build && cd build

# Конфигурация проекта
cmake .. -DCMAKE_BUILD_TYPE=Release

# Сборка
make
```

### Запуск

```bash
# Запуск примера
./simple_wallet
```

## Что демонстрирует пример

### Основные возможности
- ✅ **Инициализация SDK** - правильная последовательность инициализации модулей
- ✅ **Создание кошелька** - генерация нового кошелька с криптографическими ключами
- ✅ **Работа с адресами** - получение и отображение адреса кошелька
- ✅ **Информация о ключах** - получение информации о ключах кошелька
- ✅ **Правильная очистка** - корректное освобождение ресурсов

### Архитектурные паттерны
- **Модульная инициализация** - последовательная инициализация модулей
- **Обработка ошибок** - проверка результатов всех операций
- **Resource management** - правильное управление памятью и ресурсами
- **Graceful shutdown** - корректное завершение работы

## Структура проекта

```
simple_wallet/
├── CMakeLists.txt     # Конфигурация сборки
├── README.md         # Эта документация
└── main.c           # Основная логика примера
```

## Исходный код

### Основной файл (main.c)

```c
#include "dap_common.h"
#include "dap_chain_wallet.h"
#include "dap_enc_key.h"

// Инициализация DAP SDK
int init_result = dap_common_init("simple_wallet", NULL);
if (init_result != 0) {
    return EXIT_FAILURE;
}

// Инициализация wallet модуля
if (dap_chain_wallet_init() != 0) {
    dap_common_deinit();
    return EXIT_FAILURE;
}

// Создание ключа для кошелька
dap_enc_key_t *key = dap_enc_key_new(DAP_ENC_KEY_TYPE_SIG_ECDSA);
dap_enc_key_generate(key);

// Создание кошелька
dap_chain_wallet_t *wallet = dap_chain_wallet_create(
    "my_wallet", ".", DAP_ENC_KEY_TYPE_SIG_ECDSA, NULL);

// Получение адреса кошелька
dap_chain_addr_t *wallet_addr = dap_chain_wallet_get_addr(wallet, 0);

// Очистка ресурсов
DAP_FREE(wallet_addr);
dap_chain_wallet_close(wallet);
dap_enc_key_delete(key);
dap_chain_wallet_deinit();
dap_common_deinit();
```

## Зависимости

### Обязательные
- CellFrame SDK (основные модули)
- DAP Core (базовые функции)
- DAP Common (общие утилиты)
- DAP Crypto (криптография)
- DAP Chain (блокчейн функции)
- DAP Wallet (функции кошелька)

### Опциональные
- CMake 3.10+ (для сборки)

## Ожидаемый вывод

```
CellFrame SDK Simple Wallet Example
===================================

Initializing DAP SDK...
✓ DAP SDK initialized successfully

Initializing wallet module...
✓ Wallet module initialized successfully

Creating new wallet...
✓ Wallet created successfully

Getting wallet address...
✓ Wallet address: CELLXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

Wallet key information:
  Key count: 1
  Key type: 26
  ✓ Key retrieved successfully

Shutting down...
✓ Shutdown completed successfully

Example completed successfully!
You can now explore more advanced CellFrame SDK wallet features.
```

## Расширение функциональности

### Добавление баланса
```c
// Получение баланса кошелька
uint256_t balance = dap_chain_wallet_get_balance(wallet, net_id, "CELL");
char *balance_str = dap_chain_balance_to_coins_uint64(balance);
// Использование balance_str...
free(balance_str);
```

### Работа с транзакциями
```c
// Создание транзакции (требует compose модуля)
compose_config_t config = {
    .net_name = "Backbone",
    .url_str = "http://rpc.cellframe.net",
    .port = 8081
};

json_object *tx = dap_tx_create_compose(
    "Backbone", "CELL", "100.0", "0.001",
    recipient_addr, wallet_addr,
    config.url_str, config.port, NULL
);
```

### Сохранение и загрузка
```c
// Сохранение кошелька
if (dap_chain_wallet_save(wallet, "mypassword") != 0) {
    fprintf(stderr, "Failed to save wallet\n");
}

// Загрузка кошелька
dap_chain_wallet_t *loaded_wallet = dap_chain_wallet_open(
    "my_wallet", ".", "mypassword"
);
```

## Устранение неполадок

### Ошибка инициализации
```
ERROR: Failed to initialize DAP SDK
```
**Решение:** Убедитесь, что CellFrame SDK правильно установлен и настроен.

### Ошибка создания кошелька
```
ERROR: Failed to create wallet
```
**Решение:** Проверьте права доступа к директории для сохранения файлов кошелька.

### Ошибка получения адреса
```
ERROR: Failed to get wallet address
```
**Решение:** Убедитесь, что кошелек был создан правильно и содержит ключи.

## Следующие шаги

1. **Изучите другие примеры:**
   - `hello_cellframe/` - базовое использование SDK
   - `complex_wallet/` - продвинутые функции кошелька

2. **Ознакомьтесь с документацией:**
   - `docs/modules/wallet.md` - полная документация wallet модуля
   - `docs/modules/compose.md` - создание транзакций
   - `docs/modules/common.md` - общие функции

3. **Разработайте свое приложение:**
   - Используйте этот пример как основу
   - Добавьте требуемую функциональность
   - Следуйте лучшим практикам безопасности

---

**Этот пример является отличной отправной точкой для разработки приложений на CellFrame SDK! 🚀**



