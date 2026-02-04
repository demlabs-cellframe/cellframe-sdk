# Unit Test Fixtures - DAP SDK Module Mocking

## Обзор

Unit test fixtures предоставляют систему изоляции для тестирования Cellframe SDK с полным мокированием зависимостей DAP SDK через фреймворк `dap_mock`.

## Философия

**При тестировании Cellframe SDK мы мокируем DAP SDK модули, но НЕ мокируем сам Cellframe SDK.**

Это позволяет:
- ✅ Изолировать тесты от внешних зависимостей (crypto, DB, network)
- ✅ Получить детерминированные результаты тестов
- ✅ Тестировать реальную логику Cellframe SDK
- ✅ Избежать зависимости от файловой системы, сети, БД

## Технологии

### `dap_mock` Framework

Система моков основана на GNU ld `--wrap` механизме и макросах `dap_mock`:

- **`DAP_MOCK_DECLARE(func, defaults)`** - Объявление мока
- **`DAP_MOCK_ENABLE(func)`** - Включение мока
- **`DAP_MOCK_DISABLE(func)`** - Выключение мока
- **`DAP_MOCK_SET_RETURN(func, value)`** - Установка возвращаемого значения
- **`DAP_MOCK_GET_CALL_COUNT(func)`** - Количество вызовов
- **`DAP_MOCK_RESET(func)`** - Сброс счётчиков

### Автоматизация

Система `unit_test_fixtures` автоматически управляет 100+ моками DAP SDK функций:

```c
// ✓ В unit_test_fixtures.c предопределены моки:
DAP_MOCK_DECLARE(dap_enc_key_new, ...);
DAP_MOCK_DECLARE(dap_sign_create, ...);
DAP_MOCK_DECLARE(dap_global_db_get, ...);
DAP_MOCK_DECLARE(dap_time_now, ...);
// ... и многие другие

// ✓ unit_test_mock_dap_sdk_ex() включает/выключает их модулями
if (flags->mock_crypto) {
    DAP_MOCK_ENABLE(dap_enc_key_new);
    DAP_MOCK_ENABLE(dap_sign_create);
    // ... все crypto функции
}
```

## Архитектура

```
┌─────────────────────────────────────────┐
│  Unit Test (test_voting_vote.c)         │
│  ↓ Тестирует реальную логику            │
├─────────────────────────────────────────┤
│  Cellframe SDK (voting service)         │  ← РЕАЛЬНЫЙ КОД
│  ↓ Использует                           │
├─────────────────────────────────────────┤
│  DAP SDK Modules (MOCKED)               │  ← МОКИ
│  - crypto (sign, verify, hash)          │
│  - global_db (storage)                  │
│  - time (dap_time_now)                  │
│  - events, workers, network, etc.       │
└─────────────────────────────────────────┘
```

## Использование

### Базовый пример

```c
#include "unit_test_fixtures.h"

static unit_test_context_t *g_ctx = NULL;

void test_setup(void) {
    // 1. Инициализация контекста
    g_ctx = unit_test_fixture_init("my_test");
    
    // 2. Настройка моков DAP SDK
    dap_sdk_mock_flags_t flags = {
        .mock_crypto = true,      // ✓ Мокируем криптографию
        .mock_global_db = true,   // ✓ Мокируем БД
        .mock_time = true,        // ✓ Мокируем время
        .mock_events = false,     // ✗ Не мокируем события
        // ... остальные false
    };
    
    unit_test_mock_dap_sdk_ex(g_ctx, &flags);
    
    // 3. Настройка моков для Cellframe SDK (ledger, TX, etc.)
    DAP_MOCK_DECLARE(dap_ledger_calc_balance, ...);
    DAP_MOCK_ENABLE(dap_ledger_calc_balance);
}

void test_teardown(void) {
    // Очистка моков Cellframe SDK
    DAP_MOCK_RESET(dap_ledger_calc_balance);
    dap_mock_deinit();
    
    // Очистка unit test контекста
    unit_test_fixture_cleanup(g_ctx);
}
```

### Детальная настройка моков

#### Доступные модули DAP SDK для мокирования:

| Модуль | Описание | Когда мокировать |
|--------|----------|------------------|
| `mock_crypto` | Криптография (sign, verify, hash) | Всегда для unit тестов |
| `mock_global_db` | Key-value хранилище | Всегда для unit тестов |
| `mock_time` | Время (dap_time_now) | Для детерминированных тестов |
| `mock_events` | Система событий | Если не тестируете асинхронность |
| `mock_proc_thread` | Process/thread управление | Если не тестируете параллелизм |
| `mock_worker` | Worker threads | Если не тестируете воркеры |
| `mock_net_client` | Network client | Для изоляции от сети |
| `mock_net_server` | Network server | Для изоляции от сети |
| `mock_stream` | Data streams | Для изоляции от I/O |
| `mock_json` | JSON parser | **НЕ мокировать** если тестируете JSON |
| `mock_timerfd` | Timer events | Если не тестируете таймеры |
| `mock_file_utils` | File operations | Для изоляции от ФС |
| `mock_ring_buffer` | Ring buffer | Редко нужно |

#### Пример: Тестирование voting service

```c
// Мокируем минимум для изоляции:
dap_sdk_mock_flags_t flags = {
    .mock_crypto = true,         // ✓ Криптография не нужна (проверяем логику TX)
    .mock_global_db = true,      // ✓ БД не нужна (нет persistence)
    .mock_time = true,           // ✓ Детерминированное время
    .mock_json = false,          // ✗ НЕ мокируем - voting использует JSON
    .mock_events = false,        // ✗ НЕ мокируем - не используется
    // Всё остальное false
};
```

### Динамическое переключение моков

```c
// Включить мок во время теста
unit_test_mock_toggle(g_ctx, "crypto", true);

// Отключить мок для конкретного теста
unit_test_mock_toggle(g_ctx, "crypto", false);

// Снова включить
unit_test_mock_toggle(g_ctx, "crypto", true);
```

### Генерация тестовых данных

```c
// Детерминированный хеш
dap_hash_sha3_256_t hash;
unit_test_hash_generate(42, &hash);  // Seed = 42

// Детерминированный адрес
dap_chain_addr_t addr;
unit_test_addr_generate(100, 1, &addr);  // Seed=100, net_id=1

// Мок-подпись
dap_sign_t *sign = unit_test_sign_generate(7, data, data_size);

// uint256 из uint64
uint256_t value;
unit_test_uint256_generate(1000000, &value);
```

## Примеры тестов

### Пример 1: Изоляция от криптографии

```c
void test_transaction_validation(void) {
    // Setup: мокируем crypto, чтобы всегда возвращать "valid"
    dap_sdk_mock_flags_t flags = {
        .mock_crypto = true,
        // ...
    };
    unit_test_mock_dap_sdk_ex(g_ctx, &flags);
    
    // Настраиваем мок для проверки подписи
    DAP_MOCK_DECLARE(dap_sign_verify, { .return_value.i = 1 });
    DAP_MOCK_ENABLE(dap_sign_verify);
    DAP_MOCK_SET_RETURN(dap_sign_verify, (void*)(intptr_t)1);  // Always valid
    
    // Тестируем логику валидации TX (без реальной криптографии)
    dap_chain_datum_tx_t *tx = create_test_tx();
    int ret = validate_transaction_logic(tx);
    
    // Проверяем что мок был вызван
    int calls = DAP_MOCK_GET_CALL_COUNT(dap_sign_verify);
    dap_assert_PIF(calls > 0, "Should verify signature");
    dap_assert_PIF(ret == 0, "Validation should pass");
}
```

### Пример 2: Детерминированное время

```c
void test_poll_expiration(void) {
    // Мокируем время для детерминированных тестов
    dap_sdk_mock_flags_t flags = { .mock_time = true };
    unit_test_mock_dap_sdk_ex(g_ctx, &flags);
    
    // Устанавливаем "текущее время"
    DAP_MOCK_DECLARE(dap_time_now, { .return_value.u64 = 1000000 });
    DAP_MOCK_ENABLE(dap_time_now);
    
    // Создаём poll с истечением через 1000 секунд
    dap_chain_datum_tx_t *poll = create_poll(1000000 + 1000);
    
    // Проверяем что poll НЕ истёк
    bool expired = is_poll_expired(poll);
    dap_assert_PIF(!expired, "Poll should not be expired yet");
    
    // "Переносим время вперёд"
    DAP_MOCK_SET_RETURN(dap_time_now, (void*)(intptr_t)(1000000 + 2000));
    
    // Теперь poll истёк
    expired = is_poll_expired(poll);
    dap_assert_PIF(expired, "Poll should be expired now");
}
```

### Пример 3: Изоляция от БД

```c
void test_ledger_operations(void) {
    // Мокируем global_db для изоляции от файловой системы
    dap_sdk_mock_flags_t flags = { .mock_global_db = true };
    unit_test_mock_dap_sdk_ex(g_ctx, &flags);
    
    // Мокируем операции ledger
    DAP_MOCK_DECLARE(dap_ledger_tx_add, { .return_value.i = 0 });
    DAP_MOCK_ENABLE(dap_ledger_tx_add);
    
    // Тестируем добавление TX в ledger (без реальной БД)
    dap_chain_datum_tx_t *tx = create_test_tx();
    int ret = dap_ledger_tx_add(&g_mock_ledger, tx, &hash, false);
    
    // Проверяем что мок был вызван
    dap_assert_PIF(DAP_MOCK_GET_CALL_COUNT(dap_ledger_tx_add) > 0,
                   "Should call ledger_tx_add");
}
```

## Лучшие практики

### ✅ DO:

1. **Мокируйте DAP SDK, тестируйте Cellframe SDK**
   ```c
   // ✅ ПРАВИЛЬНО: мокируем dap_sign_verify (DAP SDK)
   DAP_MOCK_DECLARE(dap_sign_verify, ...);
   // Тестируем dap_voting_tx_create_vote (Cellframe SDK)
   ```

2. **Используйте минимальный набор моков**
   ```c
   // ✅ ПРАВИЛЬНО: мокируем только то, что нужно
   dap_sdk_mock_flags_t flags = {
       .mock_crypto = true,
       .mock_time = true,
       // Всё остальное false
   };
   ```

3. **Генерируйте детерминированные данные**
   ```c
   // ✅ ПРАВИЛЬНО: используйте фикстуры
   unit_test_hash_generate(42, &hash);
   ```

### ❌ DON'T:

1. **Не мокируйте то, что тестируете**
   ```c
   // ❌ НЕПРАВИЛЬНО: мокируем то, что тестируем
   DAP_MOCK_DECLARE(dap_voting_tx_create_vote, ...);
   // Как мы протестируем реальную логику???
   ```

2. **Не используйте глобальные моки везде**
   ```c
   // ❌ НЕПРАВИЛЬНО: мокируем всё подряд
   dap_sdk_mock_flags_t flags = {
       .mock_crypto = true,
       .mock_global_db = true,
       .mock_events = true,
       .mock_proc_thread = true,
       .mock_worker = true,
       .mock_net_client = true,
       // ... и так далее
   };
   // Мы изолировали тесты от ВСЕГО, включая то, что хотим протестировать
   ```

3. **Не забывайте сбрасывать моки**
   ```c
   // ❌ НЕПРАВИЛЬНО: забыли сбросить
   void test_teardown(void) {
       // Забыли DAP_MOCK_RESET(...)
       dap_mock_deinit();  // Моки останутся включёнными!
   }
   ```

## CMake интеграция

Моки автоматически применяются через `dap_mock_autowrap`:

```cmake
dap_add_unit_test(
    NAME test_voting_vote
    SOURCES test_voting_vote.c
    MOCKS
        # DAP SDK mocks (применяются автоматически через fixtures)
        # Cellframe SDK mocks (указываем явно)
        dap_ledger_calc_balance
        dap_ledger_tx_add
        dap_ledger_tx_find_by_hash
    LINK_LIBRARIES
        cellframe_sdk_voting
        unit_test_fixtures  # ← Подключаем фикстуры
)
```

## Отладка

### Проверка активных моков

```c
if (g_ctx->mock_flags.mock_crypto) {
    log_it(L_DEBUG, "Crypto is mocked");
}
```

### Подсчёт вызовов

```c
int calls = DAP_MOCK_GET_CALL_COUNT(dap_ledger_tx_add);
log_it(L_DEBUG, "dap_ledger_tx_add called %d times", calls);
```

### Verbose логирование

```c
dap_log_level_set(L_DEBUG);
unit_test_mock_dap_sdk_ex(g_ctx, &flags);
// Output:
//   DAP SDK module mocks enabled:
//     ✓ crypto (sign, verify, encrypt, hash)
//     ✓ global_db (key-value storage)
//     ✓ time (time functions)
```

## Миграция с legacy API

Старый код:
```c
unit_test_mock_dap_sdk(g_ctx, true, true, false);
```

Новый код:
```c
dap_sdk_mock_flags_t flags = {
    .mock_crypto = true,
    .mock_global_db = true,
    .mock_events = false
};
unit_test_mock_dap_sdk_ex(g_ctx, &flags);
```

Legacy API остаётся для обратной совместимости.

## См. также

- `test_voting_vote.c` - Комплексный пример использования
- `integration_test_fixtures.h` - Фикстуры для интеграционных тестов
- `dap_mock.h` - Документация по DAP mock framework
