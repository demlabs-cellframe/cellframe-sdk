# Test Fixtures API Documentation

## 📋 Обзор

Test Fixtures API предоставляет удобные helper функции для создания тестовых сущностей (tokens, emissions, transactions) в интеграционных и юнит-тестах Cellframe SDK.

**Принципы дизайна:**
- ✅ Все тестовые helper функции находятся в `tests/fixtures/`
- ✅ **НЕТ изменений production кода** ledger (`modules/net/`)
- ✅ Используется ТОЛЬКО **public API** ledger
- ✅ Self-contained fixtures без зависимости от internal structures

## 📁 Структура

```
tests/fixtures/
├── test_ledger_fixtures.[ch]      # Инициализация сети и ledger
├── test_token_fixtures.[ch]       # Создание токенов
├── test_emission_fixtures.[ch]    # Создание emission (NEW!)
├── test_transaction_fixtures.[ch] # Создание транзакций (UPDATED!)
└── CMakeLists.txt
```

## 🔧 API Reference

### 1. Ledger Fixtures (`test_ledger_fixtures.[ch]`)

#### `test_net_fixture_create()`
```c
test_net_fixture_t *test_net_fixture_create(const char *a_net_name);
```

**Описание:** Создает полностью настроенную тестовую сеть с ledger, zero chain и main chain.

**Возвращает:** Fixture со всеми компонентами или NULL при ошибке.

**Пример:**
```c
test_net_fixture_t *net = test_net_fixture_create("test_net");
dap_assert(net != NULL, "Network created");

// Use net->ledger, net->chain_zero, net->chain_main

test_net_fixture_destroy(net);
```

---

### 2. Emission Fixtures (`test_emission_fixtures.[ch]`) ✨ NEW

#### `test_emission_fixture_create_simple()`
```c
test_emission_fixture_t *test_emission_fixture_create_simple(
    const char *a_token_ticker,
    const char *a_value_str,
    dap_chain_addr_t *a_addr,
    bool a_sign
);
```

**Описание:** Создает простой emission с автоматической подписью (если `a_sign = true`).

**Параметры:**
- `a_token_ticker` - тикер токена
- `a_value_str` - значение emission (например, "1000.0")
- `a_addr` - адрес emission
- `a_sign` - подписать ли emission auto-generated сертификатом

**Возвращает:** Emission fixture или NULL при ошибке.

**Пример:**
```c
dap_chain_addr_t l_addr = {0};
// ... initialize l_addr ...

test_emission_fixture_t *emission = test_emission_fixture_create_simple(
    "MYTOKEN",
    "5000.0",
    &l_addr,
    true  // Auto-sign
);

dap_assert(emission != NULL, "Emission created");
test_emission_fixture_destroy(emission);
```

#### `test_emission_fixture_add_to_ledger()`
```c
int test_emission_fixture_add_to_ledger(
    dap_ledger_t *a_ledger,
    test_emission_fixture_t *a_fixture
);
```

**Описание:** Добавляет emission в ledger используя **ТОЛЬКО public API** (`dap_ledger_token_emission_add`).

**Возвращает:** `0` при успехе, error code при ошибке.

**Пример:**
```c
int result = test_emission_fixture_add_to_ledger(net->ledger, emission);
dap_assert(result == 0, "Emission added to ledger");
```

---

### 3. Token Fixtures (`test_token_fixtures.[ch]`)

#### `test_token_fixture_create_with_emission()` ✨ NEW
```c
test_token_fixture_t *test_token_fixture_create_with_emission(
    dap_ledger_t *a_ledger,
    const char *a_ticker,
    const char *a_total_supply_str,
    const char *a_emission_value_str,
    dap_chain_addr_t *a_addr,
    dap_chain_hash_fast_t *a_emission_hash_out
);
```

**Описание:** Создает токен **И автоматически создает и добавляет emission**.

**Параметры:**
- `a_ledger` - ledger instance
- `a_ticker` - тикер токена
- `a_total_supply_str` - total supply (например, "10000.0")
- `a_emission_value_str` - значение emission (может быть равно total supply)
- `a_addr` - адрес emission
- `a_emission_hash_out` - выходной параметр для emission hash (может быть NULL)

**Возвращает:** Token fixture или NULL при ошибке.

**Пример:**
```c
dap_chain_hash_fast_t emission_hash;

test_token_fixture_t *token = test_token_fixture_create_with_emission(
    net->ledger,
    "MYTOKEN",
    "10000.0",  // total supply
    "5000.0",   // emission value
    &l_addr,
    &emission_hash  // Get emission hash
);

dap_assert(token != NULL, "Token with emission created");

// Now you can use emission_hash for transactions
```

---

### 4. Transaction Fixtures (`test_transaction_fixtures.[ch]`)

#### `test_tx_fixture_create_from_emission()` ✨ NEW
```c
test_tx_fixture_t *test_tx_fixture_create_from_emission(
    dap_chain_hash_fast_t *a_emission_hash,
    const char *a_token_ticker,
    const char *a_value_str,
    dap_chain_addr_t *a_addr_to,
    dap_cert_t *a_cert
);
```

**Описание:** Создает **REAL transaction** с `IN_EMS` input из emission. Это НЕ mock transaction.

**Параметры:**
- `a_emission_hash` - hash emission для spending
- `a_token_ticker` - тикер токена
- `a_value_str` - значение (например, "100.0")
- `a_addr_to` - адрес получателя
- `a_cert` - сертификат для подписи

**Возвращает:** Transaction fixture или NULL при ошибке.

**Пример:**
```c
test_tx_fixture_t *tx = test_tx_fixture_create_from_emission(
    &emission_hash,
    "MYTOKEN",
    "100.0",
    &l_addr_to,
    token->owner_cert
);

dap_assert(tx != NULL, "Transaction created from emission");
```

#### `test_tx_fixture_add_to_ledger()` ✨ NEW
```c
int test_tx_fixture_add_to_ledger(
    dap_ledger_t *a_ledger,
    test_tx_fixture_t *a_fixture
);
```

**Описание:** Добавляет transaction в ledger используя **ТОЛЬКО public API** (`dap_ledger_tx_add`).

**Возвращает:** `0` при успехе, error code при ошибке.

**Пример:**
```c
int result = test_tx_fixture_add_to_ledger(net->ledger, tx);
dap_assert(result == 0, "Transaction added to ledger");
```

---

## 🎯 Полный пример: Создание токена с emission и транзакцией

```c
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"

void test_full_token_emission_tx_lifecycle(void)
{
    dap_print_module_name("test_full_lifecycle");
    
    // Step 1: Create network and ledger
    test_net_fixture_t *net = test_net_fixture_create("test_net");
    dap_assert(net != NULL, "Network created");
    
    // Step 2: Create address for emission
    dap_enc_key_t *key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t addr = {0};
    dap_chain_addr_fill_from_key(&addr, key, net->net->pub.id);
    
    // Step 3: Create token WITH emission automatically
    dap_chain_hash_fast_t emission_hash;
    test_token_fixture_t *token = test_token_fixture_create_with_emission(
        net->ledger,
        "MYTOKEN",
        "10000.0",   // total supply
        "5000.0",    // emission value
        &addr,
        &emission_hash
    );
    dap_assert(token != NULL, "Token with emission created");
    
    // Step 4: Create REAL transaction from emission
    test_tx_fixture_t *tx = test_tx_fixture_create_from_emission(
        &emission_hash,
        "MYTOKEN",
        "100.0",
        &addr,
        token->owner_cert
    );
    dap_assert(tx != NULL, "Transaction from emission created");
    
    // Step 5: Add transaction to ledger
    int result = test_tx_fixture_add_to_ledger(net->ledger, tx);
    dap_assert(result == 0, "Transaction added to ledger");
    
    // Step 6: Verify balance
    uint256_t balance = dap_ledger_calc_balance(net->ledger, &addr, "MYTOKEN");
    dap_assert(!IS_ZERO_256(balance), "Balance is non-zero");
    
    // Cleanup
    test_tx_fixture_destroy(tx);
    test_token_fixture_destroy(token);
    dap_enc_key_delete(key);
    test_net_fixture_destroy(net);
    
    dap_pass_msg("Full lifecycle test passed");
}
```

---

## 🔒 Design Decision: Все в Fixtures!

**Почему НЕТ изменений в production коде ledger?**

1. **Public API достаточен:**
   - `dap_ledger_token_emission_add()` ✅
   - `dap_ledger_tx_add()` ✅
   - `dap_ledger_token_get_first_emission_hash()` ✅

2. **Чистота кода:**
   - Production код не замусорен test-only функциями
   - Test fixtures полностью self-contained

3. **Безопасность:**
   - Нет риска утечки test code в production
   - Нет специальных callbacks или extension points

4. **Простота поддержки:**
   - Все тестовые helper функции в одном месте (`tests/fixtures/`)
   - Легко обновлять и расширять

---

## ✅ Best Practices

1. **Всегда используйте fixtures для setup:**
   ```c
   // ✅ GOOD
   test_net_fixture_t *net = test_net_fixture_create("test");
   test_token_fixture_t *token = test_token_fixture_create_with_emission(...);
   
   // ❌ BAD - ручное создание
   dap_ledger_t *ledger = dap_ledger_create(...);  // Too much boilerplate
   ```

2. **Всегда cleanup fixtures:**
   ```c
   test_net_fixture_destroy(net);
   test_token_fixture_destroy(token);
   test_tx_fixture_destroy(tx);
   ```

3. **Используйте `dap_assert` для проверок:**
   ```c
   dap_assert(result == 0, "Operation succeeded");
   dap_assert(!IS_ZERO_256(balance), "Balance non-zero");
   ```

4. **Для UTXO blocking - используйте реальные TX:**
   ```c
   // Create token with emission
   test_token_fixture_t *token = test_token_fixture_create_with_emission(...);
   
   // Create REAL TX from emission
   test_tx_fixture_t *tx = test_tx_fixture_create_from_emission(...);
   
   // Test UTXO blocking via token_update
   // ...
   ```

---

## 📚 См. также

- `cellframe-sdk/tests/unit/utxo_blocking_unit_test.c` - примеры использования
- `cellframe-sdk/tests/README.md` - общая информация о тестовой инфраструктуре
- `dap-sdk/test-framework/dap_test.h` - test macros (`dap_assert`, `dap_pass_msg`)

---

**Дата создания:** 2025-10-16  
**Версия:** 1.0  
**Статус:** ✅ Production-ready

