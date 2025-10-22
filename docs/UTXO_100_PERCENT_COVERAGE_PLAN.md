# План достижения 100% покрытия UTXO Blocking Documentation

**Текущее покрытие:** 52% (12/23 сценариев)  
**Цель:** 100% (23/23 сценариев)  
**Требуется добавить:** 11 новых тестов

---

## 📊 Текущее состояние

### ✅ Что уже покрыто (12/23):

1. ✅ Блокировка UTXO (immediate)
2. ✅ Разблокировка UTXO (immediate)
3. ✅ Очистка всех UTXO
4. ✅ Отложенная блокировка
5. ✅ Отложенная разблокировка
6. ✅ UTXO_BLOCKING_DISABLED при создании
7. ✅ UTXO_STATIC_BLOCKLIST при создании
8. ✅ Invalid UTXO format
9. ✅ DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED
10. ✅ Частичная блокировка (arbitrage)
11. ✅ Delayed blocking (arbitrage)
12. ✅ After unblocking (arbitrage)

### ❌ Что нужно добавить (11/23):

---

## 🔴 Критические тесты (ОБЯЗАТЕЛЬНО для 100%)

### 1. **Test: `token info` показывает blocklist** 🔴

**Приоритет:** КРИТИЧЕСКИЙ  
**Строки документации:** 78-109  
**Причина:** Пользователи не смогут увидеть состояние blocklist

**Что тестировать:**
```bash
cellframe-node-cli token info -net mynetwork -name TEST
```

**Ожидаемый output:**
```json
{
  "ticker": "TEST",
  "utxo_blocklist_count": 2,
  "utxo_blocklist": [
    {
      "tx_hash": "0x1234...",
      "out_idx": 0,
      "blocked_time": 1697529600,
      "becomes_effective": 1697529600,
      "becomes_unblocked": 0
    }
  ]
}
```

**Тестовый сценарий:**
```c
static void s_test_token_info_shows_blocklist(void)
{
    dap_print_module_name("CLI Test: token info with blocklist");

    // 1. Создать токен с emission
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "INFO_TEST", "10000.0", "5000.0", 
        &s_addr, s_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");

    // 2. Создать транзакцию
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "INFO_TEST", "1000.0", 
        &s_addr, s_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction created");
    test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);

    // 3. Заблокировать UTXO через CLI
    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx->tx_hash);
    char l_cmd[2048];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net Snet -token INFO_TEST -utxo_blocked_add %s:0 -certs %s",
             l_tx_hash_str, s_cert->name);
    
    char l_json_request[4096];
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    dap_assert_PIF(l_reply != NULL, "token_update executed");

    // 4. Вызвать token info
    snprintf(l_cmd, sizeof(l_cmd), "token info -net Snet -name INFO_TEST");
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token\",\"params\":[\"%s\"],\"id\":2,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_info_reply = dap_cli_cmd_exec(l_json_request);
    dap_assert_PIF(l_info_reply != NULL, "token info executed");

    // 5. Парсить JSON и проверить наличие utxo_blocklist
    json_object *l_json_reply = json_tokener_parse(l_info_reply);
    dap_assert_PIF(l_json_reply != NULL, "JSON reply parsed");

    json_object *l_result = NULL;
    json_object_object_get_ex(l_json_reply, "result", &l_result);
    dap_assert_PIF(l_result != NULL, "Result field exists");

    // 6. Проверить utxo_blocklist_count
    json_object *l_blocklist_count = NULL;
    json_object_object_get_ex(l_result, "utxo_blocklist_count", &l_blocklist_count);
    dap_assert_PIF(l_blocklist_count != NULL, "utxo_blocklist_count field exists");
    
    int l_count = json_object_get_int(l_blocklist_count);
    dap_assert_PIF(l_count == 1, "Blocklist count is 1");

    // 7. Проверить utxo_blocklist array
    json_object *l_blocklist = NULL;
    json_object_object_get_ex(l_result, "utxo_blocklist", &l_blocklist);
    dap_assert_PIF(l_blocklist != NULL, "utxo_blocklist field exists");
    dap_assert_PIF(json_object_is_type(l_blocklist, json_type_array), "Blocklist is array");

    // 8. Проверить первый элемент blocklist
    json_object *l_first_entry = json_object_array_get_idx(l_blocklist, 0);
    dap_assert_PIF(l_first_entry != NULL, "First blocklist entry exists");

    json_object *l_tx_hash_obj = NULL;
    json_object_object_get_ex(l_first_entry, "tx_hash", &l_tx_hash_obj);
    dap_assert_PIF(l_tx_hash_obj != NULL, "tx_hash field exists in blocklist entry");

    json_object *l_out_idx_obj = NULL;
    json_object_object_get_ex(l_first_entry, "out_idx", &l_out_idx_obj);
    dap_assert_PIF(l_out_idx_obj != NULL, "out_idx field exists in blocklist entry");

    // 9. Проверить временные метки
    json_object *l_blocked_time_obj = NULL;
    json_object_object_get_ex(l_first_entry, "blocked_time", &l_blocked_time_obj);
    dap_assert_PIF(l_blocked_time_obj != NULL, "blocked_time field exists");

    json_object *l_becomes_effective_obj = NULL;
    json_object_object_get_ex(l_first_entry, "becomes_effective", &l_becomes_effective_obj);
    dap_assert_PIF(l_becomes_effective_obj != NULL, "becomes_effective field exists");

    json_object *l_becomes_unblocked_obj = NULL;
    json_object_object_get_ex(l_first_entry, "becomes_unblocked", &l_becomes_unblocked_obj);
    dap_assert_PIF(l_becomes_unblocked_obj != NULL, "becomes_unblocked field exists");

    log_it(L_INFO, "✅ token info correctly shows blocklist with all required fields");

    // Cleanup
    json_object_put(l_json_reply);
    DAP_DELETE(l_tx_hash_str);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
}
```

**Файл:** `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c`  
**Строки для добавления:** ~100

---

### 2. **Test: UTXO_STATIC_BLOCKLIST enforcement** 🔴

**Приоритет:** КРИТИЧЕСКИЙ (SECURITY RISK!)  
**Строки документации:** 229-253  
**Причина:** Immutability - это security feature!

**Что тестировать:**
```bash
# Step 1: Create with UTXO_STATIC_BLOCKLIST
token_decl -flags UTXO_STATIC_BLOCKLIST -utxo_blocked_add 0xabcd:0

# Step 2: Try to modify (should FAIL)
token_update -utxo_blocked_add 0xef01:1  # должно быть отвергнуто
token_update -utxo_blocked_remove 0xabcd:0  # должно быть отвергнуто
token_update -utxo_blocked_clear  # должно быть отвергнуто
```

**Тестовый сценарий:**
```c
static void s_test_static_utxo_blocklist_enforcement(void)
{
    dap_print_module_name("CLI Test: UTXO_STATIC_BLOCKLIST enforcement");

    // 1. Создать токен с UTXO_STATIC_BLOCKLIST и одним заблокированным UTXO
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "STATIC_TEST", "10000.0", "5000.0", 
        &s_addr, s_cert, &l_emission_hash);
    
    // 2. Установить UTXO_STATIC_BLOCKLIST флаг через token_update
    char l_cmd[2048];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net Snet -token STATIC_TEST -flag_set UTXO_STATIC_BLOCKLIST -certs %s",
             s_cert->name);
    
    char l_json_request[4096];
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    dap_assert_PIF(l_reply != NULL, "UTXO_STATIC_BLOCKLIST flag set");

    // 3. Создать транзакцию для блокировки
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "STATIC_TEST", "1000.0", 
        &s_addr, s_cert);
    test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);

    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx->tx_hash);

    // 4. Попытка добавить UTXO в blocklist (должна ПРОВАЛИТЬСЯ)
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net Snet -token STATIC_TEST -utxo_blocked_add %s:0 -certs %s",
             l_tx_hash_str, s_cert->name);
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":2,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_add_reply = dap_cli_cmd_exec(l_json_request);
    dap_assert_PIF(l_add_reply != NULL, "CLI command executed");

    // 5. Проверить что команда вернула ОШИБКУ
    json_object *l_json_reply = json_tokener_parse(l_add_reply);
    dap_assert_PIF(l_json_reply != NULL, "JSON reply parsed");

    json_object *l_error = NULL;
    bool l_has_error = json_object_object_get_ex(l_json_reply, "error", &l_error);
    dap_assert_PIF(l_has_error, "Error field exists (modification rejected)");

    // 6. Проверить текст ошибки
    json_object *l_error_message = NULL;
    json_object_object_get_ex(l_error, "message", &l_error_message);
    const char *l_error_str = json_object_get_string(l_error_message);
    
    bool l_contains_static = (strstr(l_error_str, "UTXO_STATIC_BLOCKLIST") != NULL ||
                              strstr(l_error_str, "immutable") != NULL);
    dap_assert_PIF(l_contains_static, "Error message mentions UTXO_STATIC_BLOCKLIST");

    log_it(L_INFO, "✅ UTXO_STATIC_BLOCKLIST correctly rejects modifications");

    // 7. Попытка удалить из blocklist (должна ПРОВАЛИТЬСЯ)
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net Snet -token STATIC_TEST -utxo_blocked_remove %s:0 -certs %s",
             l_tx_hash_str, s_cert->name);
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":3,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_remove_reply = dap_cli_cmd_exec(l_json_request);
    json_object *l_remove_json = json_tokener_parse(l_remove_reply);
    
    json_object *l_remove_error = NULL;
    l_has_error = json_object_object_get_ex(l_remove_json, "error", &l_remove_error);
    dap_assert_PIF(l_has_error, "Remove operation rejected");

    log_it(L_INFO, "✅ UTXO_STATIC_BLOCKLIST rejects remove operations");

    // 8. Попытка очистить blocklist (должна ПРОВАЛИТЬСЯ)
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net Snet -token STATIC_TEST -utxo_blocked_clear -certs %s",
             s_cert->name);
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":4,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_clear_reply = dap_cli_cmd_exec(l_json_request);
    json_object *l_clear_json = json_tokener_parse(l_clear_reply);
    
    json_object *l_clear_error = NULL;
    l_has_error = json_object_object_get_ex(l_clear_json, "error", &l_clear_error);
    dap_assert_PIF(l_has_error, "Clear operation rejected");

    log_it(L_INFO, "✅ UTXO_STATIC_BLOCKLIST rejects clear operations");

    // Cleanup
    json_object_put(l_json_reply);
    json_object_put(l_remove_json);
    json_object_put(l_clear_json);
    DAP_DELETE(l_tx_hash_str);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
}
```

**Файл:** `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c`  
**Строки для добавления:** ~110

---

### 3. **Test: Vesting сценарий (двухшаговый)** 🔴

**Приоритет:** КРИТИЧЕСКИЙ  
**Строки документации:** 165-188  
**Причина:** Типовой use case для vesting

**Что тестировать:**
```bash
# Step 1: Block immediately
token_update -utxo_blocked_add 0xabcd:0

# Step 2: Schedule delayed unblock
token_update -utxo_blocked_remove 0xabcd:0:1715788800
```

**Тестовый сценарий:**
```c
static void s_test_vesting_scenario(void)
{
    dap_print_module_name("CLI Test: Vesting scenario (block + delayed unblock)");

    // 1. Создать токен и транзакцию
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "VEST", "10000.0", "5000.0", 
        &s_addr, s_cert, &l_emission_hash);

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "VEST", "1000.0", 
        &s_addr, s_cert);
    test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);

    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx->tx_hash);

    // 2. Step 1: Заблокировать UTXO немедленно
    char l_cmd[2048];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net Snet -token VEST -utxo_blocked_add %s:0 -certs %s",
             l_tx_hash_str, s_cert->name);
    
    char l_json_request[4096];
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_reply1 = dap_cli_cmd_exec(l_json_request);
    dap_assert_PIF(l_reply1 != NULL, "Step 1: Immediate block successful");

    log_it(L_INFO, "✓ Step 1: UTXO blocked immediately");

    // 3. Проверить что UTXO нельзя потратить СЕЙЧАС
    test_tx_fixture_t *l_spend_tx_now = test_tx_fixture_create_cond_output(
        s_net_fixture->ledger, &l_tx->tx_hash, 0, "VEST", "500.0", 
        &s_addr, s_cert);
    
    int l_add_ret = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_spend_tx_now);
    dap_assert_PIF(l_add_ret == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, 
                   "UTXO is blocked immediately");

    log_it(L_INFO, "✓ Verified: UTXO cannot be spent now");

    // 4. Step 2: Запланировать delayed unblock через 100 секунд
    uint64_t l_current_time = dap_nanotime_now();
    uint64_t l_unblock_time = l_current_time + 100 * 1000000000ULL; // +100 секунд

    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net Snet -token VEST -utxo_blocked_remove %s:0:%llu -certs %s",
             l_tx_hash_str, (unsigned long long)l_unblock_time, s_cert->name);
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":2,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_reply2 = dap_cli_cmd_exec(l_json_request);
    dap_assert_PIF(l_reply2 != NULL, "Step 2: Delayed unblock scheduled");

    log_it(L_INFO, "✓ Step 2: Delayed unblock scheduled for +100 seconds");

    // 5. Проверить что UTXO ВСЁ ЕЩЁ заблокирован (время не наступило)
    test_tx_fixture_t *l_spend_tx_before = test_tx_fixture_create_cond_output(
        s_net_fixture->ledger, &l_tx->tx_hash, 0, "VEST", "500.0", 
        &s_addr, s_cert);
    
    l_add_ret = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_spend_tx_before);
    dap_assert_PIF(l_add_ret == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, 
                   "UTXO still blocked before unblock time");

    log_it(L_INFO, "✓ Verified: UTXO still blocked before scheduled time");

    // 6. Симулировать прошедшее время (установить blockchain time)
    s_net_fixture->ledger->blockchain_time = l_unblock_time + 10; // +10 для уверенности

    // 7. Проверить что теперь UTXO можно потратить
    test_tx_fixture_t *l_spend_tx_after = test_tx_fixture_create_cond_output(
        s_net_fixture->ledger, &l_tx->tx_hash, 0, "VEST", "500.0", 
        &s_addr, s_cert);
    
    l_add_ret = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_spend_tx_after);
    dap_assert_PIF(l_add_ret == 0, "UTXO successfully spent after unblock time");

    log_it(L_INFO, "✅ Vesting scenario complete: block → delayed unblock → spend");

    // Cleanup
    test_tx_fixture_destroy(l_spend_tx_now);
    test_tx_fixture_destroy(l_spend_tx_before);
    test_tx_fixture_destroy(l_spend_tx_after);
    DAP_DELETE(l_tx_hash_str);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
}
```

**Файл:** `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c`  
**Строки для добавления:** ~100

---

### 4. **Test: Default UTXO blocking behaviour** 🔴

**Приоритет:** КРИТИЧЕСКИЙ  
**Строки документации:** 20-35  
**Причина:** Документация утверждает что UTXO blocking enabled by default

**Что тестировать:**
```bash
# Create token WITHOUT any flags
token_decl -net mynetwork -token TEST -type CF20

# UTXO blocking should work by default
```

**Тестовый сценарий:**
```c
static void s_test_default_utxo_blocking_enabled(void)
{
    dap_print_module_name("CLI Test: Default UTXO blocking enabled");

    // 1. Создать токен БЕЗ явных флагов (default behaviour)
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "DEFAULT", "10000.0", "5000.0", 
        &s_addr, s_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created without explicit flags");

    // 2. Проверить что флаг UTXO_BLOCKING_DISABLED НЕ установлен
    uint16_t l_flags = l_token->datum_token->header_private.flags;
    bool l_blocking_disabled = (l_flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) != 0;
    dap_assert_PIF(!l_blocking_disabled, "UTXO blocking NOT disabled by default");

    log_it(L_INFO, "✓ Token created without UTXO_BLOCKING_DISABLED flag");

    // 3. Создать транзакцию
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "DEFAULT", "1000.0", 
        &s_addr, s_cert);
    test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);

    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx->tx_hash);

    // 4. Попробовать заблокировать UTXO (должно работать)
    char l_cmd[2048];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net Snet -token DEFAULT -utxo_blocked_add %s:0 -certs %s",
             l_tx_hash_str, s_cert->name);
    
    char l_json_request[4096];
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
             l_cmd);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    dap_assert_PIF(l_reply != NULL, "CLI command executed");

    // 5. Проверить что команда УСПЕШНА (нет ошибки)
    json_object *l_json_reply = json_tokener_parse(l_reply);
    dap_assert_PIF(l_json_reply != NULL, "JSON reply parsed");

    json_object *l_error = NULL;
    bool l_has_error = json_object_object_get_ex(l_json_reply, "error", &l_error);
    dap_assert_PIF(!l_has_error, "No error - UTXO blocking works by default");

    log_it(L_INFO, "✓ UTXO successfully blocked using default token");

    // 6. Проверить что UTXO действительно заблокирован
    test_tx_fixture_t *l_spend_tx = test_tx_fixture_create_cond_output(
        s_net_fixture->ledger, &l_tx->tx_hash, 0, "DEFAULT", "500.0", 
        &s_addr, s_cert);
    
    int l_add_ret = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_spend_tx);
    dap_assert_PIF(l_add_ret == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, 
                   "UTXO is blocked (default mechanism works)");

    log_it(L_INFO, "✅ Default UTXO blocking confirmed working");

    // Cleanup
    json_object_put(l_json_reply);
    test_tx_fixture_destroy(l_spend_tx);
    DAP_DELETE(l_tx_hash_str);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
}
```

**Файл:** `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c`  
**Строки для добавления:** ~85

---

## 🟡 Важные тесты (ЖЕЛАТЕЛЬНО для 100%)

### 5. **Test: Множественные `-utxo_blocked_add` в `token_decl`**

**Приоритет:** ВАЖНО  
**Строки документации:** 244-246  
**Причина:** Документация показывает несколько `-utxo_blocked_add` в одной команде

**Тестовый сценарий:**
```c
static void s_test_multiple_utxo_additions_in_token_decl(void)
{
    dap_print_module_name("CLI Test: Multiple -utxo_blocked_add in token_decl");

    // NOTE: Текущая реализация обрабатывает только ПОСЛЕДНИЙ -utxo_blocked_add
    // Этот тест документирует это поведение

    // 1. Создать 3 транзакции для блокировки
    // ... (код создания токена и транзакций)

    // 2. Попробовать задать несколько UTXO при token_decl
    char l_cmd[4096];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_decl -net Snet -token MULTI -type CF20 "
             "-total_supply 100000 -decimals 18 "
             "-utxo_blocked_add %s:0 "
             "-utxo_blocked_add %s:0 "
             "-utxo_blocked_add %s:0 "
             "-certs %s",
             l_tx1_hash_str, l_tx2_hash_str, l_tx3_hash_str, s_cert->name);

    // 3. Проверить сколько UTXO было добавлено
    // Ожидание: только последний (текущее поведение)
    // TODO: Если требуется поддержка множественных, обновить реализацию

    log_it(L_WARNING, "⚠️ Current implementation: only last -utxo_blocked_add is processed");
}
```

**Файл:** `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c`  
**Строки для добавления:** ~60

---

### 6. **Test: `flag_set` через `token_update`**

**Приоритет:** ВАЖНО  
**Строки документации:** 212-222  

**Тестовый сценарий:**
```c
static void s_test_flag_set_via_token_update(void)
{
    dap_print_module_name("CLI Test: flag_set UTXO_BLOCKING_DISABLED via token_update");

    // 1. Создать токен с enabled UTXO blocking
    // 2. Установить UTXO_BLOCKING_DISABLED через token_update
    // 3. Проверить что блокировка больше не работает
}
```

**Файл:** `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c`  
**Строки для добавления:** ~70

---

### 7. **Test: Гибридный контроль (UTXO + address)**

**Приоритет:** ВАЖНО  
**Строки документации:** 292-324  

**Тестовый сценарий:**
```c
static void s_test_hybrid_utxo_and_address_blocking(void)
{
    dap_print_module_name("CLI Test: Hybrid UTXO + address blocking");

    // 1. Создать токен с tx_sender_blocked для адреса bad_actor
    // 2. Заблокировать конкретный UTXO от good_address
    // 3. Проверить что bad_actor не может отправлять вообще
    // 4. Проверить что good_address не может тратить заблокированный UTXO
    // 5. Проверить что good_address может тратить незаблокированные UTXO
}
```

**Файл:** `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c`  
**Строки для добавления:** ~120

---

### 8. **Test: UTXO_BLOCKING_DISABLED behaviour**

**Приоритет:** СРЕДНЕ  
**Строки документации:** 194-227  

**Тестовый сценарий:**
```c
static void s_test_utxo_blocking_disabled_behaviour(void)
{
    dap_print_module_name("CLI Test: UTXO_BLOCKING_DISABLED flag behaviour");

    // 1. Создать токен с UTXO_BLOCKING_DISABLED
    // 2. Попробовать заблокировать UTXO
    // 3. Проверить что UTXO можно потратить (блокировка игнорируется)
}
```

**Файл:** `cellframe-sdk/tests/integration/utxo_blocking_cli_integration_test.c`  
**Строки для добавления:** ~70

---

### 9-11. **Tests: Use Cases (Escrow, Security Incident, ICO)**

**Приоритет:** НИЗКИЙ (примеры, не критично)  
**Строки документации:** 349-427  

Эти тесты дублируют уже покрытый функционал, но в контексте конкретных use cases.

---

## 📊 Итоговая таблица для 100% покрытия

| № | Тест | Приоритет | Строки кода | Файл | Строки док |
|---|------|-----------|-------------|------|------------|
| 1 | token info shows blocklist | 🔴 КРИТИЧНО | ~100 | cli_integration_test.c | 78-109 |
| 2 | UTXO_STATIC_BLOCKLIST enforcement | 🔴 КРИТИЧНО | ~110 | cli_integration_test.c | 229-253 |
| 3 | Vesting scenario | 🔴 КРИТИЧНО | ~100 | cli_integration_test.c | 165-188 |
| 4 | Default UTXO blocking enabled | 🔴 КРИТИЧНО | ~85 | cli_integration_test.c | 20-35 |
| 5 | Multiple UTXO additions in token_decl | 🟡 ВАЖНО | ~60 | cli_integration_test.c | 244-246 |
| 6 | flag_set via token_update | 🟡 ВАЖНО | ~70 | cli_integration_test.c | 212-222 |
| 7 | Hybrid UTXO + address blocking | 🟡 ВАЖНО | ~120 | cli_integration_test.c | 292-324 |
| 8 | UTXO_BLOCKING_DISABLED behaviour | 🟢 СРЕДНЕ | ~70 | cli_integration_test.c | 194-227 |
| 9 | Escrow use case | 🟢 НИЗКО | ~80 | cli_integration_test.c | 349-367 |
| 10 | Security incident use case | 🟢 НИЗКО | ~80 | cli_integration_test.c | 369-390 |
| 11 | ICO/IDO use case | 🟢 НИЗКО | ~90 | cli_integration_test.c | 406-427 |

**Итого строк кода для добавления:** ~965 строк

---

## 🎯 Приоритетный план действий

### Фаза 1: Критические тесты (4 теста, ~395 строк)

1. ✅ `s_test_token_info_shows_blocklist()` - 100 строк
2. ✅ `s_test_static_utxo_blocklist_enforcement()` - 110 строк
3. ✅ `s_test_vesting_scenario()` - 100 строк
4. ✅ `s_test_default_utxo_blocking_enabled()` - 85 строк

**Результат:** Покрытие 70% (16/23)

### Фаза 2: Важные тесты (3 теста, ~250 строк)

5. ✅ `s_test_multiple_utxo_additions_in_token_decl()` - 60 строк
6. ✅ `s_test_flag_set_via_token_update()` - 70 строк
7. ✅ `s_test_hybrid_utxo_and_address_blocking()` - 120 строк

**Результат:** Покрытие 83% (19/23)

### Фаза 3: Дополнительные тесты (4 теста, ~320 строк)

8. ✅ `s_test_utxo_blocking_disabled_behaviour()` - 70 строк
9. ✅ `s_test_escrow_use_case()` - 80 строк
10. ✅ `s_test_security_incident_use_case()` - 80 строк
11. ✅ `s_test_ico_ido_use_case()` - 90 строк

**Результат:** Покрытие 100% (23/23) ✅

---

## 📝 Обновления документации после 100%

1. Обновить `UTXO_CLI_COVERAGE_ANALYSIS.md`:
   - Изменить 52% → 100%
   - Обновить таблицу покрытия
   - Убрать критические предупреждения

2. Обновить `UTXO_VERIFICATION_REPORT.md`:
   - Изменить вердикт с "APPROVE WITH WARNINGS" на "FULLY VERIFIED"
   - Обновить таблицу результатов

3. Запустить `verify_utxo_cli_commands.sh`:
   - Ожидаемый результат: 44/44 PASS (100%)

---

## 🚀 Оценка трудозатрат

- **Фаза 1 (критично):** 4-6 часов разработки + 1 час тестирования
- **Фаза 2 (важно):** 3-4 часа разработки + 1 час тестирования
- **Фаза 3 (дополнительно):** 3-4 часа разработки + 1 час тестирования
- **Обновление документации:** 1 час

**Итого:** ~13-17 часов для достижения 100% покрытия

---

## ✅ Критерии завершения

- [ ] Все 11 новых тестов реализованы
- [ ] Все тесты проходят (ctest -R utxo)
- [ ] Покрытие документации: 100% (23/23)
- [ ] `verify_utxo_cli_commands.sh`: 44/44 PASS
- [ ] Документация обновлена
- [ ] Коммиты запушены в GitLab

---

**Дата создания:** 21 октября 2025  
**Версия:** 1.0  
**Статус:** ПЛАН ГОТОВ К ВЫПОЛНЕНИЮ

