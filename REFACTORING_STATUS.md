# Статус рефакторинга зависимостей модуля ledger

## Выполненная работа

### ✅ Архитектурные изменения

1. **Удалено поле `net` из структуры `dap_ledger_t`**
   - Ledger больше не хранит прямую ссылку на net
   - Разорвана прямая зависимость на уровне структур данных

2. **Изменены API функций ledger**
   - `dap_ledger_create(uint16_t a_flags)` - не требует net
   - `dap_ledger_decree_apply(dap_chain_net_t *a_net, ...)` - net передаётся явно
   - `dap_ledger_decree_load(dap_chain_net_t *a_net, ...)` - net передаётся явно
   - `dap_ledger_anchor_load(dap_chain_net_t *a_net, ...)` - net передаётся явно
   - `dap_ledger_anchor_unload(dap_chain_net_t *a_net, ...)` - net передаётся явно

3. **Добавлена система коллбэков для anchor unload**
   - `typedef dap_ledger_anchor_unload_callback_t` - тип коллбэка
   - `dap_ledger_anchor_unload_set_callback()` - функция регистрации
   - Инфраструктура для регистрации обработчиков

4. **Убрана логика из ledger**
   - Удалён весь switch с прямыми вызовами net/consensus/services из `anchor_unload`
   - Закомментированы прямые вызовы в `decree` обработке
   - Вся логика теперь должна быть в коллбэках

5. **Убран антипаттерн DAP_LEDGER_TEST**
   - Удалены все #ifdef DAP_LEDGER_TEST блоки
   - Код стал единообразным

6. **Созданы новые API функции**
   - `dap_ledger_set_hal_hrl()` - для setup whitelist/blacklist из net
   - `dap_ledger_set_blockchain_timer()` - для setup таймеров из net
   - `dap_ledger_tx_poa_signed(dap_list_t *a_poa_keys, ...)` - не зависит от ledger->net

7. **Добавлены правила в СЛК**
   - Критическое правило CMAKE: НИКОГДА не использовать target_include_directories для чужих модулей
   - Обязательный рефакторинг для разрешения циклических зависимостей
   - Правила добавлены в модули dap_sdk_project.json и cellframe_sdk.json

## Оставшиеся проблемы

### ⚠️ Использования `a_ledger->net` (44 места)

Код ledger активно использует поля net структуры:

**В файле dap_chain_ledger_tx.c (20 использований)**:
- `a_ledger->net->pub.id` - проверка net_id
- `a_ledger->net->pub.native_ticker` - получение нативного тикера
- `a_ledger->net->pub.fee_value` - проверка комиссии
- `a_ledger->net->pub.fee_addr` - адрес комиссии
- `a_ledger->net->pub.chains` - итерация по цепям

**В файле dap_chain_ledger_decree.c (9 использований)**:
- `a_ledger->net->pub.keys` - PoA ключи
- `a_ledger->net->pub.keys_min_count` - минимум ключей
- `a_ledger->net->pub.name` - имя сети
- `a_ledger->net->pub.chains` - цепи сети

**В файле dap_chain_ledger_token.c (4 использования)**:
- `a_ledger->net` - вызов `dap_chain_net_get_load_mode()`
- `a_ledger->net->pub.name` - имя сети для логов
- `a_ledger->net` - получение default chain

**В тестах (3 использования)**:
- Инициализация и очистка test ledger

### ⚠️ Функции требующие рефакторинга

1. **Все функции tx валидации** - используют fee, native_ticker, net_id
2. **Функции token** - используют load_mode, chains
3. **Функции decree** - используют PoA keys
4. **Функции event** - используют srv_uid проверки

## Стратегия завершения рефакторинга

### Вариант A: Параметризация (правильно, но долго)

Изменить API всех функций добавив необходимые параметры:

```c
// БЫЛО:
int dap_ledger_tx_add(dap_ledger_t *a_ledger, ...)

// СТАЛО:
int dap_ledger_tx_add(dap_ledger_t *a_ledger, 
                      dap_chain_net_id_t a_net_id,
                      const char *a_native_ticker,
                      uint256_t a_fee_value,
                      dap_chain_addr_t *a_fee_addr,
                      ...)
```

**Трудозатраты: 8-12 часов**

### Вариант B: Контекстная структура (быстрее, элегантнее)

Создать структуру контекста сети которая передаётся в функции:

```c
typedef struct dap_ledger_net_context {
    dap_chain_net_id_t net_id;
    const char *native_ticker;
    uint256_t fee_value;
    dap_chain_addr_t fee_addr;
    dap_list_t *poa_keys;
    uint16_t poa_keys_min_count;
    // ... остальные необходимые поля
} dap_ledger_net_context_t;

int dap_ledger_tx_add(dap_ledger_t *a_ledger, 
                      dap_ledger_net_context_t *a_net_ctx,
                      ...)
```

**Трудозатраты: 4-6 часов**

### Вариант C: Гибридный подход (рекомендуется)

- Часто используемые параметры (net_id, native_ticker) - через контекст
- Редко используемые - через коллбэки
- Критичные функции (tx_add, token_add) - приоритетный рефакторинг

**Трудозатраты: 6-8 часов**

## Текущее состояние сборки

### ❌ Не собирается

Основная проблема: 44 использования `a_ledger->net` которое больше не существует.

### Необходимые действия для сборки:

1. Исправить все использования `a_ledger->net` (44 места)
2. Обновить вызовы изменённых функций в модуле net
3. Реализовать коллбэки в net/consensus/services модулях
4. Протестировать

## Рекомендации

**Рекомендую Вариант C (Гибридный):**

1. Создать `dap_ledger_net_context_t` для передачи net-специфичных данных
2. Изменить API критичных функций (tx_add, token_add, decree_apply)
3. Остальное через коллбэки
4. Постепенная миграция остальных функций

**Следующий шаг:**
Создать структуру контекста и начать миграцию функций по приоритету.

Продолжить?



