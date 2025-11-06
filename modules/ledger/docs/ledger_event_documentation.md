# 📚 DAP Ledger Event Module - Technical Documentation

**Module:** `dap_ledger_event`  
**Source:** `cellframe-sdk/modules/ledger/dap_chain_ledger_event.c`  
**Author:** Roman Khlopkov <roman.khlopkov@demlabs.net>  
**Version:** 1.0 (2025)  
**License:** GPLv3  

---

## 🌟 Концепция модуля событий леджера

### Что такое события леджера?

**События леджера (Ledger Events)** — это прорывная концепция взаимодействия централизованных и децентрализованных сервисов с блокчейном CellFrame. События представляют собой **особые бинарные данные внутри транзакций**, которые сервисы размещают на блокчейне для сопровождения своей деятельности, не связанной напрямую с движением токенов.

### Суть концепции

События позволяют сервисам:
- **Регистрировать произвольные данные** на блокчейне с привязкой к определённому процессу
- **Отмечать состояния в динамике** (например: старт аукциона, размещение ставки, завершение аукциона)
- **Создавать верификаторы**, основанные на наличии и содержимом событий
- **Хранить управляющие параметры** через механизм сервисных декретов

### Три обязательных атрибута события

Каждое событие содержит в заголовке три ключевых атрибута:

1. **Группа (Group Name)** — строковой идентификатор (GUID) принадлежности события определённому процессу
   - Пример: `auction-abc123`, `stake-xyz456`
   - Позволяет группировать связанные события одного процесса

2. **Сервис (Service UID)** — идентификатор сервиса, который создал событие
   - Пример: `auction service`, `stake_ext service`, `bridge service`
   - Определяет владельца и обработчика события

3. **Тип события (Event Type)** — идентификатор состояния/действия в рамках процесса
   - Примеры: `AUCTION_STARTED`, `BID_PLACED`, `AUCTION_FINISHED`
   - Отражает динамику процесса и идентифицирует содержимое

### Содержимое события

Помимо заголовка, событие может содержать **произвольные бинарные данные**, которые сервис трактует по своим правилам:
- Параметры аукциона (начальная цена, длительность)
- Данные ставки (сумма, участник)
- Результаты голосования
- Параметры стейкинга (множитель, срок)
- Любые другие сервисные данные

### Отличие от других событий в CellFrame

⚠️ **Важная терминология:**

В системе CellFrame существует несколько типов "событий" (events):
- **События леджера (Ledger Events)** — описываемая здесь концепция для сервисов
- **События DAG** — связаны с внутренней структурой DAG-графа
- **События реактора DAP SDK** — низкоуровневые системные события

**Все события леджера являются внешними** по отношению к блокчейну — они создаются внешними сервисами и регистрируются через специальные транзакции.

### Архитектура хранилища

**Хранилище событий леджера** — это специализированная надстройка над леджером, которая:
- ✅ Принимает транзакции с событиями от сервисов
- ✅ Верифицирует события через service-specific callbacks
- ✅ Хранит события в оптимизированной hash-структуре
- ✅ Предоставляет API для запросов и подписки на изменения
- ✅ Обрабатывает сервисные декреты (управляющие параметры)

### Существующие применения

На момент создания документации концепция уже используется в:

1. **Сервис расширенного стейкинга (stake_ext)** — децентрализованный
   - События фиксируют начало/завершение стейкинга
   - Верификация stake-транзакций на основе событий

2. **Сервис аукционов (auction)** — централизованный
   - Регистрация старта/финиша аукционов
   - Хранение ставок участников

3. **Механизм сервисных декретов (Service Decrees)**
   - PoA-управление параметрами сервисов
   - Например: изменение комиссии DEX

### Перспективы развития

Концепция имеет **гигантские перспективы** применения для:
- 🌉 **Мосты (Bridges)** — регистрация cross-chain операций
- 💰 **Эмиссионные центры** — контроль выпуска токенов
- 🔄 **DEX и обменники** — регистрация торговых операций
- 🗳️ **Системы голосования** — хранение результатов голосований
- 📊 **Аналитические сервисы** — индексация блокчейн-данных
- И многие другие централизованные и децентрализованные сервисы

---

## 🎯 Executive Summary

**DAP Ledger Event Module** (`dap_chain_ledger_event.c`) — это техническая реализация концепции хранилища событий леджера. Модуль обеспечивает механизм регистрации, верификации и управления событиями сервисов в блокчейне. Он предоставляет изолированную архитектуру для сервисной верификации событий, поддержку механизма PoA-декретов и систему уведомлений о изменениях состояния событий.

### Ключевые возможности:
- 🔐 **Сервисные события** - регистрация данных сервисов на блокчейне с группировкой по GUID
- ⚖️ **Изолированная верификация** - каждый сервис реализует собственную логику проверки событий
- 📜 **PoA Декреты** - специальный тип событий для управления сетевыми параметрами
- 🔔 **Event Notifiers** - система подписки на изменения состояния событий
- 🔒 **Access Control** - управление списком разрешенных публичных ключей для создания событий
- 🧵 **Thread Safety** - полная поддержка многопоточности через RWLock
- 🔄 **Hardfork Support** - специальная логика для миграции событий при hardfork'ах

---

## 📦 Module Dependencies

### Core Dependencies:
```c
#include <pthread.h>                    // Thread synchronization
#include "dap_chain_ledger_pvt.h"       // Ledger private structures
#include "dap_chain_srv.h"              // Service verification API
#include "dap_hash.h"                   // Hash operations
```

### Data Type Dependencies:
- `dap_chain_tx_event_t` - публичная структура события (см. [Event Types](#event-types))
- `dap_chain_tx_item_event_t` - transaction item для события
- `dap_ledger_event_t` - внутренняя структура события в ledger
- `dap_ledger_event_pkey_item_t` - элемент списка разрешенных ключей

---

## 🏗️ Architecture Overview

### Module Responsibilities:

```
┌─────────────────────────────────────────────────────────────┐
│                  DAP LEDGER EVENT MODULE                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  1. EVENT VERIFICATION & REGISTRATION                │   │
│  │     • Verify transaction structure                    │   │
│  │     • Check event signatures                          │   │
│  │     • Validate event permissions (pkey whitelist)     │   │
│  │     • Call service-specific verification             │   │
│  │     • Register event in ledger                        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  2. EVENT MANAGEMENT                                  │   │
│  │     • Store events in hash table (uthash)            │   │
│  │     • Find events by transaction hash                │   │
│  │     • List events by group name                      │   │
│  │     • Remove events (fork resolution)                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  3. ACCESS CONTROL                                    │   │
│  │     • Manage allowed public keys whitelist           │   │
│  │     • Check event creator permissions                │   │
│  │     • PoA decree-based key management                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  4. NOTIFICATION SYSTEM                               │   │
│  │     • Register event notifiers (callbacks)           │   │
│  │     • Notify on event ADDED                          │   │
│  │     • Notify on event DELETED                        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  5. HARDFORK SUPPORT                                  │   │
│  │     • Aggregate events for migration                 │   │
│  │     • Handle hardfork-specific TSD types             │   │
│  │     • Preserve event data integrity                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Integration Points:

```
External Services
    │
    ├─► dap_chain_srv_event_verify()  ────► Service-specific verification
    │
    ├─► dap_chain_srv_decree()        ────► PoA decree processing
    │
    └─► dap_chain_datum_tx_verify_sign() ─► Transaction signature check
```

---

## 📐 Event Types

### 🔹 dap_chain_tx_item_event_t (Transaction Item)

**File:** `cellframe-sdk/modules/datum/include/dap_chain_datum_tx_event.h`

Структура события, хранящаяся в transaction item блокчейна.

```c
typedef struct dap_chain_tx_item_event {
    dap_chain_tx_item_type_t type;     // TX_ITEM_TYPE_EVENT
    uint8_t version;                   // DAP_CHAIN_TX_EVENT_VERSION (0x0001)
    uint16_t event_type;               // Event type identifier
    uint16_t group_name_size;          // Size of group name string
    dap_time_t timestamp;              // Event timestamp
    dap_chain_srv_uid_t srv_uid;       // Service UID
    byte_t group_name[];               // Variable-size group name (GUID)
} DAP_ALIGN_PACKED dap_chain_tx_item_event_t;
```

**Key Fields:**
- `version` - версия формата события (0x0001)
- `event_type` - тип события (см. [Event Type Constants](#event-type-constants))
- `group_name` - GUID для группировки событий
- `srv_uid` - идентификатор сервиса, владеющего событием

---

### 🔹 dap_chain_tx_event_t (Public API Structure)

Публичная структура для работы с событиями через API.

```c
typedef struct dap_chain_tx_event {
    dap_chain_srv_uid_t srv_uid;        // Service UID
    dap_time_t timestamp;               // Event timestamp
    char *group_name;                   // Event group name (heap-allocated)
    dap_chain_hash_fast_t tx_hash;      // Transaction hash
    dap_chain_hash_fast_t pkey_hash;    // Creator's public key hash
    uint16_t event_type;                // Event type
    void *event_data;                   // Custom event data (heap-allocated)
    size_t event_data_size;             // Size of event_data
} dap_chain_tx_event_t;
```

**Memory Management:**
- Все строки и данные размещаются в куче
- Освобождение через `dap_chain_tx_event_delete()`
- Копирование через `dap_chain_tx_event_copy()`

---

### 🔹 dap_ledger_event_t (Internal Ledger Structure)

Внутренняя структура для хранения событий в ledger.

```c
typedef struct dap_ledger_event {
    dap_chain_srv_uid_t srv_uid;        // Service UID
    dap_time_t timestamp;               // Event timestamp
    dap_hash_fast_t tx_hash;            // Transaction hash (hash key)
    dap_hash_fast_t pkey_hash;          // Creator's public key hash
    uint16_t event_type;                // Event type
    char *group_name;                   // Event group name
    void *event_data;                   // Custom event data
    size_t event_data_size;             // Size of event_data
    UT_hash_handle hh;                  // uthash handle (indexed by tx_hash)
} dap_ledger_event_t;
```

**Hash Table Indexing:**
- Индексирование по `tx_hash` (sizeof(dap_hash_fast_t))
- Использование uthash для быстрого поиска O(1)

---

## 🔢 Event Type Constants

**File:** `cellframe-sdk/modules/datum/include/dap_chain_datum_tx_event.h`

### Service Decree Event:
```c
#define DAP_CHAIN_TX_EVENT_TYPE_SERVICE_DECREE   0x8000
```
**Special type:** обрабатывается отдельно через `dap_chain_srv_decree()`, не сохраняется в hash-таблице событий.

### Stake Extended Events:
```c
#define DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_STARTED      0x0001
#define DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_LOCK_PLACED  0x0002
#define DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_ENDED        0x0003
#define DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_CANCELLED    0x0004
```

**Use Case:** Расширенный стейкинг (`stake_ext` service) использует эти события для верификации транзакций на основе состояния стейкинга.

---

## 🔐 TSD Types for Event Data

### Pre-Hardfork:
```c
#define DAP_CHAIN_TX_TSD_TYPE_EVENT_DATA   0x1000
```
Единственный разрешенный TSD тип для хранения данных события до hardfork.

### Post-Hardfork:
```c
#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_EVENT_DATA   // Event data
#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TX_HASH      // Override tx_hash
#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_PKEY_HASH    // Override pkey_hash
```

**Hardfork Migration Logic:**
- При hardfork события переносятся целиком (item + TSD)
- Возможность переопределения `tx_hash` и `pkey_hash` через отдельные TSD
- Это позволяет сохранить исходные идентификаторы событий при миграции

---

## 📖 API Reference

### 🔔 Event Notification API

#### `dap_ledger_event_notify_add()`

**Signature:**
```c
void dap_ledger_event_notify_add(
    dap_ledger_t *a_ledger,
    dap_ledger_event_notify_t a_callback,
    void *a_arg
);
```

**Description:**  
Регистрирует callback-функцию для получения уведомлений о добавлении/удалении событий.

**Parameters:**
- `a_ledger` - экземпляр ledger
- `a_callback` - callback-функция типа `dap_ledger_event_notify_t`
- `a_arg` - пользовательские данные, передаваемые в callback

**Callback Signature:**
```c
typedef void (*dap_ledger_event_notify_t)(
    void *a_arg,                        // User data
    dap_ledger_t *a_ledger,             // Ledger instance
    dap_chain_tx_event_t *a_event,      // Event data
    dap_hash_fast_t *a_tx_hash,         // Transaction hash
    dap_ledger_notify_opcodes_t a_opcode // ADDED or DELETED
);
```

**Notify Opcodes:**
- `DAP_LEDGER_NOTIFY_OPCODE_ADDED` - событие добавлено в ledger
- `DAP_LEDGER_NOTIFY_OPCODE_DELETED` - событие удалено из ledger (при разрешении форков)

**Use Cases:**
- Мониторинг событий для внешних систем
- Обновление индексов и кэшей
- Логирование изменений состояния
- Синхронизация с базами данных

**Thread Safety:** ⚠️ Callback вызывается **без** удержания `events_rwlock`. Потокобезопасность должна обеспечиваться внутри callback.

**Example:**
```c
void my_event_monitor(void *arg, dap_ledger_t *ledger, 
                      dap_chain_tx_event_t *event, 
                      dap_hash_fast_t *tx_hash,
                      dap_ledger_notify_opcodes_t opcode)
{
    if (opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED) {
        log_it(L_INFO, "New event: group=%s, type=0x%04x", 
               event->group_name, event->event_type);
    }
}

// Registration:
dap_ledger_event_notify_add(ledger, my_event_monitor, NULL);
```

---

### 🔍 Event Query API

#### `dap_ledger_event_find()`

**Signature:**
```c
dap_chain_tx_event_t *dap_ledger_event_find(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_tx_hash
);
```

**Description:**  
Находит событие по хэшу транзакции.

**Parameters:**
- `a_ledger` - экземпляр ledger
- `a_tx_hash` - хэш транзакции события

**Returns:**
- `dap_chain_tx_event_t*` - указатель на событие (требует освобождения через `dap_chain_tx_event_delete()`)
- `NULL` - событие не найдено

**Thread Safety:** ✅ Использует `pthread_rwlock_rdlock()` для безопасного чтения.

**Memory Management:**  
⚠️ Возвращаемое значение - **новая копия** события, требует освобождения:
```c
dap_chain_tx_event_t *event = dap_ledger_event_find(ledger, &tx_hash);
if (event) {
    // Use event...
    dap_chain_tx_event_delete(event);
}
```

**Implementation Details:**
1. Захват read lock на `events_rwlock`
2. Поиск в hash table через `HASH_FIND()`
3. Освобождение lock
4. Создание копии через `s_ledger_event_to_tx_event()`

---

#### `dap_ledger_event_get_list()` / `dap_ledger_event_get_list_ex()`

**Signatures:**
```c
dap_list_t *dap_ledger_event_get_list(
    dap_ledger_t *a_ledger,
    const char *a_group_name
);

dap_list_t *dap_ledger_event_get_list_ex(
    dap_ledger_t *a_ledger,
    const char *a_group_name,
    bool a_need_lock
);
```

**Description:**  
Возвращает список событий, опционально фильтруя по имени группы.

**Parameters:**
- `a_ledger` - экземпляр ledger
- `a_group_name` - имя группы для фильтрации (NULL = все события)
- `a_need_lock` - (_ex version only_) нужно ли захватывать rwlock

**Returns:**
- `dap_list_t*` - список `dap_chain_tx_event_t*` (требует освобождения)
- `NULL` - нет событий или ошибка выделения памяти

**Thread Safety:**
- `dap_ledger_event_get_list()` - всегда потокобезопасна (a_need_lock=true)
- `dap_ledger_event_get_list_ex()` - позволяет управлять блокировкой для вложенных вызовов

**Memory Management:**
```c
dap_list_t *events = dap_ledger_event_get_list(ledger, "my_group");
if (events) {
    for (dap_list_t *it = events; it; it = it->next) {
        dap_chain_tx_event_t *event = (dap_chain_tx_event_t*)it->data;
        // Use event...
    }
    dap_list_free_full(events, dap_chain_tx_event_delete);
}
```

**Filtering Logic:**
- `a_group_name == NULL` → все события
- `a_group_name != NULL` → только события с совпадающим `group_name`

**Error Handling:**  
При ошибке выделения памяти весь список освобождается и возвращается `NULL`.

---

### 🔐 Public Key Access Control API

#### `dap_ledger_event_pkey_check()`

**Signature:**
```c
int dap_ledger_event_pkey_check(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_pkey_hash
);
```

**Description:**  
Проверяет, разрешено ли публичному ключу создавать события.

**Parameters:**
- `a_ledger` - экземпляр ledger
- `a_pkey_hash` - хэш публичного ключа

**Returns:**
- `0` - ключ разрешен (или whitelist пуст)
- `-1` - ключ запрещен

**Default Policy:**  
⚠️ Если список разрешенных ключей пуст (`event_pkeys_allowed == NULL`), **все ключи разрешены** по умолчанию.

**Use Case:**  
Ограничение круга лиц, способных создавать любые события (не специфично для типов событий).

**Thread Safety:** ✅ Использует `pthread_rwlock_rdlock()`.

---

#### `dap_ledger_event_pkey_add()`

**Signature:**
```c
int dap_ledger_event_pkey_add(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_pkey_hash
);
```

**Description:**  
Добавляет публичный ключ в whitelist разрешенных для создания событий.

**Parameters:**
- `a_ledger` - экземпляр ledger
- `a_pkey_hash` - хэш публичного ключа

**Returns:**
- `0` - успешно добавлен
- `-1` - ошибка (уже существует, NULL параметр, ошибка памяти)

**Authorization:**  
Обычно вызывается через **PoA декреты** владельцами root-нод сети.

**Thread Safety:** ✅ Использует `pthread_rwlock_wrlock()`.

---

#### `dap_ledger_event_pkey_rm()`

**Signature:**
```c
int dap_ledger_event_pkey_rm(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_pkey_hash
);
```

**Description:**  
Удаляет публичный ключ из whitelist.

**Parameters:**
- `a_ledger` - экземпляр ledger
- `a_pkey_hash` - хэш публичного ключа

**Returns:**
- `0` - успешно удален
- `-1` - ошибка (не найден, NULL параметр)

**Thread Safety:** ✅ Использует `pthread_rwlock_wrlock()`.

---

#### `dap_ledger_event_pkey_list()`

**Signature:**
```c
dap_list_t *dap_ledger_event_pkey_list(
    dap_ledger_t *a_ledger
);
```

**Description:**  
Возвращает список всех разрешенных публичных ключей.

**Returns:**
- `dap_list_t*` - список `dap_hash_fast_t*` (требует освобождения)
- `NULL` - список пуст или ошибка

**Memory Management:**
```c
dap_list_t *keys = dap_ledger_event_pkey_list(ledger);
if (keys) {
    for (dap_list_t *it = keys; it; it = it->next) {
        dap_hash_fast_t *key = (dap_hash_fast_t*)it->data;
        // Use key...
    }
    dap_list_free_full(keys, (dap_callback_destroyed_t)free);
}
```

**Thread Safety:** ✅ Использует `pthread_rwlock_rdlock()`.

---

### 🔧 Internal (Private) API

#### `dap_ledger_pvt_event_verify_add()`

**Signature:**
```c
int dap_ledger_pvt_event_verify_add(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_tx_hash,
    dap_chain_datum_tx_t *a_tx,
    bool a_apply,
    bool a_from_mempool
);
```

**Description:**  
Внутренняя функция для верификации и добавления события в ledger.

**Parameters:**
- `a_ledger` - экземпляр ledger
- `a_tx_hash` - хэш транзакции
- `a_tx` - транзакция с event item
- `a_apply` - применить изменения (true) или только верифицировать (false)
- `a_from_mempool` - источник: mempool (true) или blockchain (false)

**Returns:**
- `0` - успешно
- `-1..-11` - код ошибки верификации

**Error Codes:**
| Code | Description |
|------|-------------|
| `-1` | Event already exists |
| `-2` | Multiple event items in transaction |
| `-3` | Unsupported event version |
| `-4` | Empty group name |
| `-5` | Invalid TSD size |
| `-6` | Unsupported or multiple TSD types |
| `-7` | Event item or signature not found |
| `-8` | Signature verification failed |
| `-9` | Public key not allowed |
| `-10` | Memory allocation error for event_data |
| `-11` | Memory allocation error for group_name |

**Verification Flow:**

```
┌─────────────────────────────────────────────────────────────┐
│  1. Check if event already exists (HASH_FIND)               │
│     └─► Return -1 if exists                                 │
├─────────────────────────────────────────────────────────────┤
│  2. Parse transaction items:                                │
│     • Find TX_ITEM_TYPE_EVENT                               │
│     • Find TX_ITEM_TYPE_TSD (event data)                    │
│     • Extract second signature (event creator)              │
├─────────────────────────────────────────────────────────────┤
│  3. Validate event structure:                               │
│     • version == DAP_CHAIN_TX_EVENT_VERSION                 │
│     • group_name_size > 0                                   │
│     • TSD size matches expected                             │
├─────────────────────────────────────────────────────────────┤
│  4. Handle hardfork-specific logic:                         │
│     • if (is_hardfork_state):                               │
│       - Allow HARDFORK_EVENT_DATA TSD                       │
│       - Allow HARDFORK_TX_HASH override                     │
│       - Allow HARDFORK_PKEY_HASH override                   │
│     • else:                                                  │
│       - Only EVENT_DATA TSD allowed                         │
├─────────────────────────────────────────────────────────────┤
│  5. Verify transaction signature:                           │
│     └─► dap_chain_datum_tx_verify_sign(tx, 1)               │
├─────────────────────────────────────────────────────────────┤
│  6. Extract pkey_hash from signature:                       │
│     └─► dap_sign_get_pkey_hash(event_sign, &pkey_hash)      │
├─────────────────────────────────────────────────────────────┤
│  7. Check public key permission:                            │
│     └─► dap_ledger_event_pkey_check(ledger, &pkey_hash)     │
├─────────────────────────────────────────────────────────────┤
│  8. Handle SERVICE_DECREE events separately:                │
│     • if (event_type == SERVICE_DECREE):                    │
│       - Call dap_chain_srv_decree()                         │
│       - Don't store in events hash table                    │
│       - Return immediately                                   │
├─────────────────────────────────────────────────────────────┤
│  9. Call service-specific verification:                     │
│     └─► dap_chain_srv_event_verify(net_id, srv_uid,         │
│                                     group_name, event_type,  │
│                                     event_data, ...)         │
├─────────────────────────────────────────────────────────────┤
│  10. If verification passed and a_apply == true:            │
│      • Allocate dap_ledger_event_t                          │
│      • Copy all fields                                      │
│      • Add to hash table (HASH_ADD_BYHASHVALUE)             │
│      • Notify all registered callbacks                      │
└─────────────────────────────────────────────────────────────┘
```

**Mempool vs Blockchain Logic:**

```c
if (l_ret || !a_apply) {
    // Verification failed or dry-run
    return a_from_mempool ? l_ret : 0;
}
```

- **From mempool:** возвращает код ошибки при провале верификации → транзакция отклоняется
- **From blockchain:** возвращает 0 даже при провале → транзакция принимается (для начальной синхронизации и загрузки)

**Thread Safety:**  
⚠️ Функция захватывает:
- `wrlock` если `a_apply == true`
- `rdlock` если `a_apply == false`

Notifiers вызываются **после** освобождения lock.

---

#### `dap_ledger_pvt_event_remove()`

**Signature:**
```c
int dap_ledger_pvt_event_remove(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_tx_hash
);
```

**Description:**  
Удаляет событие из ledger (используется при разрешении форков).

**Parameters:**
- `a_ledger` - экземпляр ledger
- `a_tx_hash` - хэш транзакции события

**Returns:**
- `0` - успешно удалено
- `-1` - событие не найдено

**Removal Flow:**
1. Захват `wrlock` на `events_rwlock`
2. Поиск события в hash table
3. Создание копии для notifiers
4. Удаление из hash table (`HASH_DEL`)
5. Освобождение памяти события
6. Освобождение lock
7. Вызов notifiers с опкодом `DELETED`
8. Освобождение копии события

**Thread Safety:** ✅ Использует `pthread_rwlock_wrlock()`.

---

#### `dap_ledger_events_aggregate()`

**Signature:**
```c
dap_ledger_hardfork_events_t *dap_ledger_events_aggregate(
    dap_ledger_t *a_ledger,
    dap_chain_id_t a_chain_id
);
```

**Description:**  
Собирает все события для hardfork-миграции.

**Returns:**
- `dap_ledger_hardfork_events_t*` - linked list событий
- `NULL` - нет событий

**Structure:**
```c
typedef struct dap_ledger_hardfork_events {
    dap_chain_tx_event_t *event;
    struct dap_ledger_hardfork_events *prev, *next;  // DL_LIST
} dap_ledger_hardfork_events_t;
```

**Use Case:**  
При hardfork вся история блокчейна уничтожается, и события переносятся в новые чейны целиком (event item + TSD item).

**Thread Safety:** ✅ Использует `pthread_rwlock_rdlock()`.

**Bug Fix:**  
⚠️ В исходной версии была опечатка: `pthread_rwlock_unlock(&l_ledger_pvt->decrees_rwlock)` → **исправлено на** `events_rwlock`.

---

## 🧵 Thread Safety Guarantees

### RWLock Usage:

| Lock | Purpose | Functions |
|------|---------|-----------|
| `events_rwlock` | Защита hash-таблицы событий | All event query/modify functions |
| `event_pkeys_rwlock` | Защита whitelist публичных ключей | All pkey management functions |

### Locking Strategy:

```c
// Read operations (concurrent access allowed):
pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
// ... read data ...
pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);

// Write operations (exclusive access):
pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
// ... modify data ...
pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
```

### Critical Section Rules:

1. **Minimize lock hold time** - locks освобождаются перед вызовом callbacks
2. **No nested locks** - никогда не захватывается `event_pkeys_rwlock` внутри `events_rwlock`
3. **Copy before notify** - notifiers получают копии событий, не требующие lock

### Notifier Thread Safety:

⚠️ **ВАЖНО:** Callbacks вызываются **без** удержания `events_rwlock`. Это означает:

```c
// Inside dap_ledger_pvt_event_remove():
pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);  // Lock released!

// Now calling notifiers (no lock held):
for (dap_list_t *it = l_ledger_pvt->event_notifiers; it; it = it->next) {
    l_notifier->callback(...);  // Callback must be thread-safe
}
```

**Implications:**
- Callback может получить копию события, которое уже изменено другим потоком
- Callback должен использовать собственные механизмы синхронизации при доступе к shared state
- Callback НЕ ДОЛЖЕН вызывать функции модификации событий (риск deadlock)

---

## 🔄 Data Flow Diagrams

### Event Addition Flow (от mempool):

```
Transaction in Mempool
    │
    ├─► dap_ledger_tx_add()
    │       │
    │       └─► dap_ledger_pvt_event_verify_add(a_from_mempool=true)
    │               │
    │               ├─► [Verification checks]
    │               │
    │               ├─► dap_chain_srv_event_verify() ──┐ (service callback)
    │               │                                    │
    │               ◄───────────────────────────────────┘
    │               │
    │               ├─► if (verification failed):
    │               │       return error_code  ──► Transaction REJECTED
    │               │
    │               └─► if (verification passed):
    │                       ├─► Add to events hash table
    │                       └─► Notify subscribers (ADDED opcode)
    │
    └─► Transaction accepted into blockchain
```

### Event Addition Flow (от blockchain sync):

```
Block sync from network
    │
    ├─► dap_ledger_tx_add()
    │       │
    │       └─► dap_ledger_pvt_event_verify_add(a_from_mempool=false)
    │               │
    │               ├─► [Verification checks]
    │               │
    │               ├─► dap_chain_srv_event_verify() ──┐ (service callback)
    │               │                                    │
    │               ◄───────────────────────────────────┘
    │               │
    │               ├─► if (verification failed):
    │               │       log warning but return 0  ──► Transaction ACCEPTED
    │               │
    │               └─► if (verification passed):
    │                       ├─► Add to events hash table
    │                       └─► Notify subscribers (ADDED opcode)
    │
    └─► Block processed successfully
```

**Key Difference:**  
- Mempool → strict verification (reject invalid)
- Blockchain → permissive (accept for sync, just don't store)

---

### Event Query Flow:

```
Client Request
    │
    ├─► dap_ledger_event_find(tx_hash)
    │       │
    │       ├─► pthread_rwlock_rdlock(&events_rwlock)
    │       ├─► HASH_FIND(events, tx_hash, ...)
    │       ├─► pthread_rwlock_unlock(&events_rwlock)
    │       └─► s_ledger_event_to_tx_event()  ──► Returns copy
    │
    └─► Client receives dap_chain_tx_event_t*
            │
            └─► Must call dap_chain_tx_event_delete() when done
```

---

### Fork Resolution Flow:

```
Fork detected in blockchain
    │
    ├─► Rollback to common ancestor
    │       │
    │       └─► For each transaction in abandoned branch:
    │               │
    │               └─► dap_ledger_pvt_event_remove(tx_hash)
    │                       │
    │                       ├─► pthread_rwlock_wrlock(&events_rwlock)
    │                       ├─► HASH_FIND & HASH_DEL
    │                       ├─► pthread_rwlock_unlock(&events_rwlock)
    │                       └─► Notify subscribers (DELETED opcode)
    │
    └─► Apply transactions from winning branch
            │
            └─► dap_ledger_pvt_event_verify_add() for each new event
```

---

### Service Decree Flow (Special Case):

```
Decree Transaction
    │
    ├─► dap_ledger_pvt_event_verify_add()
    │       │
    │       ├─► Parse event_type
    │       │
    │       └─► if (event_type == DAP_CHAIN_TX_EVENT_TYPE_SERVICE_DECREE):
    │               │
    │               ├─► Extract decree TSD data
    │               │
    │               ├─► dap_chain_srv_decree(net_id, srv_uid, a_apply, tsd_data)
    │               │       │
    │               │       └─► Service-specific decree processing
    │               │               (e.g., PoA key management)
    │               │
    │               └─► Return immediately (NOT stored in events hash)
    │
    └─► Decree processed
```

**Special Properties:**
- Decree не хранится в `events` hash table
- Обрабатывается немедленно через service callback
- Используется для управляющих операций (PoA decrees, network parameters)

---

## 🏗️ Integration with Services

### Service Interface:

Каждый сервис, использующий события, должен реализовать:

```c
// Service event verification callback
int my_service_event_verify(
    dap_chain_net_id_t a_net_id,
    dap_chain_srv_uid_t a_srv_uid,
    const char *a_group_name,
    uint16_t a_event_type,
    dap_tsd_t *a_event_data,
    size_t a_event_data_size,
    dap_hash_fast_t *a_tx_hash
) {
    // Verify event logic specific to service
    // Return 0 if valid, error code otherwise
}

// Service decree processing callback (optional)
int my_service_decree(
    dap_chain_net_id_t a_net_id,
    dap_chain_srv_uid_t a_srv_uid,
    bool a_apply,
    dap_tsd_t *a_decree_data,
    size_t a_decree_data_size
) {
    // Process decree (e.g., update permissions, parameters)
    // Return 0 if valid, error code otherwise
}
```

### Registration:

Services регистрируют свои callbacks через `dap_chain_srv` API:

```c
// Register event verificator
dap_chain_srv_set_event_verificator(
    MY_SERVICE_UID,
    my_service_event_verify
);

// Register decree processor
dap_chain_srv_set_decree_processor(
    MY_SERVICE_UID,
    my_service_decree
);
```

---

### Example: Stake Extended Service

**Use Case:** `stake_ext` использует события для верификации stake-транзакций.

**Event Types:**
- `STAKE_EXT_STARTED` - начало стейкинга
- `STAKE_EXT_LOCK_PLACED` - размещение locked stake
- `STAKE_EXT_ENDED` - завершение стейкинга
- `STAKE_EXT_CANCELLED` - отмена стейкинга

**Verification Logic:**
```c
int stake_ext_event_verify(...) {
    switch (a_event_type) {
    case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_STARTED:
        // Verify:
        // - Event data contains valid multiplier/duration
        // - Group name is unique (no active stake with same GUID)
        // - Calculation rule exists
        break;
        
    case DAP_CHAIN_TX_EVENT_TYPE_STAKE_EXT_LOCK_PLACED:
        // Verify:
        // - Group name references active stake
        // - Position ID is valid
        // - Lock amount matches expected
        break;
        
    // ... other types
    }
    return 0;  // or error code
}
```

**Transaction Verification:**  
При обработке stake-транзакции, ledger проверяет наличие соответствующих событий:

```c
// Inside stake transaction verification:
dap_list_t *events = dap_ledger_event_get_list(ledger, stake_guid);
if (!events) {
    return -1;  // No active stake for this GUID
}

// Verify stake state from events...
dap_list_free_full(events, dap_chain_tx_event_delete);
```

---

## 🛠️ Best Practices

### ✅ DO:

1. **Always free returned events:**
```c
dap_chain_tx_event_t *event = dap_ledger_event_find(ledger, &hash);
if (event) {
    // ... use event ...
    dap_chain_tx_event_delete(event);  // MUST free
}
```

2. **Use group names as logical identifiers:**
```c
// Group name = unique stake GUID
dap_list_t *stake_events = dap_ledger_event_get_list(ledger, "stake-123e4567");
```

3. **Implement robust service verification:**
```c
int my_verify(/* ... */) {
    // Validate ALL fields
    if (!a_event_data || a_event_data_size < sizeof(my_data_t))
        return -1;
    
    // Check business logic
    my_data_t *data = (my_data_t*)a_event_data->data;
    if (data->value > MAX_ALLOWED)
        return -2;
    
    return 0;
}
```

4. **Make notifiers thread-safe:**
```c
void my_notifier(void *arg, dap_ledger_t *ledger, 
                 dap_chain_tx_event_t *event, 
                 dap_hash_fast_t *tx_hash,
                 dap_ledger_notify_opcodes_t opcode)
{
    my_context_t *ctx = arg;
    pthread_mutex_lock(&ctx->mutex);  // Protect shared state
    // ... process event ...
    pthread_mutex_unlock(&ctx->mutex);
}
```

5. **Handle hardfork properly:**
```c
// During hardfork migration:
dap_ledger_hardfork_events_t *events = dap_ledger_events_aggregate(old_ledger, chain_id);
for (auto *it = events; it; it = it->next) {
    // Re-create event transaction with HARDFORK TSD types
    // Apply to new ledger
}
```

---

### ❌ DON'T:

1. **Don't hold locks in callbacks:**
```c
// BAD:
void bad_notifier(...) {
    pthread_rwlock_rdlock(&some_ledger_lock);  // DEADLOCK RISK!
    dap_ledger_event_find(...);
    pthread_rwlock_unlock(&some_ledger_lock);
}
```

2. **Don't assume event persistence:**
```c
// BAD:
dap_chain_tx_event_t *event = dap_ledger_event_find(ledger, &hash);
// ... later, in another thread ...
// event may be deleted by fork resolution!
```

3. **Don't modify events hash in service verificators:**
```c
// BAD:
int my_verify(...) {
    dap_ledger_event_pkey_add(ledger, &some_key);  // May cause issues!
    return 0;
}
```

4. **Don't ignore return values:**
```c
// BAD:
dap_ledger_event_pkey_add(ledger, &key);  // May fail silently

// GOOD:
if (dap_ledger_event_pkey_add(ledger, &key) != 0) {
    log_it(L_ERROR, "Failed to add key");
    return -1;
}
```

5. **Don't use events for high-frequency updates:**
```c
// BAD: Creating event for every balance change
// Events are blockchain objects - expensive!

// GOOD: Use events for state transitions (stake started/ended)
```

---

## 📊 Performance Considerations

### Hash Table Performance:

- **Lookup:** O(1) average via uthash
- **Insert:** O(1) amortized
- **Delete:** O(1) average
- **Iteration:** O(n) where n = number of events

### Memory Overhead:

Per event in ledger:
```
sizeof(dap_ledger_event_t) + 
strlen(group_name) + 
event_data_size + 
uthash overhead (~32 bytes)
```

### Lock Contention:

**Low contention scenario:**
- Frequent reads (event queries)
- Infrequent writes (event addition/removal)
- RWLock allows concurrent reads

**High contention scenario:**
- Multiple threads adding events simultaneously
- Consider batching event additions
- Use `dap_ledger_event_get_list_ex(a_need_lock=false)` carefully

### Optimization Tips:

1. **Batch event queries:**
```c
// Instead of:
for (int i = 0; i < N; i++) {
    dap_ledger_event_find(ledger, &hashes[i]);  // N locks
}

// Do:
dap_list_t *all_events = dap_ledger_event_get_list(ledger, NULL);  // 1 lock
// Filter in memory
```

2. **Use group filtering:**
```c
// More efficient:
dap_list_t *events = dap_ledger_event_get_list(ledger, "my_group");

// Than:
dap_list_t *all = dap_ledger_event_get_list(ledger, NULL);
// Manual filtering
```

3. **Minimize notifier work:**
```c
void fast_notifier(...) {
    // Queue event for processing in separate thread
    enqueue_event_work(event, opcode);
    // Don't do heavy work here!
}
```

---

## 🐛 Error Handling

### Verification Error Codes:

```c
switch (result) {
    case 0:
        // Success
        break;
    case -1:
        // Event already exists or not found
        log_it(L_WARNING, "Duplicate event or not found");
        break;
    case -2:
        // Multiple event items
        log_it(L_ERROR, "Invalid transaction structure");
        break;
    case -3:
        // Unsupported version
        log_it(L_ERROR, "Event version not supported");
        break;
    case -4:
        // Empty group name
        log_it(L_ERROR, "Group name is mandatory");
        break;
    case -5 ... -6:
        // TSD errors
        log_it(L_ERROR, "Invalid TSD structure");
        break;
    case -7:
        // Missing items
        log_it(L_ERROR, "Event item or signature missing");
        break;
    case -8:
        // Signature verification failed
        log_it(L_ERROR, "Invalid event signature");
        break;
    case -9:
        // Public key not allowed
        log_it(L_WARNING, "Event creator not authorized");
        break;
    case -10 ... -11:
        // Memory errors
        log_it(L_CRITICAL, "Memory allocation failed");
        break;
    default:
        // Service-specific error (from verificator)
        log_it(L_WARNING, "Service rejected event: %d", result);
}
```

### Common Pitfalls:

1. **Memory leaks:**
```c
// LEAK:
dap_list_t *events = dap_ledger_event_get_list(ledger, NULL);
// ... forgot to free ...

// FIX:
dap_list_t *events = dap_ledger_event_get_list(ledger, NULL);
if (events) {
    // ... use events ...
    dap_list_free_full(events, dap_chain_tx_event_delete);
}
```

2. **Race conditions:**
```c
// RACE:
dap_chain_tx_event_t *event = dap_ledger_event_find(ledger, &hash);
// ... do something without lock ...
// event may be deleted by another thread!
event->timestamp = new_time;  // CRASH or corruption

// FIX: Work with local copy
dap_chain_tx_event_t *event_copy = dap_chain_tx_event_copy(event);
dap_chain_tx_event_delete(event);
// ... use event_copy (safe) ...
dap_chain_tx_event_delete(event_copy);
```

3. **Null pointer dereference:**
```c
// CRASH:
dap_chain_tx_event_t *event = dap_ledger_event_find(ledger, &hash);
log_it(L_INFO, "Event: %s", event->group_name);  // May be NULL!

// FIX:
dap_chain_tx_event_t *event = dap_ledger_event_find(ledger, &hash);
if (event) {
    log_it(L_INFO, "Event: %s", event->group_name);
    dap_chain_tx_event_delete(event);
} else {
    log_it(L_WARNING, "Event not found");
}
```

---

## 🔍 Debugging Tips

### Enable verbose logging:

```c
#define LOG_TAG "dap_ledger_event"

// In code:
log_it(L_DEBUG, "Event verification: group=%s, type=0x%04x, tx=%s",
       group_name, event_type, dap_hash_fast_to_str_static(tx_hash));
```

### Dump event state:

```c
void dump_ledger_events(dap_ledger_t *ledger) {
    dap_list_t *events = dap_ledger_event_get_list(ledger, NULL);
    log_it(L_INFO, "=== Ledger Events Dump ===");
    int count = 0;
    for (dap_list_t *it = events; it; it = it->next) {
        dap_chain_tx_event_t *e = (dap_chain_tx_event_t*)it->data;
        log_it(L_INFO, "[%d] Group: %s, Type: 0x%04x, SrvUID: 0x%016llx",
               count++, e->group_name, e->event_type, e->srv_uid.uint64);
    }
    log_it(L_INFO, "=== Total: %d events ===", count);
    dap_list_free_full(events, dap_chain_tx_event_delete);
}
```

### Check lock state:

```c
// WARNING: For debugging only, not production code!
pthread_rwlock_t *lock = &PVT(ledger)->events_rwlock;
if (pthread_rwlock_tryrdlock(lock) == 0) {
    log_it(L_DEBUG, "Lock is available");
    pthread_rwlock_unlock(lock);
} else {
    log_it(L_WARNING, "Lock is held!");
}
```

---

## 📝 Example: Complete Event Lifecycle

### 1. Service registers verificator:

```c
// In service init:
dap_chain_srv_set_event_verificator(MY_SRV_UID, my_event_verify);
```

### 2. Client creates event transaction:

```c
// Create event item
dap_chain_tx_item_event_t *event_item = 
    dap_chain_datum_tx_event_create(
        MY_SRV_UID,
        "stake-abc123",  // group GUID
        MY_EVENT_TYPE_STARTED,
        dap_time_now()
    );

// Create TSD with event data
my_event_data_t data = { .value = 1000 };
dap_tsd_t *tsd = dap_tsd_create(
    DAP_CHAIN_TX_TSD_TYPE_EVENT_DATA,
    &data,
    sizeof(data)
);

// Compose transaction
dap_chain_datum_tx_t *tx = dap_chain_datum_tx_create();
dap_chain_datum_tx_add_item(&tx, (byte_t*)event_item);
dap_chain_datum_tx_add_tsd(&tx, tsd);

// Sign transaction (2 signatures required!)
dap_chain_datum_tx_add_sign_from_key(tx, network_key);  // Network fee
dap_chain_datum_tx_add_sign_from_key(tx, creator_key);  // Event creator

// Emit to mempool
dap_chain_mempool_tx_add(mempool, tx, "GDB");
```

### 3. Ledger processes transaction:

```c
// Inside ledger processing:
int ret = dap_ledger_pvt_event_verify_add(
    ledger,
    &tx_hash,
    tx,
    true,      // apply
    true       // from_mempool
);

if (ret != 0) {
    // Transaction rejected
    log_it(L_WARNING, "Event verification failed: %d", ret);
    return;
}

// Event added to ledger and blockchain
```

### 4. Monitor subscribes to events:

```c
void my_monitor(void *arg, dap_ledger_t *ledger,
                dap_chain_tx_event_t *event,
                dap_hash_fast_t *tx_hash,
                dap_ledger_notify_opcodes_t opcode)
{
    if (opcode == DAP_LEDGER_NOTIFY_OPCODE_ADDED) {
        log_it(L_INFO, "New event: %s (type 0x%04x)",
               event->group_name, event->event_type);
        
        // Update external database, index, etc.
        update_my_database(event);
    }
}

// Register monitor
dap_ledger_event_notify_add(ledger, my_monitor, my_context);
```

### 5. Service queries event:

```c
// During stake transaction verification:
dap_list_t *stake_events = dap_ledger_event_get_list(ledger, stake_guid);
if (!stake_events) {
    log_it(L_WARNING, "No stake found for GUID %s", stake_guid);
    return -1;
}

// Find STARTED event
bool found_start = false;
for (dap_list_t *it = stake_events; it; it = it->next) {
    dap_chain_tx_event_t *e = (dap_chain_tx_event_t*)it->data;
    if (e->event_type == MY_EVENT_TYPE_STARTED) {
        found_start = true;
        // Extract and verify stake parameters
        my_event_data_t *data = (my_event_data_t*)e->event_data;
        if (data->value < required_stake) {
            dap_list_free_full(stake_events, dap_chain_tx_event_delete);
            return -2;  // Insufficient stake
        }
        break;
    }
}

dap_list_free_full(stake_events, dap_chain_tx_event_delete);

if (!found_start) {
    log_it(L_WARNING, "Stake not started for GUID %s", stake_guid);
    return -3;
}

// Verification passed
return 0;
```

### 6. Fork resolution removes event:

```c
// During rollback:
int ret = dap_ledger_pvt_event_remove(ledger, &tx_hash);
if (ret == 0) {
    // Notifiers called with DELETED opcode
    log_it(L_INFO, "Event removed due to fork resolution");
}
```

---

## 🔗 Related Modules

### Direct Dependencies:
- **`dap_chain_srv`** - service registration and verification callbacks
- **`dap_chain_ledger`** - main ledger management
- **`dap_chain_datum_tx`** - transaction structure and parsing

### Related Services:
- **`stake_ext`** - extended staking using events for verification
- **`srv-decree`** - PoA decree processing
- **Generic services** - any service can register event types

### Testing:
- **`test_dap_ledger_event.c`** - comprehensive unit test suite
- **`UNIT_TESTS_SPECIFICATION.md`** - test coverage documentation

---

## 📚 Further Reading

### Source Files:
1. `cellframe-sdk/modules/ledger/dap_chain_ledger_event.c` - implementation
2. `cellframe-sdk/modules/ledger/include/dap_chain_ledger.h` - public API
3. `cellframe-sdk/modules/ledger/include/dap_chain_ledger_pvt.h` - private structures
4. `cellframe-sdk/modules/datum/include/dap_chain_datum_tx_event.h` - event types
5. `cellframe-sdk/modules/datum/dap_chain_datum_tx_items.c` - event creation/deletion

### Documentation:
1. `.mcp/ledger_event_module_documentation.md` - this file
2. `cellframe-sdk/modules/ledger/tests/README.md` - test suite documentation

### Related Concepts:
- **Hardfork Migration** - event preservation during network upgrades
- **PoA Decrees** - network governance mechanism
- **Service Verification** - isolated architecture for custom business logic
- **Fork Resolution** - handling blockchain reorganizations

---

## 📄 License

```
Copyright (c) 2025 DeM Labs Inc.
Licensed under GPLv3
```

---

## 📞 Contact & Support

**Author:** Roman Khlopkov <roman.khlopkov@demlabs.net>  
**Organization:** DeM Labs Inc. (https://demlabs.net)  
**Project:** CellFrame SDK (https://cellframe.net)

---

**Document Version:** 1.0  
**Last Updated:** 2025-11-05  
**Reviewed By:** AI Assistant (СЛК documentation standards)

---

## ✅ СЛК Compliance Checklist

- ✅ **Структурированная документация** - разделы по функциональности
- ✅ **API Reference** - полное описание всех публичных функций
- ✅ **Архитектурные диаграммы** - потоки данных и integration points
- ✅ **Thread Safety** - явное указание потокобезопасности
- ✅ **Error Handling** - коды ошибок и их обработка
- ✅ **Best Practices** - рекомендации и anti-patterns
- ✅ **Performance Considerations** - оптимизация и bottlenecks
- ✅ **Examples** - полный lifecycle с примерами кода
- ✅ **Related Modules** - связи с другими компонентами
- ✅ **Doxygen-compatible comments** - в исходном коде (английский язык)

---

**End of Documentation**

