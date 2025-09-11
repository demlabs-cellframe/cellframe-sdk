# CellFrame SDK ESBOCS Consensus Module

## Обзор

**ESBOCS (Enhanced Scalable Blockchain Consensus)** - это продвинутый алгоритм консенсуса, разработанный для высокопроизводительных блокчейн систем. Комбинирует элементы proof-of-stake с оптимизациями для масштабируемости и отказоустойчивости.

## Основные характеристики

- **Тип**: Proof-of-Stake с оптимизациями
- **Масштабируемость**: Поддержка тысяч валидаторов
- **Производительность**: Быстрое достижение консенсуса
- **Отказоустойчивость**: Работа при отказе до 1/3 валидаторов
- **Гибкость**: Настраиваемые параметры консенсуса

## Архитектура

### Основные компоненты

```c
typedef struct dap_chain_esbocs {
    dap_chain_t *chain;                              // Ссылка на цепочку
    dap_chain_cs_blocks_t *blocks;                   // Управление блоками
    dap_chain_esbocs_session_t *session;             // Текущая сессия
    dap_time_t last_directive_vote_timestamp;        // Время последнего голосования
    dap_time_t last_directive_accept_timestamp;      // Время принятия директивы
    dap_time_t last_submitted_candidate_timestamp;    // Время отправки кандидата
    dap_time_t last_accepted_block_timestamp;         // Время принятия блока

    // Callback функции
    dap_chain_esbocs_callback_set_custom_metadata_t callback_set_custom_metadata;
    dap_chain_esbocs_callback_presign_t callback_presign;

    void *_pvt;                                      // Приватные данные
} dap_chain_esbocs_t;
```

### Сессия консенсуса

```c
typedef struct dap_chain_esbocs_session {
    dap_proc_thread_t *proc_thread;           // Поток обработки
    dap_chain_block_t *processing_candidate;  // Обрабатываемый кандидат блока
    dap_chain_t *chain;                       // Цепочка
    dap_chain_esbocs_t *esbocs;              // Консенсус
    dap_time_t ts_round_sync_start;           // Время начала синхронизации раунда
    dap_time_t ts_stage_entry;                // Время входа в стадию

    // Хеш-таблицы для хранения состояния
    dap_chain_esbocs_sync_item_t *sync_items;        // Элементы синхронизации
    dap_chain_esbocs_penalty_item_t *penalty;        // Штрафы

    // Кластеризация базы данных
    dap_global_db_cluster_t *db_cluster;

    // Раунд консенсуса
    dap_chain_esbocs_round_t cur_round;

    // Сетевая информация
    dap_chain_node_addr_t my_addr;            // Мой адрес в сети
    uint8_t state, old_state;                 // Состояние сессии

    // Флаги состояния
    bool cs_timer, round_fast_forward, sync_failed, new_round_enqueued, is_actual_hash;

    // Криптография
    dap_global_db_driver_hash_t db_hash;
    dap_chain_addr_t my_signing_addr;         // Мой адрес подписи
} dap_chain_esbocs_session_t;
```

### Раунд консенсуса

```c
typedef struct dap_chain_esbocs_round {
    uint64_t id;                              // ID раунда
    uint64_t sync_attempt;                    // Попытка синхронизации
    dap_time_t round_start_ts;                // Время начала раунда
    dap_time_t prev_round_start_ts;           // Время предыдущего раунда

    // Хеши состояния
    dap_hash_fast_t last_block_hash;          // Хеш последнего блока
    dap_hash_fast_t directive_hash;           // Хеш директивы
    dap_hash_fast_t attempt_candidate_hash;   // Хеш кандидата попытки

    // Списки валидаторов
    dap_list_t *all_validators;               // Все валидаторы
    dap_list_t *validators_list;              // Активные валидаторы

    // Хеш-таблицы
    dap_chain_esbocs_store_t *store_items;    // Элементы хранения
    dap_chain_esbocs_message_item_t *message_items; // Элементы сообщений

    // Директива
    dap_chain_esbocs_directive_t *directive;

    // Статистика голосования
    uint16_t votes_for_count;                 // Голосов "за"
    uint16_t votes_against_count;             // Голосов "против"
    uint16_t validators_synced_count;         // Синхронизированных валидаторов
    uint16_t total_validators_synced;         // Всего синхронизированных

    // Флаги состояния
    bool directive_applied;                   // Директива применена
    bool sync_sent;                          // Синхронизация отправлена
    uint8_t attempt_num;                     // Номер попытки
} dap_chain_esbocs_round_t;
```

## Протокол сообщений

### Типы сообщений

ESBOCS использует 9 типов сообщений для координации консенсуса:

| Тип | Константа | Описание |
|-----|-----------|----------|
| 0x04 | `MSG_TYPE_SUBMIT` | Предложение кандидата блока |
| 0x08 | `MSG_TYPE_APPROVE` | Одобрение кандидата |
| 0x12 | `MSG_TYPE_REJECT` | Отклонение кандидата |
| 0x16 | `MSG_TYPE_COMMIT_SIGN` | Подпись подтверждения |
| 0x28 | `MSG_TYPE_PRE_COMMIT` | Предварительное подтверждение |
| 0x20 | `MSG_TYPE_DIRECTIVE` | Директива изменения параметров |
| 0x22 | `MSG_TYPE_VOTE_FOR` | Голос "за" директиву |
| 0x24 | `MSG_TYPE_VOTE_AGAINST` | Голос "против" директиву |
| 0x32 | `MSG_TYPE_START_SYNC` | Начало синхронизации |

### Структура сообщения

```c
typedef struct dap_chain_esbocs_message_hdr {
    uint16_t version;                         // Версия протокола
    uint8_t type;                            // Тип сообщения
    uint8_t attempt_num;                     // Номер попытки
    uint64_t round_id;                       // ID раунда
    uint64_t sign_size;                      // Размер подписи
    uint64_t message_size;                   // Размер сообщения
    dap_time_t ts_created;                   // Время создания
    dap_chain_net_id_t net_id;               // ID сети
    dap_chain_id_t chain_id;                 // ID цепочки
    dap_chain_cell_id_t cell_id;             // ID ячейки
    dap_stream_node_addr_t recv_addr;        // Адрес получателя
    dap_hash_fast_t candidate_hash;          // Хеш кандидата
} DAP_ALIGN_PACKED dap_chain_esbocs_message_hdr_t;
```

## API интерфейс

### Основные функции

```c
// Инициализация и деинициализация
int dap_chain_cs_esbocs_init();
void dap_chain_cs_esbocs_deinit(void);

// Управление таймером
bool dap_chain_esbocs_started(dap_chain_net_id_t a_net_id);
void dap_chain_esbocs_stop_timer(dap_chain_net_id_t a_net_id);
void dap_chain_esbocs_start_timer(dap_chain_net_id_t a_net_id);

// Получение информации
dap_pkey_t *dap_chain_esbocs_get_sign_pkey(dap_chain_net_id_t a_net_id);
uint256_t dap_chain_esbocs_get_fee(dap_chain_net_id_t a_net_id);
bool dap_chain_esbocs_get_autocollect_status(dap_chain_net_id_t a_net_id);
```

### Управление валидаторами

```c
// Добавление/удаление валидаторов
bool dap_chain_esbocs_add_validator_to_clusters(
    dap_chain_net_id_t a_net_id,
    dap_stream_node_addr_t *a_validator_addr
);

bool dap_chain_esbocs_remove_validator_from_clusters(
    dap_chain_net_id_t a_net_id,
    dap_stream_node_addr_t *a_validator_addr
);

// Настройка минимального количества валидаторов
int dap_chain_esbocs_set_min_validators_count(
    dap_chain_t *a_chain,
    uint16_t a_new_value
);

uint16_t dap_chain_esbocs_get_min_validators_count(
    dap_chain_net_id_t a_net_id
);
```

### Callback функции

```c
// Установка callback для кастомных метаданных
int dap_chain_esbocs_set_custom_metadata_callback(
    dap_chain_net_id_t a_net_id,
    dap_chain_esbocs_callback_set_custom_metadata_t a_callback
);

// Установка callback для предварительной подписи
int dap_chain_esbocs_set_presign_callback(
    dap_chain_net_id_t a_net_id,
    dap_chain_esbocs_callback_presign_t a_callback
);
```

## Процесс консенсуса

### 1. Синхронизация валидаторов

Каждый раунд начинается с синхронизации всех валидаторов:

1. **Sync**: Валидаторы обмениваются информацией о последнем блоке
2. **Проверка**: Валидация состояния всех участников
3. **Готовность**: Переход к следующей фазе при достижении кворума

### 2. Предложение кандидата

Один из валидаторов предлагает кандидата блока:

1. **Submit**: Отправка кандидата блока всем валидаторам
2. **Валидация**: Каждый валидатор проверяет корректность кандидата
3. **Голосование**: Approve/Reject голоса от валидаторов

### 3. Подтверждение блока

При достижении консенсуса:

1. **Pre-commit**: Предварительное подтверждение кандидата
2. **Commit-sign**: Финальные подписи подтверждения
3. **Блок**: Добавление подтвержденного блока в цепочку

### 4. Директивы

Система поддерживает директивы для изменения параметров:

1. **Directive**: Предложение изменения параметров
2. **Vote**: Голосование валидаторов
3. **Apply**: Применение директивы при достижении консенсуса

## Система штрафов

ESBOCS включает механизм штрафов за пропуск раундов:

```c
#define DAP_CHAIN_ESBOCS_PENALTY_KICK   3U  // Количество пропусков для исключения

typedef struct dap_chain_esbocs_penalty_item {
    dap_chain_addr_t signing_addr;           // Адрес валидатора
    uint16_t miss_count;                    // Количество пропусков
    UT_hash_handle hh;                      // Хеш-таблица
} dap_chain_esbocs_penalty_item_t;
```

## Преимущества ESBOCS

### Высокая производительность
- **Быстрое достижение консенсуса**: Меньше раундов голосования
- **Параллельная обработка**: Одновременная обработка нескольких кандидатов
- **Оптимизированные сообщения**: Эффективный протокол коммуникации

### Масштабируемость
- **Тысячи валидаторов**: Поддержка больших сетей
- **Динамическое управление**: Добавление/удаление валидаторов
- **Кластеризация**: Распределение нагрузки между кластерами

### Отказоустойчивость
- **Работа при отказах**: До 1/3 валидаторов могут отказать
- **Автоматическое восстановление**: Самовосстановление после сбоев
- **Резервные механизмы**: Множественные пути достижения консенсуса

## Использование

### Базовая инициализация

```c
#include "dap_chain_cs_esbocs.h"

// Инициализация консенсуса
if (dap_chain_cs_esbocs_init() != 0) {
    log_error("Failed to initialize ESBOCS consensus");
    return -1;
}

// Проверка статуса
if (dap_chain_esbocs_started(net_id)) {
    log_info("ESBOCS consensus is running");
}

// Основная работа...

// Остановка при завершении
dap_chain_esbocs_stop_timer(net_id);
dap_chain_cs_esbocs_deinit();
```

### Настройка callback'ов

```c
// Callback для кастомных метаданных
uint8_t *custom_metadata_callback(dap_chain_block_t *block,
                                 uint8_t *meta_type,
                                 size_t *data_size) {
    // Возврат кастомных метаданных для блока
    *data_size = my_metadata_size;
    return my_metadata;
}

// Callback для предварительной подписи
bool presign_callback(dap_chain_block_t *block) {
    // Дополнительная валидация блока
    return validate_custom_rules(block);
}

// Установка callback'ов
dap_chain_esbocs_set_custom_metadata_callback(net_id, custom_metadata_callback);
dap_chain_esbocs_set_presign_callback(net_id, presign_callback);
```

### Управление валидаторами

```c
// Добавление нового валидатора
dap_stream_node_addr_t validator_addr = get_new_validator_addr();
if (dap_chain_esbocs_add_validator_to_clusters(net_id, &validator_addr)) {
    log_info("Validator added successfully");
}

// Настройка минимального количества валидаторов
dap_chain_esbocs_set_min_validators_count(chain, 21); // Минимум 21 валидатор
```

## Сравнение с другими алгоритмами

| Характеристика | ESBOCS | DAG-POA | Block-POW |
|----------------|---------|---------|-----------|
| Энергопотребление | Низкое | Низкое | Высокое |
| Производительность | Высокая | Высокая | Средняя |
| Масштабируемость | Высокая | Высокая | Низкая |
| Сложность | Высокая | Средняя | Низкая |
| Отказоустойчивость | Высокая | Средняя | Высокая |

## Заключение

ESBOCS представляет собой современный алгоритм консенсуса, оптимизированный для высокопроизводительных блокчейн систем. Его продвинутая архитектура позволяет добиться высокой пропускной способности и надежности, сохраняя при этом энергоэффективность и безопасность. Модульная структура и поддержка callback'ов делают ESBOCS гибким инструментом для построения масштабируемых блокчейн решений.
