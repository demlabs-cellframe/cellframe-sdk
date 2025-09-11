# CellFrame SDK Type Module

## Обзор

**Type Module** - это модуль типов консенсуса CellFrame SDK, предоставляющий различные алгоритмы достижения консенсуса в блокчейн сети. Модуль включает реализации классического proof-of-work с блоками, направленного ациклического графа (DAG) и специального типа для тестирования. Каждый тип консенсуса оптимизирован для специфических сценариев использования и требований к производительности.

## Основные характеристики

- **Множественные алгоритмы**: Поддержка различных типов консенсуса
- **Модульная архитектура**: Легкая замена и настройка алгоритмов
- **Оптимизированные реализации**: Высокопроизводительные вычисления
- **Гибкая конфигурация**: Настраиваемые параметры консенсуса
- **Совместимость**: Единый интерфейс для всех типов

## Структура модуля

### Типы консенсуса

#### 1. Blocks (Классический Proof-of-Work)

Традиционный блокчейн с последовательными блоками:

- **Алгоритм**: Proof-of-Work с блоками
- **Структура**: Линейная цепочка блоков
- **Сложность**: Регулируемая сложность майнинга
- **Применение**: Высокая безопасность и предсказуемость

#### 2. DAG (Directed Acyclic Graph)

Направленный ациклический граф событий:

- **Алгоритм**: DAG-based консенсус
- **Структура**: Граф взаимосвязанных событий
- **Параллелизм**: Высокий уровень параллельной обработки
- **Применение**: Высокая пропускная способность

#### 3. None (Отключенный консенсус)

Специальный тип для тестирования и разработки:

- **Алгоритм**: Без консенсуса
- **Структура**: Простая последовательность
- **Надежность**: Минимальная (для тестирования)
- **Применение**: Разработка и тестирование

## Blocks Type

### Архитектура

#### Структура блока

```c
typedef struct dap_chain_block {
    dap_chain_block_hdr_t hdr;             // Заголовок блока
    uint8_t meta_n_datum_n_sign[];         // Метаданные, данные и подписи
} DAP_ALIGN_PACKED dap_chain_block_t;
```

#### Заголовок блока

```c
typedef struct dap_chain_block_hdr {
    uint32_t signature;                    // Магическое число (DAP_CHAIN_BLOCK_SIGNATURE)
    int32_t version;                       // Версия блока
    dap_chain_cell_id_t cell_id;           // ID ячейки
    dap_chain_id_t chain_id;               // ID цепи
    dap_time_t ts_created;                 // Время создания
    uint16_t meta_count;                   // Количество метаданных
    uint16_t datum_count;                  // Количество datum'ов
    dap_chain_hash_fast_t merkle;          // Merkle хеш
    uint32_t meta_n_datum_n_signs_size;    // Размер секций
} DAP_ALIGN_PACKED dap_chain_block_hdr_t;
```

#### Метаданные блока

```c
typedef struct dap_chain_block_meta {
    struct {
        uint8_t type;                      // Тип метаданных
        uint16_t data_size;                // Размер данных
    } DAP_ALIGN_PACKED hdr;                // Заголовок метаданных
    byte_t data[];                        // Данные метаданных
} DAP_ALIGN_PACKED dap_chain_block_meta_t;
```

### Типы метаданных

| Тип | Константа | Описание |
|-----|-----------|----------|
| 0x01 | `DAP_CHAIN_BLOCK_META_GENESIS` | Genesis блок |
| 0x10 | `DAP_CHAIN_BLOCK_META_PREV` | Предыдущий блок |
| 0x11 | `DAP_CHAIN_BLOCK_META_ANCHOR` | Якорь |
| 0x12 | `DAP_CHAIN_BLOCK_META_LINK` | Связь с другими блоками |
| 0x20 | `DAP_CHAIN_BLOCK_META_NONCE` | Nonce значение |
| 0x21 | `DAP_CHAIN_BLOCK_META_NONCE2` | Дополнительный nonce |
| 0x30 | `DAP_CHAIN_BLOCK_META_MERKLE` | Merkle дерево |
| 0x80 | `DAP_CHAIN_BLOCK_META_EMERGENCY` | Аварийные данные |
| 0x81 | `DAP_CHAIN_BLOCK_META_SYNC_ATTEMPT` | Попытка синхронизации |
| 0x82 | `DAP_CHAIN_BLOCK_META_ROUND_ATTEMPT` | Попытка раунда |
| 0x83 | `DAP_CHAIN_BLOCK_META_EXCLUDED_KEYS` | Исключенные ключи |
| 0x84 | `DAP_CHAIN_BLOCK_META_EVM_DATA` | EVM данные |

## API интерфейс

### Инициализация типов

```c
// Инициализация blocks типа
int dap_chain_cs_blocks_init();

// Инициализация DAG типа
int dap_chain_cs_dag_init();

// Инициализация none типа
int dap_chain_cs_none_init();

// Инициализация блочного модуля
int dap_chain_block_init();
```

### Создание и управление блоками

```c
// Создание нового блока
dap_chain_block_t *dap_chain_block_new(
    dap_chain_hash_fast_t *a_prev_block_hash, // Хеш предыдущего блока
    size_t *a_block_size                      // Размер блока (выходной)
);

// Добавление метаданных в блок
size_t dap_chain_block_meta_add(
    dap_chain_block_t **a_block_ptr,         // Указатель на блок
    size_t a_block_size,                     // Текущий размер блока
    uint8_t a_meta_type,                     // Тип метаданных
    const void *a_data,                      // Данные метаданных
    size_t a_data_size                       // Размер данных
);

// Извлечение метаданных из блока
uint8_t *dap_chain_block_meta_get(
    const dap_chain_block_t *a_block,        // Блок
    size_t a_block_size,                     // Размер блока
    uint8_t a_meta_type                      // Тип метаданных
);
```

### Работа с datum'ами

```c
// Добавление datum в блок
size_t dap_chain_block_datum_add(
    dap_chain_block_t **a_block_ptr,         // Указатель на блок
    size_t a_block_size,                     // Размер блока
    dap_chain_datum_t *a_datum,              // Datum для добавления
    size_t a_datum_size                      // Размер datum
);

// Удаление datum по хешу
size_t dap_chain_block_datum_del_by_hash(
    dap_chain_block_t **a_block_ptr,         // Указатель на блок
    size_t a_block_size,                     // Размер блока
    dap_chain_hash_fast_t *a_datum_hash      // Хеш datum
);

// Получение списка datum'ов
dap_chain_datum_t **dap_chain_block_get_datums(
    const dap_chain_block_t *a_block,        // Блок
    size_t a_block_size,                     // Размер блока
    size_t *a_datums_count                   // Количество datum'ов (выходной)
);
```

### Работа с подписями

```c
// Добавление подписи в блок
size_t dap_chain_block_sign_add(
    dap_chain_block_t **a_block_ptr,         // Указатель на блок
    size_t a_block_size,                     // Размер блока
    dap_enc_key_t *a_key                    // Ключ для подписи
);

// Получение подписи по номеру
dap_sign_t *dap_chain_block_sign_get(
    const dap_chain_block_t *a_block,        // Блок
    size_t a_block_size,                     // Размер блока
    uint16_t a_sign_num                      // Номер подписи
);

// Проверка подписи по публичному ключу
bool dap_chain_block_sign_match_pkey(
    const dap_chain_block_t *a_block,        // Блок
    size_t a_block_size,                     // Размер блока
    dap_pkey_t *a_sign_pkey                  // Публичный ключ
);

// Получение количества подписей
size_t dap_chain_block_get_signs_count(
    const dap_chain_block_t *a_block,        // Блок
    size_t a_block_size                      // Размер блока
);
```

### Вспомогательные функции

```c
// Получение размера блока
size_t dap_chain_block_get_size(
    dap_chain_block_t *a_block               // Блок
);

// Получение хеша предыдущего блока
dap_hash_fast_t *dap_chain_block_get_prev_hash(
    const dap_chain_block_t *a_block,        // Блок
    size_t a_block_size                      // Размер блока
);

// Извлечение информации из метаданных
int dap_chain_block_meta_extract(
    dap_chain_block_t *a_block,              // Блок
    size_t a_block_size,                     // Размер блока
    dap_chain_hash_fast_t *a_prev_hash,      // Хеш предыдущего блока
    dap_chain_hash_fast_t *a_anchor_hash,    // Хеш якоря
    dap_chain_hash_fast_t *a_merkle,         // Merkle хеш
    dap_chain_hash_fast_t **a_links,         // Ссылки на блоки
    size_t *a_links_count,                   // Количество ссылок
    bool *a_is_genesis,                      // Флаг genesis блока
    uint64_t *a_nonce,                       // Nonce значение
    uint64_t *a_nonce2                       // Дополнительный nonce
);
```

## DAG Type

### Структура событий

```c
typedef struct dap_chain_cs_dag_event {
    dap_chain_hash_fast_t hash;              // Хеш события
    dap_chain_addr_t creator_addr;           // Адрес создателя
    uint64_t round_id;                       // ID раунда
    uint64_t ts_created;                     // Время создания
    uint64_t links_count;                    // Количество ссылок
    dap_chain_hash_fast_t *links;            // Ссылки на предыдущие события
    dap_chain_datum_t *datum;                // Данные события
    size_t datum_size;                       // Размер данных
} dap_chain_cs_dag_event_t;
```

### Особенности DAG консенсуса

1. **Параллельная обработка**: Множество событий могут создаваться одновременно
2. **Гибкие связи**: События могут ссылаться на несколько предыдущих
3. **Быстрое достижение консенсуса**: Высокая пропускная способность
4. **Отказоустойчивость**: Продолжение работы при отказе части узлов

## None Type

### Характеристики

1. **Отсутствие консенсуса**: Все транзакции принимаются без проверки
2. **Для тестирования**: Используется только в тестовых сетях
3. **Минимальная задержка**: Быстрое подтверждение транзакций
4. **Безопасность**: Отсутствует (только для разработки)

## Использование

### Работа с blocks типом

```c
#include "dap_chain_block.h"

// Инициализация блочного модуля
int init_result = dap_chain_block_init();
if (init_result != 0) {
    log_error("Failed to initialize block module");
    return -1;
}

// Создание нового блока
dap_chain_hash_fast_t prev_block_hash = get_last_block_hash();
size_t block_size = 0;

dap_chain_block_t *new_block = dap_chain_block_new(&prev_block_hash, &block_size);
if (!new_block) {
    log_error("Failed to create new block");
    return -1;
}

// Добавление метаданных о предыдущем блоке
size_t new_size = dap_chain_block_meta_add(&new_block, block_size,
                                         DAP_CHAIN_BLOCK_META_PREV,
                                         &prev_block_hash,
                                         sizeof(dap_chain_hash_fast_t));
block_size = new_size;

// Добавление nonce
uint64_t nonce = calculate_nonce(new_block, target_difficulty);
new_size = dap_chain_block_meta_add(&new_block, block_size,
                                   DAP_CHAIN_BLOCK_META_NONCE,
                                   &nonce, sizeof(uint64_t));
block_size = new_size;

// Добавление datum'ов
for (size_t i = 0; i < pending_datums_count; i++) {
    new_size = dap_chain_block_datum_add(&new_block, block_size,
                                       pending_datums[i],
                                       datum_sizes[i]);
    block_size = new_size;
}

// Подписание блока
new_size = dap_chain_block_sign_add(&new_block, block_size, signing_key);
block_size = new_size;

// Валидация блока
if (validate_block(new_block, block_size)) {
    // Блок готов к распространению
    broadcast_block(new_block, block_size);
} else {
    log_error("Block validation failed");
    free(new_block);
}
```

### Работа с подписями блоков

```c
// Проверка подписей блока
size_t signs_count = dap_chain_block_get_signs_count(block, block_size);
log_info("Block has %zu signatures", signs_count);

// Проверка каждой подписи
bool all_signs_valid = true;
for (size_t i = 0; i < signs_count; i++) {
    dap_sign_t *sign = dap_chain_block_sign_get(block, block_size, i);
    if (!sign) {
        log_error("Failed to get signature %zu", i);
        all_signs_valid = false;
        break;
    }

    // Получение публичного ключа валидатора
    dap_pkey_t *validator_pkey = get_validator_pkey(i);
    if (!validator_pkey) {
        log_error("Unknown validator %zu", i);
        all_signs_valid = false;
        break;
    }

    // Проверка подписи
    if (!dap_chain_block_sign_match_pkey(block, block_size, validator_pkey)) {
        log_error("Invalid signature from validator %zu", i);
        all_signs_valid = false;
        break;
    }
}

if (all_signs_valid) {
    log_info("All block signatures are valid");
    // Блок можно принимать
    accept_block(block, block_size);
} else {
    log_error("Block has invalid signatures");
    reject_block(block);
}
```

### Извлечение информации из блока

```c
// Извлечение метаданных из блока
dap_chain_hash_fast_t prev_hash, anchor_hash, merkle_hash;
dap_chain_hash_fast_t *block_links = NULL;
size_t links_count = 0;
bool is_genesis = false;
uint64_t nonce = 0, nonce2 = 0;

int extract_result = dap_chain_block_meta_extract(
    block, block_size,
    &prev_hash, &anchor_hash, &merkle_hash,
    &block_links, &links_count,
    &is_genesis, &nonce, &nonce2
);

if (extract_result == 0) {
    if (is_genesis) {
        log_info("This is a genesis block");
    } else {
        char prev_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&prev_hash, prev_hash_str, sizeof(prev_hash_str));
        log_info("Previous block hash: %s", prev_hash_str);
        log_info("Block nonce: %llu", nonce);
    }

    // Освобождение ресурсов
    if (block_links) {
        free(block_links);
    }
} else {
    log_error("Failed to extract block metadata: %d", extract_result);
}
```

### Работа с datum'ами блока

```c
// Получение всех datum'ов из блока
size_t datums_count = 0;
dap_chain_datum_t **datums = dap_chain_block_get_datums(block, block_size, &datums_count);

if (datums && datums_count > 0) {
    log_info("Block contains %zu datums", datums_count);

    for (size_t i = 0; i < datums_count; i++) {
        dap_chain_datum_t *datum = datums[i];

        // Обработка datum в зависимости от типа
        switch (datum->type) {
            case DATUM_TYPE_TX:
                process_transaction_datum(datum);
                break;
            case DATUM_TYPE_TOKEN_EMISSION:
                process_token_emission_datum(datum);
                break;
            case DATUM_TYPE_DECREE:
                process_decree_datum(datum);
                break;
            default:
                log_warning("Unknown datum type: %d", datum->type);
        }
    }

    // Освобождение массива указателей (не самих datum'ов)
    free(datums);
} else {
    log_warning("Block contains no datums");
}
```

## Производительность

### Характеристики производительности

#### Blocks Type:
- **Размер блока**: До 1MB
- **Время создания**: < 100 мс
- **Время валидации**: < 50 мс
- **Пропускная способность**: 10-100 tx/s

#### DAG Type:
- **Размер события**: До 10KB
- **Время создания**: < 10 мс
- **Время валидации**: < 5 мс
- **Пропускная способность**: 1000+ tx/s

#### None Type:
- **Размер блока**: Переменный
- **Время создания**: < 1 мс
- **Время валидации**: Минимальное
- **Пропускная способность**: Не ограничена

### Оптимизации

1. **Кеширование**: Кеширование часто используемых данных
2. **Индексирование**: Быстрый поиск по хешам и адресам
3. **Батчинг**: Группировка операций для оптимизации
4. **Предварительная валидация**: Проверка корректности до обработки

## Безопасность

### Механизмы защиты

1. **Криптографические подписи**: Все блоки и события подписаны
2. **Целостность данных**: Merkle деревья для проверки целостности
3. **Валидация**: Автоматическая проверка корректности данных
4. **Консенсус**: Защита от двойного расходования

### Защита от атак

- **Double spending**: Предотвращение через механизм консенсуса
- **51% attack**: Защита через распределение мощности
- **Nothing-at-stake**: Экономические стимулы для честного поведения
- **Eclipse attack**: Защита через множественные пути

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Управление цепочкой блоков/событий
- **Consensus**: Реализация алгоритмов консенсуса
- **Crypto**: Криптографическая защита данных
- **Net**: Распространение блоков и событий

### Примеры интеграции

```c
// Интеграция с consensus модулем
class ConsensusManager {
private:
    ConsensusType current_type;
    BlocksConsensus *blocks_consensus;
    DagConsensus *dag_consensus;
    NoneConsensus *none_consensus;

public:
    void set_consensus_type(ConsensusType type) {
        current_type = type;

        // Инициализация соответствующего типа
        switch (type) {
            case CONSENSUS_BLOCKS:
                dap_chain_cs_blocks_init();
                break;
            case CONSENSUS_DAG:
                dap_chain_cs_dag_init();
                break;
            case CONSENSUS_NONE:
                dap_chain_cs_none_init();
                break;
        }
    }

    bool validate_block(const Block &block) {
        switch (current_type) {
            case CONSENSUS_BLOCKS:
                return validate_blocks_consensus(block);
            case CONSENSUS_DAG:
                return validate_dag_consensus(block);
            case CONSENSUS_NONE:
                return true; // Всегда принимаем в тестовом режиме
            default:
                return false;
        }
    }

    Block *create_new_block() {
        switch (current_type) {
            case CONSENSUS_BLOCKS:
                return create_blocks_block();
            case CONSENSUS_DAG:
                return create_dag_event();
            case CONSENSUS_NONE:
                return create_none_block();
            default:
                return nullptr;
        }
    }
};

// Интеграция с сетевым модулем
class NetworkBlockManager {
private:
    NetworkManager *network;
    BlockStorage *storage;

public:
    void on_new_block_received(const BlockHeader &header, const uint8_t *data, size_t size) {
        // Создание блока из полученных данных
        dap_chain_block_t *received_block = (dap_chain_block_t *)malloc(size);
        memcpy(received_block, data, size);

        // Валидация блока
        if (validate_received_block(received_block, size)) {
            // Сохранение блока
            storage->store_block(received_block, size);

            // Распространение блока дальше
            network->broadcast_block(header, data, size);

            log_info("Block accepted and relayed: %s",
                    dap_chain_hash_fast_to_str_static(&header.hash));
        } else {
            log_warning("Block validation failed");
            free(received_block);
        }
    }

    bool validate_received_block(dap_chain_block_t *block, size_t size) {
        // Проверка подписи блока
        size_t signs_count = dap_chain_block_get_signs_count(block, size);
        if (signs_count == 0) {
            log_error("Block has no signatures");
            return false;
        }

        // Проверка хотя бы одной известной подписи
        bool has_valid_sign = false;
        for (size_t i = 0; i < signs_count; i++) {
            dap_pkey_t *validator_key = get_validator_key(i);
            if (validator_key &&
                dap_chain_block_sign_match_pkey(block, size, validator_key)) {
                has_valid_sign = true;
                break;
            }
        }

        if (!has_valid_sign) {
            log_error("Block has no valid signatures");
            return false;
        }

        // Проверка метаданных
        dap_chain_hash_fast_t prev_hash, anchor_hash, merkle_hash;
        bool is_genesis = false;
        uint64_t nonce = 0;

        if (dap_chain_block_meta_extract(block, size, &prev_hash, &anchor_hash,
                                       &merkle_hash, NULL, NULL, &is_genesis,
                                       &nonce, NULL) != 0) {
            log_error("Failed to extract block metadata");
            return false;
        }

        // Дополнительные проверки для конкретного типа консенсуса
        return validate_consensus_specific_checks(block, size, nonce);
    }
};
```

## Заключение

Type Module CellFrame SDK предоставляет гибкую и эффективную инфраструктуру для различных типов консенсуса в блокчейн сетях. Модуль поддерживает классический proof-of-work, DAG-based консенсус и специальный тестовый режим, обеспечивая оптимальную производительность для различных сценариев использования. Полная интеграция с остальными компонентами CellFrame гарантирует надежность, безопасность и масштабируемость блокчейн решений.
