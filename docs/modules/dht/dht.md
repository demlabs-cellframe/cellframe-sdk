# CellFrame SDK DHT Module

## Обзор

**DHT Module** (Distributed Hash Table) - это модуль распределенной хеш-таблицы CellFrame SDK, обеспечивающий децентрализованное хранение и поиск данных в P2P сети. Модуль реализует эффективные алгоритмы маршрутизации, репликации и поиска данных без центрального сервера, обеспечивая высокую отказоустойчивость и масштабируемость.

## Основные характеристики

- **Децентрализованное хранение**: Распределенное хранение данных по узлам сети
- **Эффективная маршрутизация**: Оптимизированные алгоритмы поиска данных
- **Репликация**: Автоматическое дублирование данных для отказоустойчивости
- **Самоорганизация**: Автоматическое поддержание структуры сети
- **Криптографическая защита**: Защита целостности и конфиденциальности данных

## Архитектура

### Основные структуры данных

#### Узел DHT

```c
typedef struct dap_chain_dht_node {
    dap_chain_node_addr_t addr;              // Адрес узла
    dap_chain_node_info_t info;              // Информация об узле
    uint64_t last_seen;                      // Время последнего контакта
    uint32_t distance;                       // Расстояние в DHT пространстве
    bool is_alive;                          // Статус доступности
    UT_hash_handle hh;                       // Хеш-таблица
} dap_chain_dht_node_t;
```

#### Запись DHT

```c
typedef struct dap_chain_dht_record {
    dap_hash_fast_t key;                     // Ключ записи
    void *value;                             // Значение
    size_t value_size;                       // Размер значения
    uint64_t ttl;                            // Время жизни
    uint64_t created_at;                     // Время создания
    dap_chain_addr_t publisher;              // Издатель записи
    uint8_t *signature;                      // Подпись
    uint32_t replication_factor;             // Коэффициент репликации
    UT_hash_handle hh;                       // Хеш-таблица
} dap_chain_dht_record_t;
```

#### Маршрутизационная таблица

```c
typedef struct dap_chain_dht_routing_table {
    uint8_t node_id[DAP_CHAIN_ID_SIZE];      // ID текущего узла
    dap_chain_dht_node_t *buckets[K_BUCKET_SIZE]; // K-бакеты
    size_t bucket_sizes[K_BUCKET_SIZE];      // Размеры бакетов
    dap_chain_dht_node_t *replacement_cache; // Кеш замен
    uint32_t maintenance_timer;              // Таймер обслуживания
} dap_chain_dht_routing_table_t;
```

#### Основная структура сервиса

```c
typedef struct dap_chain_dht {
    dap_chain_net_t *net;                    // Ссылка на сеть
    dap_chain_dht_routing_table_t routing_table; // Маршрутизационная таблица
    dap_hash_fast_t *local_records;          // Локальные записи
    uint64_t statistics;                     // Статистика
    bool is_bootstrap_node;                  // Является ли узел bootstrap
    dap_list_t *bootstrap_nodes;             // Список bootstrap узлов
    uint32_t replication_factor;             // Коэффициент репликации
} dap_chain_dht_t;
```

## Алгоритмы DHT

### Kademlia DHT

Модуль реализует протокол Kademlia:

#### Основные принципы:
- **XOR метрика**: Расстояние между узлами вычисляется как XOR ID
- **K-бакеты**: Разделение пространства ключей на бакеты
- **Итеративный поиск**: Поиск через последовательные запросы
- **Републикация**: Периодическое обновление записей

#### Вычисление расстояния:

```c
// Расстояние между двумя узлами в DHT
uint32_t dht_distance(const uint8_t *node1_id, const uint8_t *node2_id) {
    uint32_t distance = 0;
    for (int i = 0; i < DAP_CHAIN_ID_SIZE; i++) {
        distance |= (node1_id[i] ^ node2_id[i]) << (i * 8);
    }
    return distance;
}

// Нахождение бакета для узла
int find_bucket(const uint8_t *node_id, const uint8_t *target_id) {
    uint32_t distance = dht_distance(node_id, target_id);
    return 31 - __builtin_clz(distance); // Номер старшего бита
}
```

### Chord DHT

Альтернативная реализация протокола Chord:

#### Основные характеристики:
- **Кольцевая топология**: Узлы образуют кольцо
- **Finger table**: Таблица указателей на другие узлы
- **Logarithmic hops**: O(log N) hops для поиска
- **Динамическая стабилизация**: Адаптация к изменениям топологии

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация DHT сервиса
int dap_chain_dht_init(dap_config_t *config);

// Деинициализация DHT сервиса
void dap_chain_dht_deinit();

// Инициализация узла DHT
int dap_chain_dht_node_init(const uint8_t *node_id);

// Подключение к DHT сети
int dap_chain_dht_join_network(dap_list_t *bootstrap_nodes);
```

### Операции с данными

```c
// Сохранение данных в DHT
int dap_chain_dht_put(const uint8_t *key, const void *value,
                     size_t value_size, uint64_t ttl);

// Получение данных из DHT
int dap_chain_dht_get(const uint8_t *key, void **value,
                     size_t *value_size);

// Удаление данных из DHT
int dap_chain_dht_remove(const uint8_t *key);

// Поиск ближайших узлов
dap_list_t *dap_chain_dht_find_nodes(const uint8_t *target_id,
                                    size_t max_nodes);
```

### Маршрутизация

```c
// Поиск узла ответственного за ключ
dap_chain_dht_node_t *dap_chain_dht_find_responsible_node(
    const uint8_t *key);

// Отправка ping сообщения
int dap_chain_dht_ping_node(dap_chain_dht_node_t *node);

// Обновление маршрутизационной таблицы
int dap_chain_dht_update_routing_table(dap_chain_dht_node_t *node);
```

### Репликация и обслуживание

```c
// Републикация записей
int dap_chain_dht_republish_records();

// Очистка устаревших записей
int dap_chain_dht_cleanup_expired();

// Проверка здоровья узлов
int dap_chain_dht_health_check();

// Балансировка нагрузки
int dap_chain_dht_load_balance();
```

## Принцип работы

### 1. Структура DHT

#### K-бакеты:
```
Бакет 0: Узлы с расстоянием 2^0 - 2^1 (1-2)
Бакет 1: Узлы с расстоянием 2^1 - 2^2 (3-4)
Бакет 2: Узлы с расстоянием 2^2 - 2^3 (5-8)
...
Бакет k: Узлы с расстоянием 2^k - 2^(k+1)
```

#### Процесс поиска:
1. **Локальный поиск**: Проверка локальной маршрутизационной таблицы
2. **Итеративный запрос**: Отправка запросов ближайшим узлам
3. **Сбор результатов**: Агрегация ответов от нескольких узлов
4. **Обновление таблицы**: Обновление маршрутизационной информации

### 2. Репликация данных

#### Стратегии репликации:
- **K ближайших узлов**: Хранение на K ближайших узлах
- **Географическая репликация**: Распределение по географическим регионам
- **Временная репликация**: Репликация на основе времени жизни

#### Алгоритм репликации:

```c
void replicate_data(const uint8_t *key, const void *value, size_t value_size) {
    // Нахождение K ближайших узлов
    dap_list_t *nearest_nodes = dap_chain_dht_find_nodes(key, K_REPLICATION);

    // Репликация на каждый узел
    dap_list_t *current = nearest_nodes;
    while (current) {
        dap_chain_dht_node_t *node = (dap_chain_dht_node_t *)current->data;

        // Отправка данных для репликации
        dht_send_replicate(node, key, value, value_size);

        current = current->next;
    }

    dap_list_free(nearest_nodes);
}
```

### 3. Обслуживание сети

#### Регулярные задачи:
- **Обновление маршрутов**: Проверка доступности узлов
- **Републикация данных**: Обновление TTL записей
- **Очистка**: Удаление устаревших данных
- **Балансировка**: Распределение нагрузки

## Безопасность

### Механизмы защиты

1. **Цифровые подписи**: Подтверждение авторства данных
2. **TTL механизм**: Ограничение времени жизни записей
3. **Rate limiting**: Защита от DoS атак
4. **Валидация данных**: Проверка целостности хранимых данных

### Защита от атак

- **Eclipse атаки**: Защита через множественные пути
- **Sybil атаки**: Экономические барьеры для создания узлов
- **Data poisoning**: Валидация и репликация данных
- **Route poisoning**: Проверка маршрутизационной информации

## Использование

### Базовая инициализация

```c
#include "dap_chain_dht.h"

// Инициализация DHT
int result = dap_chain_dht_init(config);
if (result != 0) {
    log_error("Failed to initialize DHT: %d", result);
    return -1;
}

// Создание ID узла
uint8_t node_id[DAP_CHAIN_ID_SIZE];
generate_node_id(node_id);

// Инициализация узла
result = dap_chain_dht_node_init(node_id);
if (result != 0) {
    log_error("Failed to initialize DHT node: %d", result);
    return -1;
}

// Подключение к сети
dap_list_t *bootstrap_nodes = load_bootstrap_nodes();
result = dap_chain_dht_join_network(bootstrap_nodes);
if (result != 0) {
    log_error("Failed to join DHT network: %d", result);
    return -1;
}
```

### Работа с данными

```c
// Сохранение данных
const char *key_data = "user_profile_123";
const char *value_data = "{\"name\":\"John\",\"age\":30}";
uint64_t ttl = 3600 * 24; // 24 часа

uint8_t key[DAP_CHAIN_ID_SIZE];
dht_hash_key(key_data, strlen(key_data), key);

int put_result = dap_chain_dht_put(key, value_data,
                                  strlen(value_data) + 1, ttl);
if (put_result == 0) {
    log_info("Data stored successfully in DHT");
} else {
    log_error("Failed to store data: %d", put_result);
}

// Получение данных
void *retrieved_value = NULL;
size_t value_size = 0;

int get_result = dap_chain_dht_get(key, &retrieved_value, &value_size);
if (get_result == 0 && retrieved_value) {
    log_info("Retrieved data: %s", (char *)retrieved_value);
    free(retrieved_value);
} else {
    log_error("Failed to retrieve data: %d", get_result);
}

// Удаление данных
int remove_result = dap_chain_dht_remove(key);
if (remove_result == 0) {
    log_info("Data removed successfully");
} else {
    log_error("Failed to remove data: %d", remove_result);
}
```

### Поиск узлов

```c
// Поиск узлов ответственных за ключ
uint8_t search_key[DAP_CHAIN_ID_SIZE];
dht_hash_key("search_target", 13, search_key);

dap_list_t *responsible_nodes = dap_chain_dht_find_nodes(search_key, 5);

if (responsible_nodes) {
    log_info("Found %d responsible nodes:", dap_list_length(responsible_nodes));

    dap_list_t *current = responsible_nodes;
    while (current) {
        dap_chain_dht_node_t *node = (dap_chain_dht_node_t *)current->data;

        char addr_str[64];
        dap_chain_node_addr_to_str(node->addr, addr_str, sizeof(addr_str));
        log_info("Node: %s, Distance: %u", addr_str, node->distance);

        current = current->next;
    }

    dap_list_free(responsible_nodes);
}
```

### Управление записями

```c
// Публикация записи с подписью
int publish_signed_record(const char *key_str, const char *value,
                         dap_chain_wallet_t *wallet) {
    uint8_t key[DAP_CHAIN_ID_SIZE];
    dht_hash_key(key_str, strlen(key_str), key);

    // Создание записи
    dap_chain_dht_record_t record = {
        .key = {0},
        .value = (void *)value,
        .value_size = strlen(value) + 1,
        .ttl = 3600 * 24, // 24 часа
        .publisher = wallet->addr,
        .replication_factor = 3
    };
    memcpy(record.key, key, sizeof(record.key));

    // Подписание записи
    record.signature = dap_chain_wallet_sign(wallet, &record,
                                            sizeof(dap_chain_dht_record_t));

    // Публикация в DHT
    return dap_chain_dht_publish_record(&record);
}

// Поиск и валидация записей
dap_list_t *find_valid_records(const char *key_str) {
    uint8_t key[DAP_CHAIN_ID_SIZE];
    dht_hash_key(key_str, strlen(key_str), key);

    // Получение всех копий записи
    dap_list_t *records = dap_chain_dht_get_all_replicas(key);

    // Валидация и фильтрация
    dap_list_t *current = records;
    while (current) {
        dap_chain_dht_record_t *record = (dap_chain_dht_record_t *)current->data;

        if (!validate_record_signature(record)) {
            // Удаление недействительной записи
            dap_list_remove_link(records, current);
        }

        current = current->next;
    }

    return records;
}
```

## Производительность

### Характеристики производительности

- **Время поиска**: O(log N) hops, где N - количество узлов
- **Хранение на узел**: O(log N) записей
- **Сетевая нагрузка**: O(log N) сообщений на операцию
- **Отказоустойчивость**: K реплик на запись

### Метрики оптимизации

```c
// Статистика DHT
typedef struct dht_stats {
    uint64_t total_nodes;                // Общее количество узлов
    uint64_t total_records;              // Общее количество записей
    uint64_t total_lookups;              // Общее количество поисков
    uint64_t successful_lookups;         // Успешные поиски
    double avg_lookup_hops;              // Среднее количество hops
    double avg_lookup_time;              // Среднее время поиска
    uint64_t network_messages;           // Количество сетевых сообщений
} dht_stats_t;

// Мониторинг производительности
void monitor_dht_performance() {
    dht_stats_t stats = dap_chain_dht_get_stats();

    double success_rate = (double)stats.successful_lookups / stats.total_lookups;
    double efficiency = stats.total_records / stats.total_nodes;

    log_info("DHT Performance:");
    log_info("Success rate: %.2f%%", success_rate * 100);
    log_info("Efficiency: %.2f records/node", efficiency);
    log_info("Avg lookup time: %.2f ms", stats.avg_lookup_time);
    log_info("Avg lookup hops: %.2f", stats.avg_lookup_hops);
    log_info("Network messages: %llu", stats.network_messages);
}
```

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Хранение DHT записей в блокчейне для персистентности
- **Net**: Сетевая коммуникация между DHT узлами
- **Crypto**: Криптографическая защита данных и маршрутизации
- **Consensus**: Валидация DHT операций через консенсус

### Примеры интеграции

```c
// Интеграция с блокчейн хранилищем
class DHTBlockchainStorage {
private:
    DHTClient *dht;
    BlockchainClient *blockchain;

public:
    void store_permanently(const std::string &key, const std::string &value) {
        // Сохранение в DHT с коротким TTL
        dht->put(key, value, 3600); // 1 час в DHT

        // Сохранение в блокчейн для персистентности
        blockchain->store_data(key, value);

        // Создание ссылки в DHT на блокчейн запись
        std::string blockchain_ref = blockchain->get_reference(key);
        dht->put(key + "_blockchain_ref", blockchain_ref, 24 * 3600); // 24 часа
    }

    std::string retrieve_data(const std::string &key) {
        // Сначала пытаемся найти в DHT
        try {
            return dht->get(key);
        } catch (DHTNotFoundException &e) {
            // Если не найдено в DHT, ищем в блокчейне
            std::string blockchain_ref = dht->get(key + "_blockchain_ref");
            return blockchain->retrieve_data(blockchain_ref);
        }
    }
};

// Интеграция с P2P сетью
class DHTNetworkManager {
private:
    DHTNode *dht_node;
    P2PNetwork *network;

public:
    void join_dht_network() {
        // Получение списка bootstrap узлов из P2P сети
        std::vector<NodeAddress> bootstrap_nodes = network->get_bootstrap_nodes();

        // Преобразование в формат DHT
        std::vector<dht_addr_t> dht_bootstrap;
        for (const auto &node : bootstrap_nodes) {
            dht_bootstrap.push_back(convert_to_dht_addr(node));
        }

        // Подключение к DHT сети
        dht_node->join_network(dht_bootstrap);
    }

    void handle_network_message(const NetworkMessage &msg) {
        if (msg.type == DHT_PING) {
            handle_dht_ping(msg);
        } else if (msg.type == DHT_FIND_NODE) {
            handle_dht_find_node(msg);
        } else if (msg.type == DHT_FIND_VALUE) {
            handle_dht_find_value(msg);
        }
    }

    void broadcast_dht_presence() {
        // Периодическая отправка ping сообщений
        auto neighbors = dht_node->get_neighbors();
        for (const auto &neighbor : neighbors) {
            network->send_ping(neighbor.network_addr);
        }
    }
};
```

## Заключение

DHT Module CellFrame SDK предоставляет мощную и масштабируемую инфраструктуру для децентрализованного хранения и поиска данных. Модуль реализует современные алгоритмы распределенных хеш-таблиц, обеспечивая высокую производительность, отказоустойчивость и безопасность. Полная интеграция с остальными компонентами CellFrame позволяет создавать распределенные приложения с эффективным управлением данными в P2P сетях.
