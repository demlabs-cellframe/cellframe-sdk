# CellFrame Net Module (dap_chain_net.h)

## Обзор

Модуль `dap_chain_net` является центральным компонентом сетевой архитектуры CellFrame SDK. Он обеспечивает:

- **Управление сетевыми состояниями** - контроль жизненного цикла сетей
- **Кластеризация узлов** - организация и управление кластерами
- **Синхронизация данных** - координация между узлами сети
- **Управление узлами** - регистрация и мониторинг участников
- **RPC интерфейсы** - удаленное управление сетью

## Архитектурная роль

Net модуль является координационным центром всей сетевой инфраструктуры:

```
┌─────────────────┐    ┌─────────────────┐
│   CellFrame     │───▶│   Net Module    │
│   SDK           │    └─────────────────┘
         │                       │
    ┌────▼────┐             ┌────▼────┐
    │Chains     │             │Nodes       │
    │Управление │             │Управление  │
    └─────────┘             └─────────┘
         │                       │
    ┌────▼────┐             ┌────▼────┐
    │Ledger     │◄────────────►│Clusters    │
    │Бухгалтерия│             │Кластеризация│
    └─────────┘             └─────────┘
```

## Основные структуры данных

### `dap_chain_net_t`
```c
typedef struct dap_chain_net {
    char name[DAP_CHAIN_NET_NAME_MAX];    // Имя сети
    dap_chain_net_id_t id;                // Уникальный ID сети
    dap_chain_net_state_t state;          // Текущее состояние

    // Компоненты сети
    dap_chain_t *chains;                  // Цепочки блоков
    size_t chains_count;                  // Количество цепочек

    // Узлы и кластеризация
    dap_list_t *nodes;                    // Список узлов
    dap_global_db_cluster_t *cluster;     // Кластер базы данных

    // Леджер и состояние
    dap_ledger_t *ledger;                 // Бухгалтерская книга
    uint64_t cur_ts;                      // Текущее время

    // Настройки
    bool is_active;                       // Активность сети
    uint32_t mempool_ttl;                 // TTL для mempool
    uint32_t nodes_ttl;                   // TTL для узлов
} dap_chain_net_t;
```

### `dap_chain_node_info_t`
```c
typedef struct dap_chain_node_info {
    dap_chain_node_addr_t address;        // Адрес узла
    char *alias;                          // Псевдоним узла
    uint32_t cell_id;                     // ID ячейки
    dap_chain_node_role_t role;           // Роль узла

    // Статус и метрики
    bool is_online;                       // Онлайн статус
    uint64_t last_seen;                   // Последнее появление
    uint32_t blocks_count;                // Количество блоков

    // Связи
    dap_list_t *links;                    // Связи с другими узлами
    void *_internal;                      // Внутренние данные
} dap_chain_node_info_t;
```

## Состояния сети

### `dap_chain_net_state_t`
```c
typedef enum dap_chain_net_state {
    NET_STATE_LOADING = 0,        // Загрузка сети
    NET_STATE_OFFLINE,            // Оффлайн
    NET_STATE_LINKS_ESTABLISHING, // Установление связей
    NET_STATE_LINKS_ESTABLISHED,  // Связи установлены
    NET_STATE_SYNC_CHAINS,        // Синхронизация цепочек
    NET_STATE_SYNC_GDB,           // Синхронизация глобальной БД
    NET_STATE_ONLINE              // Полностью онлайн
} dap_chain_net_state_t;
```

## Основные функции

### Инициализация и управление сетью

#### `dap_chain_net_init()`
```c
int dap_chain_net_init();
```

Инициализирует систему сетей CellFrame.

**Возвращаемые значения:**
- `0` - успешная инициализация
- `-1` - ошибка инициализации

#### `dap_chain_net_deinit()`
```c
void dap_chain_net_deinit();
```

Деинициализирует систему сетей.

### Создание и управление сетями

#### `dap_chain_net_create()`
```c
dap_chain_net_t *dap_chain_net_create(const char *a_name,
                                     dap_chain_net_id_t a_id);
```

Создает новую сеть.

**Параметры:**
- `a_name` - имя сети
- `a_id` - уникальный ID сети

**Возвращаемое значение:**
- Указатель на созданную сеть или NULL при ошибке

#### `dap_chain_net_start()`
```c
int dap_chain_net_start(dap_chain_net_t *a_net);
```

Запускает сеть.

**Параметры:**
- `a_net` - сеть для запуска

**Возвращаемые значения:**
- `0` - успешный запуск
- `-1` - ошибка запуска

#### `dap_chain_net_stop()`
```c
void dap_chain_net_stop(dap_chain_net_t *a_net);
```

Останавливает сеть.

**Параметры:**
- `a_net` - сеть для остановки

### Управление цепочками

#### `dap_chain_net_add_chain()`
```c
int dap_chain_net_add_chain(dap_chain_net_t *a_net,
                           dap_chain_t *a_chain);
```

Добавляет цепочку в сеть.

**Параметры:**
- `a_net` - сеть
- `a_chain` - цепочка для добавления

**Возвращаемые значения:**
- `0` - успешное добавление
- `-1` - ошибка добавления

#### `dap_chain_net_get_chain_by_id()`
```c
dap_chain_t *dap_chain_net_get_chain_by_id(dap_chain_net_t *a_net,
                                          dap_chain_id_t a_chain_id);
```

Получает цепочку по ID.

**Параметры:**
- `a_net` - сеть
- `a_chain_id` - ID цепочки

**Возвращаемое значение:**
- Указатель на найденную цепочку или NULL

### Управление узлами

#### `dap_chain_net_add_node()`
```c
int dap_chain_net_add_node(dap_chain_net_t *a_net,
                          dap_chain_node_info_t *a_node_info);
```

Добавляет узел в сеть.

**Параметры:**
- `a_net` - сеть
- `a_node_info` - информация об узле

**Возвращаемые значения:**
- `0` - успешное добавление
- `-1` - ошибка добавления

#### `dap_chain_net_remove_node()`
```c
int dap_chain_net_remove_node(dap_chain_net_t *a_net,
                             dap_chain_node_addr_t a_node_addr);
```

Удаляет узел из сети.

**Параметры:**
- `a_net` - сеть
- `a_node_addr` - адрес узла

**Возвращаемые значения:**
- `0` - успешное удаление
- `-1` - ошибка удаления

### Синхронизация и состояние

#### `dap_chain_net_sync()`
```c
int dap_chain_net_sync(dap_chain_net_t *a_net);
```

Запускает синхронизацию сети.

**Параметры:**
- `a_net` - сеть для синхронизации

**Возвращаемые значения:**
- `0` - синхронизация запущена
- `-1` - ошибка запуска синхронизации

#### `dap_chain_net_get_state()`
```c
dap_chain_net_state_t dap_chain_net_get_state(dap_chain_net_t *a_net);
```

Получает текущее состояние сети.

**Параметры:**
- `a_net` - сеть

**Возвращаемое значение:**
- Текущее состояние сети

### Работа с ledger

#### `dap_chain_net_get_ledger()`
```c
dap_ledger_t *dap_chain_net_get_ledger(dap_chain_net_t *a_net);
```

Получает ledger сети.

**Параметры:**
- `a_net` - сеть

**Возвращаемое значение:**
- Указатель на ledger или NULL

#### `dap_chain_net_ledger_tx_add()`
```c
int dap_chain_net_ledger_tx_add(dap_chain_net_t *a_net,
                               dap_chain_datum_t *a_datum);
```

Добавляет транзакцию в ledger.

**Параметры:**
- `a_net` - сеть
- `a_datum` - datum транзакции

**Возвращаемые значения:**
- `0` - успешное добавление
- `-1` - ошибка добавления

## Константы и лимиты

```c
#define DAP_CHAIN_NET_NAME_MAX 32             // Максимальная длина имени сети
#define DAP_CHAIN_NET_MEMPOOL_TTL 4 * 3600    // TTL для mempool (4 часа)
#define DAP_CHAIN_NET_NODES_TTL 14 * 24 * 3600 // TTL для узлов (2 недели)
```

## Работа с кластерами

### Создание кластера

```c
dap_global_db_cluster_t *cluster = dap_global_db_cluster_create("main_cluster");
if (!cluster) {
    fprintf(stderr, "Failed to create cluster\n");
    return -1;
}

// Добавление в сеть
a_net->cluster = cluster;
```

### Управление узлами кластера

```c
// Добавление узла в кластер
dap_chain_node_addr_t node_addr = {.addr = inet_addr("192.168.1.10"), .port = 8080};
dap_global_db_cluster_add_member(cluster, node_addr);

// Получение списка узлов
dap_list_t *cluster_nodes = dap_global_db_cluster_get_members(cluster);
```

## RPC интерфейсы

### Инициализация RPC

```c
int dap_chain_net_rpc_init(void);
```

Инициализирует RPC интерфейс для сетей.

### RPC обработчики

#### Получение информации о сети
```c
// RPC: network.info
void rpc_network_info(dap_json_rpc_params_t *params,
                     dap_json_rpc_response_t *response);
```

#### Управление сетью
```c
// RPC: network.start
void rpc_network_start(dap_json_rpc_params_t *params,
                      dap_json_rpc_response_t *response);

// RPC: network.stop
void rpc_network_stop(dap_json_rpc_params_t *params,
                     dap_json_rpc_response_t *response);
```

#### Работа с узлами
```c
// RPC: network.nodes.list
void rpc_network_nodes_list(dap_json_rpc_params_t *params,
                           dap_json_rpc_response_t *response);

// RPC: network.nodes.add
void rpc_network_nodes_add(dap_json_rpc_params_t *params,
                          dap_json_rpc_response_t *response);
```

## Мониторинг и статистика

### Получение статистики сети

```c
typedef struct dap_chain_net_stats {
    uint32_t active_nodes;         // Активных узлов
    uint32_t total_chains;         // Всего цепочек
    uint64_t total_transactions;   // Всего транзакций
    uint64_t mempool_size;         // Размер mempool
    double sync_progress;          // Прогресс синхронизации
    uint64_t last_block_time;      // Время последнего блока
} dap_chain_net_stats_t;

dap_chain_net_stats_t dap_chain_net_get_stats(dap_chain_net_t *a_net);
```

### Мониторинг состояния

```c
// Проверка здоровья сети
bool dap_chain_net_is_healthy(dap_chain_net_t *a_net);

// Получение метрик производительности
double dap_chain_net_get_tps(dap_chain_net_t *a_net);  // Transactions per second
uint64_t dap_chain_net_get_latency(dap_chain_net_t *a_net); // Средняя задержка
```

## Использование

### Создание и запуск сети

```c
#include "dap_chain_net.h"

// Инициализация системы сетей
if (dap_chain_net_init() != 0) {
    fprintf(stderr, "Failed to initialize network system\n");
    return -1;
}

// Создание сети
dap_chain_net_id_t net_id = {.uint64 = 0x1807202300000000}; // KelVPN
dap_chain_net_t *network = dap_chain_net_create("KelVPN", net_id);

if (!network) {
    fprintf(stderr, "Failed to create network\n");
    return -1;
}

// Запуск сети
if (dap_chain_net_start(network) != 0) {
    fprintf(stderr, "Failed to start network\n");
    return -1;
}

printf("Network %s started successfully\n", network->name);
```

### Работа с цепочками

```c
// Создание цепочки
dap_chain_id_t chain_id = {.uint64 = 0x0404202200000000}; // Backbone
dap_chain_t *chain = dap_chain_create("Backbone", chain_id, network);

if (!chain) {
    fprintf(stderr, "Failed to create chain\n");
    return -1;
}

// Добавление цепочки в сеть
if (dap_chain_net_add_chain(network, chain) != 0) {
    fprintf(stderr, "Failed to add chain to network\n");
    return -1;
}

// Поиск цепочки
dap_chain_t *found_chain = dap_chain_net_get_chain_by_id(network, chain_id);
if (found_chain) {
    printf("Chain found: %s\n", found_chain->name);
}
```

### Управление узлами

```c
// Создание информации об узле
dap_chain_node_info_t node_info = {
    .address = {.addr = inet_addr("192.168.1.100"), .port = 8081},
    .alias = "node-01",
    .cell_id = 1,
    .role = NODE_ROLE_MASTER,
    .is_online = true,
    .last_seen = time(NULL)
};

// Добавление узла в сеть
if (dap_chain_net_add_node(network, &node_info) != 0) {
    fprintf(stderr, "Failed to add node to network\n");
    return -1;
}

// Получение списка узлов
dap_list_t *nodes = dap_chain_net_get_nodes(network);
printf("Network has %u nodes\n", dap_list_length(nodes));
```

### Синхронизация и состояние

```c
// Запуск синхронизации
if (dap_chain_net_sync(network) != 0) {
    fprintf(stderr, "Failed to start network synchronization\n");
    return -1;
}

// Мониторинг состояния
while (true) {
    dap_chain_net_state_t state = dap_chain_net_get_state(network);

    switch (state) {
        case NET_STATE_LOADING:
            printf("Network is loading...\n");
            break;
        case NET_STATE_ONLINE:
            printf("Network is online\n");
            goto sync_complete;
        case NET_STATE_OFFLINE:
            printf("Network is offline\n");
            break;
        // ... другие состояния
    }

    sleep(1);
}

sync_complete:
// Сеть полностью синхронизирована и готова к работе
```

### Работа с ledger

```c
// Получение ledger сети
dap_ledger_t *ledger = dap_chain_net_get_ledger(network);
if (!ledger) {
    fprintf(stderr, "Network ledger not available\n");
    return -1;
}

// Добавление транзакции в ledger
if (dap_chain_net_ledger_tx_add(network, transaction_datum) != 0) {
    fprintf(stderr, "Failed to add transaction to ledger\n");
    return -1;
}

// Получение баланса
uint256_t balance = dap_ledger_get_balance(ledger, &account_addr, "KEL");
printf("Account balance: %s KEL\n", uint256_to_str(balance));
```

## Производительность и оптимизации

### Масштабирование
- **Горизонтальное масштабирование** - распределение по множеству узлов
- **Вертикальное масштабирование** - увеличение ресурсов узла
- **Автоматическая балансировка** - распределение нагрузки

### Оптимизации
- **Кэширование состояния** - in-memory кэш для частых запросов
- **Компрессия данных** - сжатие при передаче между узлами
- **Асинхронные операции** - неблокирующие сетевые вызовы
- **Connection pooling** - переиспользование соединений

## Безопасность

### Аутентификация узлов
```c
// Проверка подписи узла
bool dap_chain_net_verify_node_signature(dap_chain_net_t *a_net,
                                        dap_chain_node_addr_t a_node_addr,
                                        dap_sign_t *a_sign);

// Валидация сертификатов
bool dap_chain_net_validate_node_certificate(dap_chain_net_t *a_net,
                                           dap_cert_t *a_cert);
```

### Шифрование коммуникаций
```c
// Установка шифрования для сети
dap_chain_net_set_encryption(network, DAP_CHAIN_NET_ENCRYPTION_TLS);

// Генерация ключей для узла
dap_enc_key_t *node_key = dap_chain_net_generate_node_key(network, node_addr);
```

## Интеграция с другими модулями

### DAP Chain
- Управление цепочками блоков
- Синхронизация состояния
- Валидация транзакций

### DAP Ledger
- Учет транзакций и балансов
- Верификация платежей
- Аудит операций

### DAP Global DB
- Распределенное хранение данных
- Синхронизация состояния
- Репликация между узлами

### DAP Node
- Регистрация и мониторинг узлов
- Управление ролями и правами
- Статистика производительности

## Типичные сценарии использования

### 1. Создание частной сети

```c
// Создание конфигурации сети
dap_chain_net_config_t config = {
    .name = "PrivateNet",
    .type = NET_TYPE_PRIVATE,
    .consensus = CONSENSUS_DAG_POA,
    .encryption = true,
    .max_nodes = 100
};

// Создание и запуск сети
dap_chain_net_t *private_net = dap_chain_net_create_from_config(&config);
dap_chain_net_start(private_net);
```

### 2. Присоединение к существующей сети

```c
// Конфигурация для присоединения
dap_chain_net_join_config_t join_config = {
    .network_name = "KelVPN",
    .bootstrap_nodes = {"node1.cellframe.net:8081", "node2.cellframe.net:8081"},
    .node_role = NODE_ROLE_SLAVE,
    .sync_from_genesis = false
};

// Присоединение к сети
dap_chain_net_join(&join_config);
```

### 3. Мониторинг состояния сети

```c
// Получение полной статистики
dap_chain_net_stats_t stats = dap_chain_net_get_stats(network);

printf("Network Status:\n");
printf("- Active nodes: %u\n", stats.active_nodes);
printf("- Total chains: %u\n", stats.total_chains);
printf("- Mempool size: %llu\n", stats.mempool_size);
printf("- Sync progress: %.2f%%\n", stats.sync_progress * 100);

// Проверка здоровья компонентов
bool ledger_ok = dap_chain_net_check_ledger(network);
bool chains_ok = dap_chain_net_check_chains(network);
bool nodes_ok = dap_chain_net_check_nodes(network);

if (!ledger_ok || !chains_ok || !nodes_ok) {
    fprintf(stderr, "Network health check failed\n");
    // Запуск восстановления
    dap_chain_net_start_recovery(network);
}
```

## Заключение

Модуль `dap_chain_net` предоставляет полную инфраструктуру для создания и управления децентрализованными сетями в экосистеме CellFrame. Его архитектура обеспечивает высокую масштабируемость, надежность и безопасность для сложных распределенных приложений.

