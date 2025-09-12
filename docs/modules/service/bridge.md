# CellFrame SDK Bridge Service Module

## Обзор

**Bridge Service** - это сервис межсетевых мостов в CellFrame SDK, обеспечивающий безопасный и надежный перенос активов между различными блокчейн сетями. Сервис поддерживает различные типы мостов, включая custodial и non-custodial решения, с поддержкой мульти-сигнатур и атомарных свопов.

## Основные характеристики

- **Межсетевые мосты**: Перенос активов между сетями
- **Множественные типы**: Custodial и non-custodial мосты
- **Мульти-сигнатуры**: Защита через мульти-подписи
- **Атомарные свопы**: Гарантированные обмены
- **Мониторинг**: Отслеживание состояния мостов

## Архитектура

### Основные структуры данных

#### Конфигурация моста

```c
typedef struct dap_chain_net_srv_bridge_config {
    char name[DAP_CHAIN_BRIDGE_NAME_SIZE];         // Имя моста
    dap_chain_net_id_t source_net;                 // Исходная сеть
    dap_chain_net_id_t target_net;                 // Целевая сеть
    uint256_t min_amount;                          // Минимальная сумма
    uint256_t max_amount;                          // Максимальная сумма
    uint256_t fee_fixed;                           // Фиксированная комиссия
    uint256_t fee_percent;                         // Процентная комиссия
    uint16_t confirmations_required;               // Требуемые подтверждения
    uint16_t multisig_threshold;                   // Порог мульти-сигнатуры
    bool enabled;                                  // Включен ли мост
} dap_chain_net_srv_bridge_config_t;
```

#### Запрос на мост

```c
typedef struct dap_chain_net_srv_bridge_request {
    dap_chain_hash_fast_t request_hash;            // Хеш запроса
    dap_chain_addr_t sender_addr;                  // Адрес отправителя
    dap_chain_addr_t receiver_addr;                // Адрес получателя
    uint256_t amount;                              // Сумма перевода
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];  // Тикер токена
    dap_chain_net_id_t source_net;                 // Исходная сеть
    dap_chain_net_id_t target_net;                 // Целевая сеть
    dap_time_t created_at;                         // Время создания
    uint8_t status;                                // Статус запроса
    uint16_t confirmations;                        // Количество подтверждений
} dap_chain_net_srv_bridge_request_t;
```

#### Состояние моста

```c
typedef struct dap_chain_net_srv_bridge {
    dap_chain_net_srv_t *parent;                   // Родительский сервис
    dap_chain_net_srv_bridge_config_t config;      // Конфигурация
    dap_list_t *active_requests;                   // Активные запросы
    dap_list_t *validators;                        // Список валидаторов
    bool emergency_stop;                           // Аварийная остановка
    uint64_t total_transferred;                    // Общий объем переводов
} dap_chain_net_srv_bridge_t;
```

## Типы мостов

### По архитектуре

1. **Custodial Bridge**: С использованием custodians для хранения активов
2. **Non-custodial Bridge**: Без хранения активов третьей стороной
3. **Hybrid Bridge**: Комбинация различных подходов

### По механизму

1. **Lock-Mint**: Блокировка на исходной сети, выпуск на целевой
2. **Burn-Mint**: Сжигание на исходной сети, выпуск на целевой
3. **Atomic Swap**: Атомарный обмен между сетями

### По управлению

1. **Centralized**: Управление центральным органом
2. **Decentralized**: Децентрализованное управление
3. **DAO-governed**: Управление через DAO

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация bridge сервиса
int dap_chain_net_srv_bridge_init();

// Деинициализация bridge сервиса
void dap_chain_net_srv_bridge_deinit();
```

### Управление мостами

```c
// Создание нового моста
int dap_chain_net_srv_bridge_create(
    const char *bridge_name,                       // Имя моста
    dap_chain_net_id_t source_net,                 // Исходная сеть
    dap_chain_net_id_t target_net,                 // Целевая сеть
    uint16_t multisig_threshold                    // Порог мульти-сигнатуры
);

// Включение/выключение моста
int dap_chain_net_srv_bridge_enable(
    const char *bridge_name,                       // Имя моста
    bool enable                                    // Включить/выключить
);

// Аварийная остановка моста
int dap_chain_net_srv_bridge_emergency_stop(
    const char *bridge_name                        // Имя моста
);
```

### Операции с активами

```c
// Запрос на перенос активов
int dap_chain_net_srv_bridge_request_transfer(
    const char *bridge_name,                       // Имя моста
    dap_chain_wallet_t *wallet,                    // Кошелек отправителя
    uint256_t amount,                              // Сумма
    const char *token_ticker,                      // Тикер токена
    dap_chain_addr_t receiver_addr,                // Адрес получателя
    char **request_hash                            // Хеш запроса
);

// Подтверждение запроса валидатором
int dap_chain_net_srv_bridge_confirm_request(
    const char *bridge_name,                       // Имя моста
    const char *request_hash,                      // Хеш запроса
    dap_chain_wallet_t *validator_wallet           // Кошелек валидатора
);

// Исполнение запроса
int dap_chain_net_srv_bridge_execute_request(
    const char *bridge_name,                       // Имя моста
    const char *request_hash                       // Хеш запроса
);
```

### Получение информации

```c
// Получение списка активных мостов
dap_list_t *dap_chain_net_srv_bridge_get_list();

// Получение конфигурации моста
dap_chain_net_srv_bridge_config_t *dap_chain_net_srv_bridge_get_config(
    const char *bridge_name                        // Имя моста
);

// Получение активных запросов моста
dap_list_t *dap_chain_net_srv_bridge_get_requests(
    const char *bridge_name                        // Имя моста
);

// Получение статистики моста
dap_chain_net_srv_bridge_stats_t *dap_chain_net_srv_bridge_get_stats(
    const char *bridge_name                        // Имя моста
);
```

## Безопасность

### Механизмы защиты

1. **Мульти-сигнатуры**: Требование нескольких подписей для операций
2. **Временные блокировки**: Защита от быстрого вывода средств
3. **Мониторинг**: Отслеживание подозрительной активности
4. **Аудит**: Полная traceability всех операций

### Защита от рисков

- **Bridge exploits**: Защита от уязвимостей в коде моста
- **Validator compromise**: Защита при компрометации валидаторов
- **Network attacks**: Защита от атак на сеть
- **Smart contract bugs**: Аудит смарт-контрактов

## Использование

### Создание моста

```c
#include "dap_chain_net_srv_bridge.h"

// Создание моста между сетями
int result = dap_chain_net_srv_bridge_create(
    "CELL_ETH_Bridge",                     // Имя моста
    CELLFRAME_NET_ID,                      // Исходная сеть
    ETHEREUM_NET_ID,                       // Целевая сеть
    3                                      // Требуется 3 из 5 подписей
);

if (result == 0) {
    log_info("Bridge created successfully");
} else {
    log_error("Failed to create bridge: %d", result);
}
```

### Запрос на перенос активов

```c
// Параметры переноса
uint256_t transfer_amount = dap_chain_coins_to_balance("10.0");
const char *token_ticker = "CELL";
dap_chain_addr_t receiver_addr = get_receiver_address();

// Создание запроса на перенос
char *request_hash = NULL;
int transfer_result = dap_chain_net_srv_bridge_request_transfer(
    "CELL_ETH_Bridge",                     // Имя моста
    wallet,                                // Кошелек отправителя
    transfer_amount,                       // Сумма
    token_ticker,                          // Тикер токена
    receiver_addr,                         // Адрес получателя
    &request_hash                         // Хеш запроса
);

if (transfer_result == 0) {
    log_info("Transfer request created: %s", request_hash);
    free(request_hash);
} else {
    log_error("Failed to create transfer request: %d", transfer_result);
}
```

### Подтверждение запроса валидатором

```c
// Подтверждение запроса (для валидаторов)
int confirm_result = dap_chain_net_srv_bridge_confirm_request(
    "CELL_ETH_Bridge",                     // Имя моста
    request_hash,                          // Хеш запроса
    validator_wallet                      // Кошелек валидатора
);

if (confirm_result == 0) {
    log_info("Request confirmed by validator");
} else {
    log_error("Failed to confirm request: %d", confirm_result);
}
```

### Мониторинг состояния моста

```c
// Получение статистики моста
dap_chain_net_srv_bridge_stats_t *stats =
    dap_chain_net_srv_bridge_get_stats("CELL_ETH_Bridge");

if (stats) {
    log_info("Bridge Statistics:");
    log_info("Active requests: %u", stats->active_requests_count);
    log_info("Total transferred: %s", dap_256_to_str(stats->total_transferred));
    log_info("Success rate: %.2f%%", stats->success_rate * 100);

    free(stats);
}

// Получение активных запросов
dap_list_t *requests = dap_chain_net_srv_bridge_get_requests("CELL_ETH_Bridge");

dap_list_t *current = requests;
while (current) {
    dap_chain_net_srv_bridge_request_t *request =
        (dap_chain_net_srv_bridge_request_t *)current->data;

    log_info("Request: %s", dap_hash_fast_to_str_static(&request->request_hash));
    log_info("Amount: %s", dap_256_to_str(request->amount));
    log_info("Status: %d", request->status);
    log_info("Confirmations: %u/%u", request->confirmations,
             get_bridge_config()->confirmations_required);

    current = current->next;
}

dap_list_free(requests);
```

## Производительность

### Характеристики производительности

- **Время создания запроса**: < 30 секунд
- **Время подтверждения**: < 5 минут
- **Время исполнения**: < 10 минут
- **Пропускная способность**: 50+ переводов/час
- **Максимальная сумма**: Ограничена конфигурацией

### Оптимизации

1. **Батчинг**: Группировка нескольких запросов
2. **Кеширование**: Кеширование состояний мостов
3. **Распределение**: Распределенная обработка запросов
4. **Мониторинг**: Реального времени мониторинг производительности

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Хранение запросов и подтверждений в блокчейне
- **Wallet**: Управление балансами для комиссий
- **Crypto**: Криптографическая защита операций
- **Net**: Сетевая коммуникация между мостами

### Примеры интеграции

```c
// Интеграция с wallet для автоматического бриджирования
void auto_bridge_assets(dap_chain_wallet_t *wallet,
                       const char *target_network,
                       uint256_t amount) {
    // Проверка доступных мостов
    dap_list_t *bridges = dap_chain_net_srv_bridge_get_list();

    dap_list_t *current = bridges;
    while (current) {
        const char *bridge_name = (const char *)current->data;

        // Проверка соответствия целевой сети
        dap_chain_net_srv_bridge_config_t *config =
            dap_chain_net_srv_bridge_get_config(bridge_name);

        if (strcmp(config->target_net_name, target_network) == 0) {
            // Создание запроса на бриджирование
            dap_chain_net_srv_bridge_request_transfer(
                bridge_name, wallet, amount, "CELL",
                get_target_address(target_network), NULL);
            break;
        }

        current = current->next;
    }

    dap_list_free(bridges);
}

// Интеграция с мониторингом для отслеживания мостов
void monitor_bridge_health() {
    dap_list_t *bridges = dap_chain_net_srv_bridge_get_list();

    dap_list_t *current = bridges;
    while (current) {
        const char *bridge_name = (const char *)current->data;

        dap_chain_net_srv_bridge_stats_t *stats =
            dap_chain_net_srv_bridge_get_stats(bridge_name);

        // Проверка здоровья моста
        if (stats->success_rate < 0.95) {
            alert_bridge_issue(bridge_name, "Low success rate");
        }

        if (stats->avg_confirmation_time > 600) { // 10 минут
            alert_bridge_issue(bridge_name, "Slow confirmation time");
        }

        free(stats);
        current = current->next;
    }

    dap_list_free(bridges);
}
```

## Заключение

Bridge Service CellFrame SDK предоставляет надежную и безопасную инфраструктуру для межсетевых переводов активов. Сервис поддерживает различные типы мостов и механизмы защиты, обеспечивая высокий уровень безопасности и надежности. Полная интеграция с блокчейн стеком CellFrame гарантирует прозрачность и неизменность всех операций бриджирования.
