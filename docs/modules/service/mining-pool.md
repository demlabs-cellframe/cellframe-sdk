# CellFrame SDK Mining Pool Service Module

## Обзор

**Mining Pool Service** - это сервис управления майнинг-пулами в CellFrame SDK. Сервис предоставляет инфраструктуру для координации работы майнеров, распределения задач, сбора решений и справедливого распределения вознаграждений в децентрализованной сети.

## Основные характеристики

- **Координация майнеров**: Управление группой майнеров
- **Распределение задач**: Эффективное распределение вычислительных задач
- **Сбор решений**: Агрегация решений от участников
- **Справедливое распределение**: PPLNS и другие схемы распределения
- **Мониторинг производительности**: Отслеживание вклада участников

## Архитектура

### Основные структуры данных

#### Конфигурация пула

```c
typedef struct dap_chain_net_srv_mining_pool_config {
    char name[DAP_MINING_POOL_NAME_SIZE];            // Имя пула
    char description[DAP_MINING_POOL_DESC_SIZE];     // Описание
    dap_chain_net_id_t net_id;                       // ID сети
    uint32_t min_contribution;                       // Минимальный вклад
    uint32_t max_participants;                       // Максимум участников
    uint32_t share_difficulty;                       // Сложность шарей
    dap_mining_pool_payout_scheme_t payout_scheme;   // Схема выплат
    uint32_t fee_percent;                            // Процент комиссии
    bool auto_payout;                                // Автоматические выплаты
    uint32_t payout_threshold;                       // Порог выплат
} dap_chain_net_srv_mining_pool_config_t;
```

#### Участник пула

```c
typedef struct dap_chain_net_srv_mining_pool_participant {
    dap_chain_addr_t addr;                           // Адрес участника
    uint64_t joined_at;                              // Время присоединения
    uint64_t total_shares;                           // Общее количество шарей
    uint64_t valid_shares;                           // Валидные шари
    uint64_t invalid_shares;                         // Неверные шари
    uint256_t pending_rewards;                       // Ожидающие вознаграждения
    uint256_t total_rewards;                         // Общие вознаграждения
    double hash_rate;                                // Хешрейт
    bool is_active;                                  // Активен ли участник
    uint64_t last_share_time;                        // Время последнего шара
} dap_chain_net_srv_mining_pool_participant_t;
```

#### Задача майнинга

```c
typedef struct dap_chain_net_srv_mining_pool_task {
    dap_hash_fast_t task_id;                         // ID задачи
    uint64_t created_at;                             // Время создания
    uint32_t difficulty;                             // Сложность
    dap_hash_fast_t prev_block_hash;                 // Хеш предыдущего блока
    uint64_t block_height;                           // Высота блока
    dap_time_t deadline;                             // Дедлайн
    uint32_t nonce_start;                            // Начальный nonce
    uint32_t nonce_range;                            // Диапазон nonce
    bool is_completed;                               // Завершена ли задача
    dap_hash_fast_t solution_hash;                   // Хеш решения
} dap_chain_net_srv_mining_pool_task_t;
```

#### Основная структура сервиса

```c
typedef struct dap_chain_net_srv_mining_pool {
    dap_chain_net_srv_t *parent;                     // Родительский сервис
    dap_chain_net_srv_mining_pool_config_t config;   // Конфигурация
    dap_list_t *participants;                        // Список участников
    dap_list_t *active_tasks;                        // Активные задачи
    dap_hash_fast_t *share_history;                  // История шарей
    uint64_t total_shares;                           // Общее количество шарей
    uint256_t total_rewards;                         // Общие вознаграждения
    uint64_t current_round;                          // Текущий раунд
    bool is_active;                                  // Активен ли пул
} dap_chain_net_srv_mining_pool_t;
```

## Схемы распределения вознаграждений

### Pay Per Last N Shares (PPLNS)

Распределение вознаграждений на основе последних N шарей:

```c
uint256_t calculate_pplns_reward(
    uint64_t participant_shares,                     // Шари участника
    uint64_t total_shares_in_window,                 // Общие шари в окне
    uint256_t block_reward                          // Вознаграждение блока
) {
    return (participant_shares * block_reward) / total_shares_in_window;
}
```

### Pay Per Share (PPS)

Фиксированная оплата за каждый шар:

```c
uint256_t calculate_pps_reward(
    uint64_t participant_shares,                     // Шари участника
    uint256_t share_reward                          // Вознаграждение за шар
) {
    return participant_shares * share_reward;
}
```

### Recent Share (RS)

На основе недавних шарей с экспоненциальным затуханием:

```c
uint256_t calculate_rs_reward(
    uint64_t participant_shares,                     // Шари участника
    uint64_t total_recent_shares,                    // Общие недавние шари
    uint256_t block_reward,                         // Вознаграждение блока
    double decay_factor                             // Коэффициент затухания
) {
    return (participant_shares * block_reward * decay_factor) / total_recent_shares;
}
```

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация mining pool сервиса
int dap_chain_net_srv_mining_pool_init();

// Деинициализация mining pool сервиса
void dap_chain_net_srv_mining_pool_deinit();
```

### Управление пулом

```c
// Создание нового майнинг-пула
int dap_chain_net_srv_mining_pool_create(
    const char *pool_name,                           // Имя пула
    dap_chain_net_id_t net_id,                       // ID сети
    dap_mining_pool_payout_scheme_t payout_scheme,   // Схема выплат
    uint32_t fee_percent                            // Процент комиссии
);

// Запуск пула
int dap_chain_net_srv_mining_pool_start(
    const char *pool_name                            // Имя пула
);

// Остановка пула
int dap_chain_net_srv_mining_pool_stop(
    const char *pool_name                            // Имя пула
);

// Удаление пула
int dap_chain_net_srv_mining_pool_remove(
    const char *pool_name                            // Имя пула
);
```

### Управление участниками

```c
// Присоединение к пулу
int dap_chain_net_srv_mining_pool_join(
    const char *pool_name,                           // Имя пула
    dap_chain_wallet_t *wallet                       // Кошелек участника
);

// Выход из пула
int dap_chain_net_srv_mining_pool_leave(
    const char *pool_name,                           // Имя пула
    dap_chain_addr_t participant_addr                // Адрес участника
);

// Получение списка участников
dap_list_t *dap_chain_net_srv_mining_pool_get_participants(
    const char *pool_name                            // Имя пула
);

// Получение статистики участника
dap_chain_net_srv_mining_pool_participant_t *dap_chain_net_srv_mining_pool_get_participant_stats(
    const char *pool_name,                           // Имя пула
    dap_chain_addr_t participant_addr                // Адрес участника
);
```

### Управление задачами

```c
// Получение задачи для майнинга
dap_chain_net_srv_mining_pool_task_t *dap_chain_net_srv_mining_pool_get_task(
    const char *pool_name,                           // Имя пула
    dap_chain_addr_t participant_addr                // Адрес участника
);

// Отправка решения
int dap_chain_net_srv_mining_pool_submit_solution(
    const char *pool_name,                           // Имя пула
    dap_chain_addr_t participant_addr,               // Адрес участника
    dap_chain_net_srv_mining_pool_task_t *task,      // Задача
    uint32_t nonce,                                  // Найденный nonce
    dap_hash_fast_t solution_hash                    // Хеш решения
);

// Проверка валидности решения
bool dap_chain_net_srv_mining_pool_validate_solution(
    dap_chain_net_srv_mining_pool_task_t *task,      // Задача
    uint32_t nonce,                                  // Nonce
    dap_hash_fast_t solution_hash                    // Хеш решения
);
```

### Управление выплатами

```c
// Расчет вознаграждений
int dap_chain_net_srv_mining_pool_calculate_rewards(
    const char *pool_name,                           // Имя пула
    uint256_t block_reward                          // Вознаграждение блока
);

// Выплата вознаграждений
int dap_chain_net_srv_mining_pool_payout_rewards(
    const char *pool_name,                           // Имя пула
    dap_chain_wallet_t *pool_wallet                 // Кошелек пула
);

// Получение ожидающих выплат
uint256_t dap_chain_net_srv_mining_pool_get_pending_rewards(
    const char *pool_name,                           // Имя пула
    dap_chain_addr_t participant_addr                // Адрес участника
);

// Запрос выплаты
int dap_chain_net_srv_mining_pool_request_payout(
    const char *pool_name,                           // Имя пула
    dap_chain_addr_t participant_addr,               // Адрес участника
    uint256_t amount                                // Сумма
);
```

## Безопасность

### Механизмы защиты

1. **Валидация шарей**: Проверка корректности решений
2. **Защита от мошенничества**: Обнаружение невалидных шарей
3. **Аутентификация**: Проверка подлинности участников
4. **Мониторинг**: Отслеживание подозрительной активности

### Защита от атак

- **Share grinding**: Защита от искусственного создания шарей
- **Pool hopping**: Предотвращение быстрого переключения между пулами
- **Sybil attacks**: Защита через экономические барьеры
- **DDoS attacks**: Защита от сетевых атак

## Использование

### Создание майнинг-пула

```c
#include "dap_chain_net_srv_mining_pool.h"

// Параметры пула
const char *pool_name = "MyMiningPool";
dap_chain_net_id_t net_id = CELLFRAME_NET_ID;
dap_mining_pool_payout_scheme_t payout_scheme = PPLNS_SCHEME;
uint32_t fee_percent = 2; // 2% комиссия

// Создание пула
int result = dap_chain_net_srv_mining_pool_create(
    pool_name,                               // Имя пула
    net_id,                                  // ID сети
    payout_scheme,                           // Схема выплат
    fee_percent                             // Процент комиссии
);

if (result == 0) {
    log_info("Mining pool created successfully");

    // Запуск пула
    if (dap_chain_net_srv_mining_pool_start(pool_name) == 0) {
        log_info("Mining pool started");
    }
} else {
    log_error("Failed to create mining pool: %d", result);
}
```

### Присоединение к пулу

```c
// Присоединение к пулу
int join_result = dap_chain_net_srv_mining_pool_join(
    pool_name,                               // Имя пула
    wallet                                   // Кошелек участника
);

if (join_result == 0) {
    log_info("Successfully joined mining pool");

    // Получение статистики участника
    dap_chain_net_srv_mining_pool_participant_t *stats =
        dap_chain_net_srv_mining_pool_get_participant_stats(
            pool_name, wallet->addr);

    if (stats) {
        log_info("Participant stats:");
        log_info("Total shares: %llu", stats->total_shares);
        log_info("Hash rate: %.2f H/s", stats->hash_rate);
        log_info("Pending rewards: %s", dap_256_to_str(stats->pending_rewards));

        free(stats);
    }
} else {
    log_error("Failed to join mining pool: %d", join_result);
}
```

### Работа с задачами майнинга

```c
// Получение задачи для майнинга
dap_chain_net_srv_mining_pool_task_t *task =
    dap_chain_net_srv_mining_pool_get_task(pool_name, wallet->addr);

if (task) {
    log_info("Received mining task:");
    log_info("Task ID: %s", dap_hash_fast_to_str_static(&task->task_id));
    log_info("Difficulty: %u", task->difficulty);
    log_info("Block height: %llu", task->block_height);

    // Майнинг решения
    uint32_t found_nonce = perform_mining(
        task->prev_block_hash,
        task->difficulty,
        task->nonce_start,
        task->nonce_range
    );

    if (found_nonce != 0) {
        // Вычисление хеша решения
        dap_hash_fast_t solution_hash = calculate_solution_hash(
            task->prev_block_hash, found_nonce);

        // Отправка решения
        int submit_result = dap_chain_net_srv_mining_pool_submit_solution(
            pool_name,                          // Имя пула
            wallet->addr,                       // Адрес участника
            task,                               // Задача
            found_nonce,                        // Найденный nonce
            solution_hash                       // Хеш решения
        );

        if (submit_result == 0) {
            log_info("Solution submitted successfully");
        } else {
            log_error("Failed to submit solution: %d", submit_result);
        }
    }

    free(task);
} else {
    log_error("Failed to get mining task");
}
```

### Управление вознаграждениями

```c
// Проверка ожидающих вознаграждений
uint256_t pending_rewards = dap_chain_net_srv_mining_pool_get_pending_rewards(
    pool_name, wallet->addr);

if (dap_is_zero256(pending_rewards) == false) {
    log_info("Pending rewards: %s", dap_256_to_str(pending_rewards));

    // Запрос выплаты
    int payout_result = dap_chain_net_srv_mining_pool_request_payout(
        pool_name,                              // Имя пула
        wallet->addr,                           // Адрес участника
        pending_rewards                        // Сумма для выплаты
    );

    if (payout_result == 0) {
        log_info("Payout requested successfully");
    } else {
        log_error("Failed to request payout: %d", payout_result);
    }
}
```

### Мониторинг производительности

```c
// Получение списка участников
dap_list_t *participants = dap_chain_net_srv_mining_pool_get_participants(pool_name);

// Анализ производительности
dap_list_t *current = participants;
while (current) {
    dap_chain_net_srv_mining_pool_participant_t *participant =
        (dap_chain_net_srv_mining_pool_participant_t *)current->data;

    // Расчет эффективности
    double efficiency = (double)participant->valid_shares /
                       (participant->valid_shares + participant->invalid_shares);

    log_info("Participant: %s", dap_chain_addr_to_str_static(&participant->addr));
    log_info("Hash rate: %.2f H/s", participant->hash_rate);
    log_info("Efficiency: %.2f%%", efficiency * 100);
    log_info("Total rewards: %s", dap_256_to_str(participant->total_rewards));

    current = current->next;
}

dap_list_free(participants);
```

## Производительность

### Характеристики производительности

- **Время распределения задач**: < 1 секунда
- **Время проверки решений**: < 100 мс
- **Пропускная способность**: 1000+ шарей/сек
- **Задержка сети**: < 50 мс
- **Эффективность распределения**: > 95%

### Оптимизации

1. **Распределение нагрузки**: Балансировка задач между участниками
2. **Кеширование**: Кеширование часто используемых данных
3. **Батчинг**: Группировка операций для оптимизации
4. **Предварительная валидация**: Быстрая проверка решений

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Валидация решений и распределение вознаграждений
- **Wallet**: Управление выплатами и балансами
- **Net**: Сетевая коммуникация с участниками
- **Consensus**: Участие в формировании блоков

### Примеры интеграции

```c
// Интеграция с майнинг ПО
class MiningClient {
private:
    const char *pool_name;
    dap_chain_wallet_t *wallet;
    bool is_mining = false;

public:
    void startMining() {
        is_mining = true;

        while (is_mining) {
            // Получение задачи
            auto task = dap_chain_net_srv_mining_pool_get_task(pool_name, wallet->addr);

            if (task) {
                // Майнинг
                uint32_t nonce = mineBlock(task);

                if (nonce != 0) {
                    // Отправка решения
                    submitSolution(task, nonce);
                }

                delete task;
            }

            // Небольшая пауза
            sleep(1);
        }
    }

    uint32_t mineBlock(dap_chain_net_srv_mining_pool_task_t *task) {
        // Реализация майнинга
        for (uint32_t nonce = task->nonce_start;
             nonce < task->nonce_start + task->nonce_range;
             nonce++) {

            if (checkSolution(task, nonce)) {
                return nonce;
            }
        }
        return 0;
    }

    void submitSolution(dap_chain_net_srv_mining_pool_task_t *task, uint32_t nonce) {
        dap_hash_fast_t solution_hash = calculate_hash(task, nonce);

        dap_chain_net_srv_mining_pool_submit_solution(
            pool_name, wallet->addr, task, nonce, solution_hash);
    }
};

// Интеграция с мониторингом
void monitorPoolPerformance() {
    // Получение общей статистики пула
    uint64_t total_shares = get_pool_total_shares(pool_name);
    uint64_t active_participants = get_pool_active_participants(pool_name);
    double avg_hash_rate = get_pool_avg_hash_rate(pool_name);

    // Отправка метрик
    send_metric("mining_pool_total_shares", total_shares);
    send_metric("mining_pool_active_participants", active_participants);
    send_metric("mining_pool_avg_hash_rate", avg_hash_rate);

    // Проверка здоровья пула
    if (active_participants < 10) {
        alert_pool_issue("Low participant count");
    }

    if (avg_hash_rate < 1000000) { // 1 MH/s
        alert_pool_issue("Low average hash rate");
    }
}
```

## Заключение

Mining Pool Service CellFrame SDK предоставляет полноценную инфраструктуру для организации децентрализованного майнинга. Сервис обеспечивает эффективную координацию участников, справедливое распределение вознаграждений и высокую производительность. Полная интеграция с блокчейн стеком гарантирует безопасность, прозрачность и надежность майнинг операций в сети CellFrame.
