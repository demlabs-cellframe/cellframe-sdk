# CellFrame SDK Staking Service Module

## Обзор

**Staking Service** - это сервис делегирования ставок в CellFrame SDK, обеспечивающий механизм Proof-of-Stake (PoS) для сети. Сервис позволяет участникам делегировать свои токены валидаторам для обеспечения консенсуса и получения вознаграждений. Включает поддержку делегирования, валидации и управления ставками.

## Основные характеристики

- **Proof-of-Stake**: Полная поддержка PoS консенсуса
- **Делегирование**: Возможность делегирования ставок валидаторам
- **Валидация**: Автоматическая валидация ставок и валидаторов
- **Награды**: Распределение вознаграждений между делегаторами и валидаторами
- **Безопасность**: Криптографическая защита всех операций

## Архитектура

### Основные структуры данных

#### Элемент ставки

```c
typedef struct dap_chain_net_srv_stake_item {
    bool is_active;                           // Активна ли ставка
    dap_chain_net_t *net;                     // Ссылка на сеть
    uint256_t locked_value;                   // Заблокированная сумма
    uint256_t value;                          // Текущая сумма ставки
    dap_chain_addr_t signing_addr;            // Адрес подписи
    dap_chain_hash_fast_t tx_hash;            // Хеш транзакции
    dap_chain_node_addr_t node_addr;          // Адрес узла
    dap_chain_addr_t sovereign_addr;          // Суверенный адрес
    uint256_t sovereign_tax;                  // Налог суверена
    dap_pkey_t *pkey;                         // Открытый ключ
    UT_hash_handle hh, ht;                    // Хеш-таблицы
} dap_chain_net_srv_stake_item_t;
```

#### Кэш данных ставки

```c
typedef struct dap_chain_net_srv_stake_cache_data {
    dap_chain_hash_fast_t tx_hash;            // Хеш транзакции
    dap_chain_addr_t signing_addr;            // Адрес подписи
} dap_chain_net_srv_stake_cache_data_t;
```

#### Основная структура сервиса

```c
typedef struct dap_chain_net_srv_stake {
    dap_chain_net_id_t net_id;                // ID сети
    uint256_t delegate_allowed_min;           // Минимальная сумма делегирования
    uint256_t delegate_percent_max;           // Максимальный процент делегирования
    dap_chain_net_srv_stake_item_t *itemlist; // Список элементов ставок
    dap_chain_net_srv_stake_item_t *tx_itemlist; // Список элементов транзакций
    dap_chain_net_srv_stake_cache_item_t *cache; // Кэш
} dap_chain_net_srv_stake_t;
```

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация staking сервиса
int dap_chain_net_srv_stake_pos_delegate_init();

// Деинициализация staking сервиса
void dap_chain_net_srv_stake_pos_delegate_deinit();
```

### Управление сетью

```c
// Добавление сети для staking
int dap_chain_net_srv_stake_net_add(dap_chain_net_id_t a_net_id);
```

### Делегирование ключей

```c
// Делегирование ключа валидатору
void dap_chain_net_srv_stake_key_delegate(
    dap_chain_net_t *a_net,                   // Сеть
    dap_chain_addr_t *a_signing_addr,         // Адрес подписи
    dap_hash_fast_t *a_stake_tx_hash,         // Хеш транзакции ставки
    uint256_t a_value,                        // Сумма ставки
    dap_chain_node_addr_t *a_node_addr,       // Адрес узла
    dap_pkey_t *a_pkey                        // Открытый ключ
);

// Инвалидация делегированного ключа
void dap_chain_net_srv_stake_key_invalidate(
    dap_chain_addr_t *a_signing_addr          // Адрес подписи
);

// Обновление суммы ставки
void dap_chain_net_srv_stake_key_update(
    dap_chain_addr_t *a_signing_addr,         // Адрес подписи
    uint256_t a_new_value,                    // Новая сумма
    dap_hash_fast_t *a_new_tx_hash            // Новый хеш транзакции
);

// Обновление открытого ключа
void dap_chain_net_srv_stake_pkey_update(
    dap_chain_net_t *a_net,                   // Сеть
    dap_pkey_t *a_pkey                        // Новый открытый ключ
);
```

### Управление параметрами

```c
// Установка минимальной суммы делегирования
void dap_chain_net_srv_stake_set_allowed_min_value(
    dap_chain_net_id_t a_net_id,              // ID сети
    uint256_t a_value                         // Минимальная сумма
);

// Получение минимальной суммы делегирования
uint256_t dap_chain_net_srv_stake_get_allowed_min_value(
    dap_chain_net_id_t a_net_id               // ID сети
);

// Установка максимального процента делегирования
void dap_chain_net_srv_stake_set_percent_max(
    dap_chain_net_id_t a_net_id,              // ID сети
    uint256_t a_value                         // Максимальный процент
);

// Получение максимального процента делегирования
uint256_t dap_chain_net_srv_stake_get_percent_max(
    dap_chain_net_id_t a_net_id               // ID сети
);
```

### Проверка и валидация

```c
// Проверка делегирования ключа
int dap_chain_net_srv_stake_key_delegated(
    dap_chain_addr_t *a_addr                  // Адрес для проверки
);

// Верификация ключа и узла
int dap_chain_net_srv_stake_verify_key_and_node(
    dap_chain_addr_t* a_signing_addr,         // Адрес подписи
    dap_chain_node_addr_t* a_node_addr        // Адрес узла
);
```

### Получение списка валидаторов

```c
// Получение списка валидаторов
dap_list_t *dap_chain_net_srv_stake_get_validators(
    dap_chain_net_id_t a_net_id,              // ID сети
    bool a_only_active,                       // Только активные
    uint16_t **a_excluded_list                // Список исключенных
);
```

### Статистика комиссий

```c
// Получение статистики комиссий валидаторов
bool dap_chain_net_srv_stake_get_fee_validators(
    dap_chain_net_t *a_net,                   // Сеть
    uint256_t *a_max_fee,                     // Максимальная комиссия
    uint256_t *a_average_fee,                 // Средняя комиссия
    uint256_t *a_min_fee,                     // Минимальная комиссия
    uint256_t *a_median_fee                   // Медианная комиссия
);

// Получение статистики комиссий в виде строки
void dap_chain_net_srv_stake_get_fee_validators_str(
    dap_chain_net_t *a_net,                   // Сеть
    dap_string_t *a_string                    // Строка для результата
);

// Получение статистики комиссий в виде JSON
json_object *dap_chain_net_srv_stake_get_fee_validators_json(
    dap_chain_net_t *a_net                    // Сеть
);
```

### Управление кэшем

```c
// Загрузка кэша ставок
int dap_chain_net_srv_stake_load_cache(
    dap_chain_net_t *a_net                    // Сеть
);

// Очистка ставок
void dap_chain_net_srv_stake_purge(
    dap_chain_net_t *a_net                    // Сеть
);
```

### Валидация валидаторов

```c
// Проверка валидатора
int dap_chain_net_srv_stake_check_validator(
    dap_chain_net_t * a_net,                  // Сеть
    dap_hash_fast_t *a_tx_hash,               // Хеш транзакции
    dap_chain_ch_validator_test_t * out_data, // Выходные данные
    int a_time_connect,                       // Время подключения
    int a_time_respone                        // Время ответа
);
```

### Управление декретами

```c
// Создание декрета для утверждения ставки
dap_chain_datum_decree_t *dap_chain_net_srv_stake_decree_approve(
    dap_chain_net_t *a_net,                   // Сеть
    dap_hash_fast_t *a_stake_tx_hash,         // Хеш транзакции ставки
    dap_cert_t *a_cert                        // Сертификат
);

// Управление активностью валидатора
int dap_chain_net_srv_stake_mark_validator_active(
    dap_chain_addr_t *a_signing_addr,         // Адрес подписи
    bool a_on_off                            // Включить/выключить
);
```

### Поиск и статистика

```c
// Поиск ставки по публичному ключу хеша
dap_chain_net_srv_stake_item_t *dap_chain_net_srv_stake_check_pkey_hash(
    dap_chain_net_id_t a_net_id,              // ID сети
    dap_hash_fast_t *a_pkey_hash              // Хеш публичного ключа
);

// Получение общего веса ставок
uint256_t dap_chain_net_srv_stake_get_total_weight(
    dap_chain_net_id_t a_net_id,              // ID сети
    uint256_t *a_locked_weight                // Заблокированный вес
);

// Получение общего количества ключей
size_t dap_chain_net_srv_stake_get_total_keys(
    dap_chain_net_id_t a_net_id,              // ID сети
    size_t *a_in_active_count                 // Количество неактивных
);

// Поиск публичного ключа по хешу
dap_pkey_t *dap_chain_net_srv_stake_get_pkey_by_hash(
    dap_chain_net_id_t a_net_id,              // ID сети
    dap_hash_fast_t *a_hash                   // Хеш
);
```

## Принцип работы

### 1. Процесс делегирования

1. **Создание ставки**: Участник создает транзакцию с суммой ставки
2. **Делегирование**: Ставка делегируется выбранному валидатору
3. **Валидация**: Система проверяет корректность делегирования
4. **Активация**: Ставка становится активной и участвует в консенсусе

### 2. Распределение вознаграждений

1. **Генерация блока**: Валидатор создает новый блок
2. **Расчет вознаграждения**: Система рассчитывает вознаграждение
3. **Распределение**: Вознаграждение распределяется между валидатором и делегаторами
4. **Выплата**: Вознаграждения выплачиваются участникам

### 3. Управление рисками

- **Slashing**: Штрафы за недобросовестное поведение
- **Timeout**: Автоматическое исключение неактивных валидаторов
- **Limits**: Ограничения на максимальную ставку одного участника

## Использование

### Базовая инициализация

```c
#include "dap_chain_net_srv_stake_pos_delegate.h"

// Инициализация staking сервиса
if (dap_chain_net_srv_stake_pos_delegate_init() != 0) {
    log_error("Failed to initialize staking service");
    return -1;
}

// Добавление сети
if (dap_chain_net_srv_stake_net_add(net_id) != 0) {
    log_error("Failed to add network to staking service");
    return -1;
}

// Основная работа...

// Деинициализация
dap_chain_net_srv_stake_pos_delegate_deinit();
```

### Делегирование ставки

```c
// Параметры делегирования
dap_chain_addr_t signing_addr = get_my_signing_addr();
dap_hash_fast_t stake_tx_hash = get_stake_tx_hash();
uint256_t stake_value = dap_chain_balance_to256("1000.0");
dap_chain_node_addr_t validator_addr = get_validator_addr();
dap_pkey_t *pkey = get_my_public_key();

// Делегирование ставки валидатору
dap_chain_net_srv_stake_key_delegate(
    net, &signing_addr, &stake_tx_hash,
    stake_value, &validator_addr, pkey
);

// Проверка успешности делегирования
if (dap_chain_net_srv_stake_key_delegated(&signing_addr)) {
    log_info("Stake successfully delegated");
} else {
    log_error("Stake delegation failed");
}
```

### Получение статистики

```c
// Получение списка активных валидаторов
dap_list_t *validators = dap_chain_net_srv_stake_get_validators(net_id, true, NULL);

// Получение статистики комиссий
uint256_t max_fee, avg_fee, min_fee, median_fee;
if (dap_chain_net_srv_stake_get_fee_validators(net, &max_fee, &avg_fee, &min_fee, &median_fee)) {
    log_info("Validator fees - Max: %s, Avg: %s, Min: %s, Median: %s",
             dap_256_to_str(max_fee), dap_256_to_str(avg_fee),
             dap_256_to_str(min_fee), dap_256_to_str(median_fee));
}

// Освобождение ресурсов
dap_list_free(validators);
```

### Управление ставками

```c
// Обновление суммы ставки
uint256_t new_value = dap_chain_balance_to256("1500.0");
dap_hash_fast_t new_tx_hash = get_new_stake_tx_hash();

dap_chain_net_srv_stake_key_update(&signing_addr, new_value, &new_tx_hash);

// Инвалидация ставки (отзыв)
dap_chain_net_srv_stake_key_invalidate(&signing_addr);
```

## Безопасность

### Механизмы безопасности

1. **Криптографическая защита**: Все операции подписываются
2. **Валидация транзакций**: Проверка корректности всех ставок
3. **Аудит**: Полный аудит всех операций со ставками
4. **Мониторинг**: Отслеживание подозрительной активности

### Защита от атак

- **Double staking**: Предотвращение двойного делегирования
- **Sybil attacks**: Защита через минимальные суммы ставок
- **Nothing-at-stake**: Экономические стимулы для честного поведения

## Производительность

### Метрики производительности

- **Время делегирования**: < 30 секунд
- **Количество валидаторов**: До 1000 активных
- **Время обновления**: < 10 секунд
- **Пропускная способность**: 1000+ транзакций/сек

### Оптимизации

1. **Кеширование**: Кеширование часто используемых данных
2. **Батчинг**: Группировка операций для оптимизации
3. **Индексирование**: Эффективное индексирование ставок
4. **Распределение**: Распределенная обработка запросов

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Управление транзакциями ставок
- **Wallet**: Управление балансами и переводами
- **Consensus**: Участие в голосовании
- **Net**: Сетевая коммуникация валидаторов

### Примеры интеграции

```c
// Интеграция с wallet для автоматического делегирования
void auto_delegate_stake(dap_chain_wallet_t *wallet, uint256_t amount) {
    // Проверка баланса
    if (dap_chain_wallet_get_balance(wallet) >= amount) {
        // Автоматический выбор валидатора с лучшей комиссией
        dap_chain_node_addr_t best_validator = find_best_validator();

        // Создание и подписание транзакции ставки
        dap_chain_datum_tx_t *stake_tx = create_stake_tx(wallet, amount);

        // Делегирование ставки
        dap_chain_net_srv_stake_key_delegate(
            net, &wallet->addr, &stake_tx->hash,
            amount, &best_validator, wallet->pkey
        );
    }
}

// Интеграция с мониторингом
void monitor_staking_activity() {
    // Получение статистики ставок
    uint256_t total_weight, locked_weight;
    uint256_t total = dap_chain_net_srv_stake_get_total_weight(net_id, &locked_weight);

    // Отправка метрик
    send_metric("staking_total_weight", dap_256_to_str(total));
    send_metric("staking_locked_weight", dap_256_to_str(locked_weight));
}
```

## Заключение

Staking Service CellFrame SDK предоставляет полную инфраструктуру для Proof-of-Stake консенсуса с поддержкой делегирования ставок. Сервис обеспечивает безопасное и эффективное управление ставками, распределение вознаграждений и участие в сетевом консенсусе. Интеграция с другими компонентами CellFrame позволяет создавать масштабируемые и безопасные блокчейн решения на базе PoS механизма.
