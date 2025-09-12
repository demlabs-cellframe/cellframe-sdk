# CellFrame SDK Exchange Service Module

## Обзор

**Exchange Service** - это децентрализованный сервис обмена токенов в CellFrame SDK. Сервис позволяет участникам сети создавать ордера на обмен токенов, управлять ликвидностью и выполнять атомарные свопы. Включает поддержку ордербука, различных типов ордеров и интеграцию с блокчейн для обеспечения надежности транзакций.

## Основные характеристики

- **Децентрализованный обмен**: P2P обмен без центрального контрагента
- **Атомарные свопы**: Гарантированные обмены без риска контрагента
- **Множественные пары**: Поддержка различных токенов и валют
- **Ордербук**: Полноценная книга ордеров с matching engine
- **Комиссии**: Гибкая система комиссий и сборов

## Архитектура

### Основные структуры данных

#### Цена обмена

```c
typedef struct dap_chain_net_srv_xchange_price {
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];    // Токен продажи
    uint256_t datoshi_sell;                        // Количество токена продажи
    dap_chain_net_t *net;                          // Ссылка на сеть
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];     // Токен покупки
    uint256_t rate;                                // Курс обмена
    uint256_t fee;                                 // Комиссия
    dap_chain_hash_fast_t tx_hash;                 // Хеш транзакции
    dap_chain_hash_fast_t order_hash;              // Хеш ордера
    dap_chain_addr_t creator_addr;                 // Адрес создателя
    dap_time_t creation_date;                      // Дата создания
} dap_chain_net_srv_xchange_price_t;
```

#### Расширение ордера

```c
typedef struct dap_srv_xchange_order_ext {
    uint64_t padding;                              // Заполнитель
    uint256_t datoshi_buy;                         // Количество токена покупки
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];     // Токен покупки
} DAP_ALIGN_PACKED dap_srv_xchange_order_ext_t;
```

#### Основная структура сервиса

```c
typedef struct dap_chain_net_srv_xchange {
    dap_chain_net_srv_t *parent;                   // Родительский сервис
    bool enabled;                                  // Включен ли сервис
} dap_chain_net_srv_xchange_t;
```

## Типы ордеров

### По времени действия

1. **Market Order**: Рыночный ордер - исполнение по текущей цене
2. **Limit Order**: Лимитный ордер - исполнение по указанной цене или лучше
3. **Stop Order**: Стоп ордер - активация при достижении цены
4. **Stop-Limit Order**: Стоп-лимит ордер - комбинация стоп и лимит

### По направлению

1. **Buy Order**: Ордер на покупку
2. **Sell Order**: Ордер на продажу

### По условиям

1. **GTC (Good Till Cancel)**: Действует до отмены
2. **IOC (Immediate or Cancel)**: Исполнить немедленно или отменить
3. **FOK (Fill or Kill)**: Исполнить полностью или отменить

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация exchange сервиса
int dap_chain_net_srv_xchange_init();

// Деинициализация exchange сервиса
void dap_chain_net_srv_xchange_deinit();
```

### Создание ордера

```c
// Создание ордера на обмен
dap_chain_net_srv_xchange_create_error_t dap_chain_net_srv_xchange_create(
    dap_chain_net_t *a_net,                        // Сеть
    const char *a_token_buy,                       // Токен покупки
    const char *a_token_sell,                      // Токен продажи
    uint256_t a_datoshi_sell,                      // Количество продажи
    uint256_t a_rate,                              // Курс обмена
    uint256_t a_fee,                               // Комиссия
    dap_chain_wallet_t *a_wallet,                  // Кошелек
    char **a_out_tx_hash                           // Выходной хеш транзакции
);
```

### Удаление ордера

```c
// Удаление существующего ордера
dap_chain_net_srv_xchange_remove_error_t dap_chain_net_srv_xchange_remove(
    dap_chain_net_t *a_net,                        // Сеть
    dap_hash_fast_t *a_hash_tx,                    // Хеш транзакции ордера
    uint256_t a_fee,                               // Комиссия за удаление
    dap_chain_wallet_t *a_wallet,                  // Кошелек
    char **a_out_hash_tx                           // Выходной хеш транзакции
);
```

### Исполнение ордера

```c
// Покупка по существующему ордеру
dap_chain_net_srv_xchange_purchase_error_t dap_chain_net_srv_xchange_purchase(
    dap_chain_net_t *a_net,                        // Сеть
    dap_hash_fast_t *a_order_hash,                 // Хеш ордера
    uint256_t a_value,                             // Сумма покупки
    uint256_t a_fee,                               // Комиссия
    dap_chain_wallet_t *a_wallet,                  // Кошелек покупателя
    char **a_hash_out                              // Выходной хеш
);
```

### Получение информации

```c
// Получение всех транзакций обмена
dap_list_t *dap_chain_net_srv_xchange_get_tx_xchange(
    dap_chain_net_t *a_net                         // Сеть
);

// Получение всех цен/ордеров
dap_list_t *dap_chain_net_srv_xchange_get_prices(
    dap_chain_net_t *a_net                         // Сеть
);
```

### Статистика и мониторинг

```c
// Получение процента исполнения ордера
uint64_t dap_chain_net_srv_xchange_get_order_completion_rate(
    dap_chain_net_t *a_net,                        // Сеть
    dap_hash_fast_t a_order_tx_hash                // Хеш транзакции ордера
);

// Получение статуса ордера
dap_chain_net_srv_xchange_order_status_t dap_chain_net_srv_xchange_get_order_status(
    dap_chain_net_t *a_net,                        // Сеть
    dap_hash_fast_t a_order_tx_hash                // Хеш транзакции ордера
);

// Получение комиссии
bool dap_chain_net_srv_xchange_get_fee(
    dap_chain_net_id_t a_net_id,                   // ID сети
    uint256_t *a_fee,                              // Комиссия
    dap_chain_addr_t *a_addr,                      // Адрес
    uint16_t *a_type                               // Тип
);
```

## Коды ошибок

### Ошибки создания ордера

| Код | Константа | Описание |
|-----|-----------|----------|
| 0 | `XCHANGE_CREATE_ERROR_OK` | Успешное создание |
| 1 | `XCHANGE_CREATE_ERROR_INVALID_ARGUMENT` | Неверные аргументы |
| 2 | `XCHANGE_CREATE_ERROR_TOKEN_TICKER_SELL_IS_NOT_FOUND_LEDGER` | Токен продажи не найден |
| 3 | `XCHANGE_CREATE_ERROR_TOKEN_TICKER_BUY_IS_NOT_FOUND_LEDGER` | Токен покупки не найден |
| 4 | `XCHANGE_CREATE_ERROR_RATE_IS_ZERO` | Нулевой курс |
| 5 | `XCHANGE_CREATE_ERROR_FEE_IS_ZERO` | Нулевая комиссия |
| 6 | `XCHANGE_CREATE_ERROR_VALUE_SELL_IS_ZERO` | Нулевая сумма продажи |
| 7 | `XCHANGE_CREATE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE` | Переполнение при суммировании |
| 8 | `XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET` | Недостаточно средств для комиссии |

### Ошибки удаления ордера

| Код | Константа | Описание |
|-----|-----------|----------|
| 0 | `XCHANGE_REMOVE_ERROR_OK` | Успешное удаление |
| 1 | `XCHANGE_REMOVE_ERROR_INVALID_ARGUMENT` | Неверные аргументы |
| 2 | `XCHANGE_REMOVE_ERROR_FEE_IS_ZERO` | Нулевая комиссия |
| 3 | `XCHANGE_REMOVE_ERROR_CAN_NOT_FIND_TX` | Транзакция не найдена |

### Ошибки покупки

| Код | Константа | Описание |
|-----|-----------|----------|
| 0 | `XCHANGE_PURCHASE_ERROR_OK` | Успешная покупка |
| 1 | `XCHANGE_PURCHASE_ERROR_INVALID_ARGUMENT` | Неверные аргументы |
| 2 | `XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND` | Ордер не найден |

## Принцип работы

### 1. Создание ордера

1. **Формулировка условий**: Указание токенов, суммы, курса
2. **Расчет комиссии**: Автоматический расчет сборов
3. **Создание транзакции**: Формирование ордера в блокчейне
4. **Публикация**: Добавление в ордербук

### 2. Matching ордеров

1. **Поиск совпадений**: Поиск подходящих контр-ордеров
2. **Исполнение**: Атомарный обмен при совпадении условий
3. **Обновление**: Корректировка ордербука после исполнения
4. **Уведомления**: Информирование участников об изменениях

### 3. Управление ликвидностью

1. **Ордербук**: Поддержание актуального состояния книги ордеров
2. **Цены**: Расчет оптимальных курсов обмена
3. **Статистика**: Мониторинг объема торгов и ликвидности
4. **Балансировка**: Поддержание баланса между спросом и предложением

## Безопасность

### Механизмы защиты

1. **Атомарные свопы**: Гарантированные обмены без риска контрагента
2. **Многоуровневая валидация**: Проверка всех параметров транзакций
3. **Криптографическая защита**: Подписание всех операций
4. **Аудит транзакций**: Полная traceability всех обменов

### Защита от рисков

- **Slippage**: Защита от нежелательных изменений цены
- **Front-running**: Предотвращение фронт-раннинга
- **Wash trading**: Обнаружение и предотвращение фейковых сделок
- **Market manipulation**: Защита от манипуляций рынком

## Использование

### Создание ордера на продажу

```c
#include "dap_chain_net_srv_xchange.h"

// Параметры ордера
const char *token_sell = "CELL";           // Продаем CELL токены
const char *token_buy = "USD";             // Покупаем за USD
uint256_t amount_sell = dap_chain_coins_to_balance("100.0");  // Продаем 100 CELL
uint256_t rate = dap_chain_coins_to_balance("0.5");           // Курс 1 CELL = 0.5 USD
uint256_t fee = dap_chain_coins_to_balance("0.001");          // Комиссия 0.001 CELL

// Создание ордера
char *tx_hash = NULL;
dap_chain_net_srv_xchange_create_error_t result = dap_chain_net_srv_xchange_create(
    net,                                    // Сеть
    token_buy,                              // Токен покупки
    token_sell,                             // Токен продажи
    amount_sell,                            // Сумма продажи
    rate,                                   // Курс
    fee,                                    // Комиссия
    wallet,                                 // Кошелек
    &tx_hash                               // Выходной хеш
);

if (result == XCHANGE_CREATE_ERROR_OK) {
    log_info("Exchange order created: %s", tx_hash);
    free(tx_hash);
} else {
    log_error("Failed to create exchange order: %d", result);
}
```

### Исполнение существующего ордера

```c
// Хеш ордера для покупки
dap_hash_fast_t order_hash;
dap_hash_fast_from_str(&order_hash, "0123456789abcdef...");

// Параметры покупки
uint256_t buy_amount = dap_chain_coins_to_balance("25.0");    // Купить на 25 USD
uint256_t buy_fee = dap_chain_coins_to_balance("0.001");      // Комиссия

// Исполнение ордера
char *purchase_hash = NULL;
dap_chain_net_srv_xchange_purchase_error_t purchase_result =
    dap_chain_net_srv_xchange_purchase(
        net,                                // Сеть
        &order_hash,                        // Хеш ордера
        buy_amount,                         // Сумма покупки
        buy_fee,                            // Комиссия
        wallet,                             // Кошелек покупателя
        &purchase_hash                     // Выходной хеш
    );

if (purchase_result == XCHANGE_PURCHASE_ERROR_OK) {
    log_info("Exchange purchase completed: %s", purchase_hash);
    free(purchase_hash);
} else {
    log_error("Failed to complete exchange purchase: %d", purchase_result);
}
```

### Получение информации о рынке

```c
// Получение всех активных ордеров
dap_list_t *prices = dap_chain_net_srv_xchange_get_prices(net);

// Обработка списка цен
dap_list_t *current = prices;
while (current) {
    dap_chain_net_srv_xchange_price_t *price =
        (dap_chain_net_srv_xchange_price_t *)current->data;

    log_info("Exchange pair: %s/%s", price->token_sell, price->token_buy);
    log_info("Rate: %s", dap_256_to_str(price->rate));
    log_info("Amount: %s", dap_256_to_str(price->datoshi_sell));
    log_info("Fee: %s", dap_256_to_str(price->fee));
    log_info("Creator: %s", dap_chain_addr_to_str_static(&price->creator_addr));

    current = current->next;
}

// Освобождение ресурсов
dap_list_free(prices);
```

### Мониторинг ордера

```c
// Хеш транзакции ордера
dap_hash_fast_t order_tx_hash;
dap_hash_fast_from_str(&order_tx_hash, "0123456789abcdef...");

// Получение статуса ордера
dap_chain_net_srv_xchange_order_status_t status =
    dap_chain_net_srv_xchange_get_order_status(net, order_tx_hash);

switch (status) {
    case XCHANGE_ORDER_STATUS_OPENED:
        log_info("Order is active and waiting for execution");
        break;
    case XCHANGE_ORDER_STATUS_CLOSED:
        log_info("Order has been fully executed");
        break;
    case XCHANGE_ORDER_STATUS_UNKNOWN:
        log_error("Order status unknown");
        break;
}

// Получение процента исполнения
uint64_t completion_rate = dap_chain_net_srv_xchange_get_order_completion_rate(
    net, order_tx_hash);

log_info("Order completion: %llu%%", completion_rate);
```

### Удаление ордера

```c
// Параметры удаления
uint256_t cancel_fee = dap_chain_coins_to_balance("0.001");

// Удаление ордера
char *cancel_hash = NULL;
dap_chain_net_srv_xchange_remove_error_t cancel_result =
    dap_chain_net_srv_xchange_remove(
        net,                                // Сеть
        &order_tx_hash,                     // Хеш транзакции ордера
        cancel_fee,                         // Комиссия за отмену
        wallet,                             // Кошелек владельца
        &cancel_hash                       // Выходной хеш
    );

if (cancel_result == XCHANGE_REMOVE_ERROR_OK) {
    log_info("Order cancelled: %s", cancel_hash);
    free(cancel_hash);
} else {
    log_error("Failed to cancel order: %d", cancel_result);
}
```

## Производительность

### Характеристики производительности

- **Время создания ордера**: < 15 секунд
- **Время исполнения**: < 30 секунд
- **Пропускная способность**: 100+ ордеров/сек
- **Ордербук**: До 10,000 активных ордеров
- **Время отклика**: < 5 секунд

### Оптимизации

1. **Индексирование**: Быстрый поиск ордеров по парам
2. **Кеширование**: Кеширование часто используемых данных
3. **Батчинг**: Группировка операций для оптимизации
4. **Распределение**: Распределенная обработка ордеров

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Хранение ордеров и транзакций в блокчейне
- **Wallet**: Управление балансами и переводами
- **Ledger**: Отслеживание балансов токенов
- **Crypto**: Криптографическая защита транзакций

### Примеры интеграции

```c
// Интеграция с wallet для автоматического трейдинга
void auto_exchange_based_on_price(dap_chain_wallet_t *wallet,
                                  const char *token_sell,
                                  const char *token_buy,
                                  uint256_t target_rate) {
    // Получение текущих цен
    dap_list_t *prices = dap_chain_net_srv_xchange_get_prices(net);

    // Поиск подходящего ордера
    dap_list_t *current = prices;
    while (current) {
        dap_chain_net_srv_xchange_price_t *price =
            (dap_chain_net_srv_xchange_price_t *)current->data;

        // Проверка условий
        if (strcmp(price->token_sell, token_sell) == 0 &&
            strcmp(price->token_buy, token_buy) == 0 &&
            price->rate >= target_rate) {

            // Автоматическая покупка
            dap_chain_net_srv_xchange_purchase(net, &price->order_hash,
                                             price->datoshi_sell, fee, wallet, NULL);
            break;
        }

        current = current->next;
    }

    dap_list_free(prices);
}

// Интеграция с мониторингом рынка
void monitor_exchange_activity() {
    // Получение статистики обмена
    dap_list_t *tx_list = dap_chain_net_srv_xchange_get_tx_xchange(net);

    size_t tx_count = dap_list_length(tx_list);
    uint256_t total_volume = 0;

    // Расчет общего объема
    dap_list_t *current = tx_list;
    while (current) {
        // Расчет объема транзакции
        total_volume = dap_add256(total_volume, get_tx_volume(current->data));
        current = current->next;
    }

    // Отправка метрик
    send_metric("exchange_tx_count", tx_count);
    send_metric("exchange_total_volume", dap_256_to_str(total_volume));

    dap_list_free(tx_list);
}
```

## Заключение

Exchange Service CellFrame SDK предоставляет полноценную инфраструктуру для децентрализованного обмена токенов. Сервис сочетает традиционные принципы торговых платформ с преимуществами блокчейн технологии: атомарные свопы, прозрачность транзакций и отсутствие центрального контрагента. Полная интеграция с другими компонентами CellFrame обеспечивает надежность, безопасность и высокую производительность обменных операций.
