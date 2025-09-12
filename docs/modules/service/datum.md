# CellFrame SDK Datum Service Module

## Обзор

**Datum Service** - это сервис управления данными и токенами в CellFrame SDK. Сервис предоставляет инфраструктуру для создания, управления и обмена различными типами активов в блокчейн сети, включая токены, NFT, сертификаты и другие формы цифровых активов.

## Основные характеристики

- **Множественные типы активов**: Поддержка различных типов токенов
- **Управление жизненным циклом**: Создание, передача, уничтожение активов
- **Метаданные**: Богатые метаданные для активов
- **Валидация**: Автоматическая валидация операций
- **Интеграция с рынком**: Взаимодействие с торговыми сервисами

## Архитектура

### Основные структуры данных

#### Определение datum

```c
typedef struct dap_chain_datum {
    dap_chain_datum_type_t type;                     // Тип datum
    uint64_t version;                                // Версия
    uint64_t ts_create;                              // Время создания
    uint64_t ts_expire;                              // Время истечения
    dap_chain_hash_fast_t hash;                      // Хеш datum
    union {
        dap_chain_datum_tx_t tx;                     // Транзакция
        dap_chain_datum_token_t token;               // Токен
        dap_chain_datum_token_emission_t emission;   // Эмиссия токена
        dap_chain_datum_decree_t decree;             // Декрет
        dap_chain_datum_anchor_t anchor;             // Якорь
        dap_chain_datum_voting_t voting;             // Голосование
    } data;                                          // Данные
} DAP_ALIGN_PACKED dap_chain_datum_t;
```

#### Токен

```c
typedef struct dap_chain_datum_token {
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];         // Тикер токена
    char name[DAP_CHAIN_TOKEN_NAME_SIZE_MAX];        // Имя токена
    uint256_t total_supply;                          // Общее предложение
    uint256_t total_supply_max;                      // Максимальное предложение
    uint16_t decimals;                               // Десятичные знаки
    uint16_t flags;                                  // Флаги
    dap_chain_addr_t owner_addr;                     // Адрес владельца
    char description[DAP_CHAIN_TOKEN_DESCRIPTION_SIZE_MAX]; // Описание
} DAP_ALIGN_PACKED dap_chain_datum_token_t;
```

#### Эмиссия токена

```c
typedef struct dap_chain_datum_token_emission {
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];         // Тикер токена
    uint256_t value;                                 // Значение эмиссии
    uint64_t type;                                   // Тип эмиссии
    uint64_t version;                                // Версия
    dap_chain_addr_t address;                        // Адрес назначения
    char *data;                                      // Дополнительные данные
} DAP_ALIGN_PACKED dap_chain_datum_token_emission_t;
```

#### Основная структура сервиса

```c
typedef struct dap_chain_net_srv_datum {
    dap_chain_net_srv_t *parent;                     // Родительский сервис
    dap_hash_fast_t *datum_cache;                    // Кеш datum'ов
    uint64_t total_datums;                           // Общее количество
    uint64_t cache_hits;                             // Попаданий в кеш
    bool validation_enabled;                         // Валидация включена
    dap_list_t *active_emissions;                    // Активные эмиссии
} dap_chain_net_srv_datum_t;
```

## Типы Datum

### Основные типы

1. **DATUM_TYPE_TX**: Транзакции - переводы активов
2. **DATUM_TYPE_TOKEN**: Токены - определение токенов
3. **DATUM_TYPE_TOKEN_EMISSION**: Эмиссия токенов - выпуск токенов
4. **DATUM_TYPE_DECREE**: Декреты - управляющие решения
5. **DATUM_TYPE_ANCHOR**: Якоря - привязка к внешним данным
6. **DATUM_TYPE_VOTING**: Голосования - демократические решения

### Специализированные типы

1. **DATUM_TYPE_NFT**: NFT токены
2. **DATUM_TYPE_CONTRACT**: Смарт-контракты
3. **DATUM_TYPE_CERTIFICATE**: Сертификаты
4. **DATUM_TYPE_BADGE**: Значки и достижения
5. **DATUM_TYPE_LICENSE**: Лицензии

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация datum сервиса
int dap_chain_net_srv_datum_init();

// Деинициализация datum сервиса
void dap_chain_net_srv_datum_deinit();
```

### Управление токенами

```c
// Создание нового токена
int dap_chain_net_srv_datum_token_create(
    const char *ticker,                              // Тикер токена
    const char *name,                                // Имя токена
    uint256_t total_supply,                          // Общее предложение
    uint16_t decimals,                               // Десятичные знаки
    dap_chain_wallet_t *wallet,                      // Кошелек создателя
    char **token_hash                               // Хеш токена
);

// Эмиссия токенов
int dap_chain_net_srv_datum_token_emission(
    const char *ticker,                              // Тикер токена
    uint256_t amount,                                // Сумма эмиссии
    dap_chain_addr_t recipient_addr,                 // Адрес получателя
    dap_chain_wallet_t *wallet,                      // Кошелек эмитента
    char **emission_hash                            // Хеш эмиссии
);

// Сжигание токенов
int dap_chain_net_srv_datum_token_burn(
    const char *ticker,                              // Тикер токена
    uint256_t amount,                                // Сумма сжигания
    dap_chain_wallet_t *wallet,                      // Кошелек владельца
    char **burn_hash                                // Хеш сжигания
);
```

### Операции с datum

```c
// Создание datum
dap_chain_datum_t *dap_chain_net_srv_datum_create(
    dap_chain_datum_type_t type,                     // Тип datum
    const void *data,                                // Данные
    size_t data_size                                 // Размер данных
);

// Валидация datum
bool dap_chain_net_srv_datum_validate(
    dap_chain_datum_t *datum                         // Datum для валидации
);

// Подписание datum
int dap_chain_net_srv_datum_sign(
    dap_chain_datum_t *datum,                        // Datum для подписи
    dap_chain_wallet_t *wallet                       // Кошелек для подписи
);

// Публикация datum в сеть
int dap_chain_net_srv_datum_publish(
    dap_chain_datum_t *datum,                        // Datum для публикации
    dap_chain_net_t *net                             // Сеть
);
```

### Получение информации

```c
// Получение информации о токене
dap_chain_datum_token_t *dap_chain_net_srv_datum_token_get_info(
    const char *ticker                               // Тикер токена
);

// Получение баланса токена
uint256_t dap_chain_net_srv_datum_token_get_balance(
    const char *ticker,                              // Тикер токена
    dap_chain_addr_t addr                            // Адрес
);

// Получение истории операций
dap_list_t *dap_chain_net_srv_datum_get_history(
    const char *ticker,                              // Тикер токена
    dap_chain_addr_t addr                            // Адрес
);

// Получение списка всех токенов
dap_list_t *dap_chain_net_srv_datum_token_list();
```

### Управление активами

```c
// Передача токенов
int dap_chain_net_srv_datum_token_transfer(
    const char *ticker,                              // Тикер токена
    uint256_t amount,                                // Сумма
    dap_chain_addr_t recipient_addr,                 // Адрес получателя
    dap_chain_wallet_t *wallet,                      // Кошелек отправителя
    char **transfer_hash                            // Хеш перевода
);

// Заморозка токенов
int dap_chain_net_srv_datum_token_freeze(
    const char *ticker,                              // Тикер токена
    uint256_t amount,                                // Сумма
    dap_chain_wallet_t *wallet,                      // Кошелек владельца
    char **freeze_hash                              // Хеш заморозки
);

// Разморозка токенов
int dap_chain_net_srv_datum_token_unfreeze(
    const char *ticker,                              // Тикер токена
    uint256_t amount,                                // Сумма
    dap_chain_wallet_t *wallet,                      // Кошелек владельца
    char **unfreeze_hash                            // Хеш разморозки
);
```

## Безопасность

### Механизмы защиты

1. **Криптографическая подпись**: Все операции подписываются
2. **Валидация данных**: Автоматическая проверка корректности
3. **Контроль доступа**: Управление правами на операции
4. **Аудит**: Полная traceability всех операций

### Защита от угроз

- **Double spending**: Предотвращение двойного расходования
- **Token forgery**: Защита от подделки токенов
- **Unauthorized minting**: Контроль за эмиссией
- **Data tampering**: Защита от модификации данных

## Использование

### Создание токена

```c
#include "dap_chain_net_srv_datum.h"

// Параметры токена
const char *ticker = "MYTOKEN";
const char *name = "My Custom Token";
uint256_t total_supply = dap_chain_coins_to_balance("1000000.0"); // 1M токенов
uint16_t decimals = 18; // 18 десятичных знаков

// Создание токена
char *token_hash = NULL;
int result = dap_chain_net_srv_datum_token_create(
    ticker,                                  // Тикер
    name,                                    // Имя
    total_supply,                            // Общее предложение
    decimals,                                // Десятичные знаки
    wallet,                                  // Кошелек создателя
    &token_hash                             // Хеш токена
);

if (result == 0) {
    log_info("Token created successfully: %s", token_hash);
    free(token_hash);
} else {
    log_error("Failed to create token: %d", result);
}
```

### Эмиссия токенов

```c
// Эмиссия дополнительных токенов
uint256_t emission_amount = dap_chain_coins_to_balance("50000.0");
dap_chain_addr_t recipient_addr = get_recipient_address();

// Эмиссия токенов
char *emission_hash = NULL;
int emission_result = dap_chain_net_srv_datum_token_emission(
    ticker,                                  // Тикер токена
    emission_amount,                         // Сумма эмиссии
    recipient_addr,                          // Адрес получателя
    wallet,                                  // Кошелек эмитента
    &emission_hash                          // Хеш эмиссии
);

if (emission_result == 0) {
    log_info("Tokens emitted successfully: %s", emission_hash);
    free(emission_hash);
} else {
    log_error("Failed to emit tokens: %d", emission_result);
}
```

### Передача токенов

```c
// Передача токенов другому адресу
uint256_t transfer_amount = dap_chain_coins_to_balance("100.0");
dap_chain_addr_t recipient_addr = get_recipient_address();

// Передача токенов
char *transfer_hash = NULL;
int transfer_result = dap_chain_net_srv_datum_token_transfer(
    ticker,                                  // Тикер токена
    transfer_amount,                         // Сумма
    recipient_addr,                          // Адрес получателя
    wallet,                                  // Кошелек отправителя
    &transfer_hash                          // Хеш перевода
);

if (transfer_result == 0) {
    log_info("Tokens transferred successfully: %s", transfer_hash);
    free(transfer_hash);
} else {
    log_error("Failed to transfer tokens: %d", transfer_result);
}
```

### Получение информации о токене

```c
// Получение информации о токене
dap_chain_datum_token_t *token_info = dap_chain_net_srv_datum_token_get_info(ticker);

if (token_info) {
    log_info("Token Information:");
    log_info("Name: %s", token_info->name);
    log_info("Total Supply: %s", dap_256_to_str(token_info->total_supply));
    log_info("Decimals: %u", token_info->decimals);
    log_info("Owner: %s", dap_chain_addr_to_str_static(&token_info->owner_addr));

    free(token_info);
}

// Получение баланса
uint256_t balance = dap_chain_net_srv_datum_token_get_balance(ticker, wallet->addr);
log_info("Token balance: %s", dap_256_to_str(balance));
```

### Работа с datum

```c
// Создание кастомного datum
custom_datum_data_t custom_data = {
    .field1 = "value1",
    .field2 = 42,
    .timestamp = time(NULL)
};

// Создание datum
dap_chain_datum_t *datum = dap_chain_net_srv_datum_create(
    DATUM_TYPE_CUSTOM,                      // Тип datum
    &custom_data,                           // Данные
    sizeof(custom_datum_data_t)             // Размер
);

// Подписание datum
if (dap_chain_net_srv_datum_sign(datum, wallet) == 0) {
    log_info("Datum signed successfully");

    // Публикация в сеть
    if (dap_chain_net_srv_datum_publish(datum, net) == 0) {
        log_info("Datum published successfully");
    }
}

// Валидация datum
if (dap_chain_net_srv_datum_validate(datum)) {
    log_info("Datum is valid");
} else {
    log_error("Datum validation failed");
}

// Освобождение памяти
dap_chain_datum_free(datum);
```

## Производительность

### Характеристики производительности

- **Время создания токена**: < 30 секунд
- **Время перевода**: < 10 секунд
- **Пропускная способность**: 100+ операций/сек
- **Время валидации**: < 1 секунда
- **Кеш эффективность**: > 85% попаданий

### Оптимизации

1. **Индексирование**: Быстрый поиск по адресам и токенам
2. **Кеширование**: Кеширование часто используемых данных
3. **Батчинг**: Группировка операций для оптимизации
4. **Предварительная валидация**: Проверка корректности до выполнения

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Хранение datum'ов в блокчейне
- **Wallet**: Управление токенами и активами
- **Exchange**: Торговля токенами
- **Voting**: Голосования с использованием токенов

### Примеры интеграции

```c
// Интеграция с wallet для управления портфелем
class TokenPortfolio {
private:
    dap_chain_wallet_t *wallet;
    const char *supported_tokens[10];

public:
    void updatePortfolio() {
        log_info("Portfolio Update:");

        for (int i = 0; supported_tokens[i] != NULL; i++) {
            const char *ticker = supported_tokens[i];
            uint256_t balance = dap_chain_net_srv_datum_token_get_balance(
                ticker, wallet->addr);

            if (dap_is_zero256(balance) == false) {
                log_info("%s: %s", ticker, dap_256_to_str(balance));
            }
        }
    }

    bool transferToken(const char *ticker, uint256_t amount,
                      dap_chain_addr_t recipient) {
        char *transfer_hash = NULL;
        int result = dap_chain_net_srv_datum_token_transfer(
            ticker, amount, recipient, wallet, &transfer_hash);

        if (result == 0) {
            log_info("Transfer completed: %s", transfer_hash);
            free(transfer_hash);
            return true;
        }
        return false;
    }
};

// Интеграция с рыночной аналитикой
void analyzeTokenMarket() {
    // Получение списка всех токенов
    dap_list_t *tokens = dap_chain_net_srv_datum_token_list();

    dap_list_t *current = tokens;
    while (current) {
        const char *ticker = (const char *)current->data;

        // Получение статистики токена
        uint256_t total_supply = get_token_total_supply(ticker);
        uint64_t holder_count = get_token_holder_count(ticker);
        uint256_t market_cap = get_token_market_cap(ticker);

        // Анализ
        if (holder_count > 1000) {
            log_info("Popular token: %s (holders: %llu, cap: %s)",
                    ticker, holder_count, dap_256_to_str(market_cap));
        }

        current = current->next;
    }

    dap_list_free(tokens);
}
```

## Заключение

Datum Service CellFrame SDK предоставляет всестороннюю инфраструктуру для управления цифровыми активами в блокчейн сети. Сервис поддерживает различные типы активов и операций, обеспечивая высокий уровень безопасности, производительности и гибкости. Полная интеграция с другими компонентами CellFrame позволяет создавать сложные децентрализованные приложения с богатыми возможностями управления активами.
