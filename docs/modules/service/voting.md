# CellFrame SDK Voting Service Module

## Обзор

**Voting Service** - это сервис голосования в CellFrame SDK, обеспечивающий децентрализованный механизм принятия решений в сети. Сервис позволяет создавать голосования, управлять вариантами ответов, собирать голоса участников и определять результаты. Поддерживает как простые бинарные голосования, так и сложные мультивариантные опросы с различными правилами.

## Основные характеристики

- **Децентрализованное голосование**: Полностью децентрализованный процесс
- **Гибкие правила**: Настраиваемые параметры голосования
- **Криптографическая защита**: Защита целостности голосов
- **Прозрачность**: Полная traceability всех голосов
- **Множественные форматы**: Поддержка различных типов голосований

## Архитектура

### Основные структуры данных

#### Информация о варианте ответа

```c
typedef struct dap_chain_net_vote_info_option {
    uint64_t option_idx;                    // Индекс варианта
    uint64_t votes_count;                   // Количество голосов
    uint256_t weight;                       // Вес голосов
    uint64_t description_size;              // Размер описания
    char *description;                      // Описание варианта
    dap_list_t *hashes_tx_votes;            // Хеши транзакций голосов
} dap_chain_net_vote_info_option_t;
```

#### Информация о голосовании

```c
typedef struct dap_chain_net_vote_info {
    dap_hash_fast_t hash;                   // Хеш голосования
    dap_chain_net_id_t net_id;              // ID сети
    bool is_expired;                        // Истекло ли время
    dap_time_t expired;                     // Время истечения
    bool is_max_count_votes;                // Достигнуто ли максимальное количество
    uint64_t max_count_votes;               // Максимальное количество голосов

    bool is_changing_allowed;               // Разрешено ли менять голос
    bool is_delegate_key_required;          // Требуется ли делегированный ключ

    struct {
        size_t question_size;                // Размер вопроса
        char *question_str;                  // Текст вопроса
    } question;                             // Вопрос голосования

    struct {
        uint64_t count_option;               // Количество вариантов
        dap_chain_net_vote_info_option_t **options; // Массив вариантов
    } options;                              // Варианты ответов
} dap_chain_net_vote_info_t;
```

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация voting сервиса
int dap_chain_net_srv_voting_init();

// Деинициализация voting сервиса
void dap_chain_net_srv_voting_deinit();
```

### Создание голосования

```c
// Создание нового голосования
int dap_chain_net_vote_create(
    const char *a_question,                  // Вопрос голосования
    dap_list_t *a_options,                   // Список вариантов ответов
    dap_time_t a_expire_vote,                // Время истечения
    uint64_t a_max_vote,                     // Максимальное количество голосов
    uint256_t a_fee,                         // Комиссия
    bool a_delegated_key_required,           // Требуется ли делегированный ключ
    bool a_vote_changing_allowed,            // Разрешено ли менять голос
    dap_chain_wallet_t *a_wallet,            // Кошелек создателя
    dap_chain_net_t *a_net,                  // Сеть
    const char *a_token_ticker,              // Тикер токена
    const char *a_hash_out_type,             // Тип хеша выхода
    char **a_hash_output                     // Выходной хеш
);
```

### Голосование

```c
// Голосование в существующем опросе
int dap_chain_net_vote_voting(
    dap_cert_t *a_cert,                      // Сертификат голосующего
    uint256_t a_fee,                         // Комиссия за голос
    dap_chain_wallet_t *a_wallet,            // Кошелек голосующего
    dap_hash_fast_t a_hash,                  // Хеш голосования
    uint64_t a_option_idx,                   // Индекс выбранного варианта
    dap_chain_net_t *a_net,                  // Сеть
    const char *a_hash_out_type,             // Тип хеша выхода
    char **a_hash_tx_out                     // Хеш транзакции выхода
);
```

### Получение результатов

```c
// Получение результатов голосования
uint64_t* dap_chain_net_voting_get_result(
    dap_ledger_t* a_ledger,                  // Леджер
    dap_chain_hash_fast_t* a_voting_hash     // Хеш голосования
);
```

### Управление голосованиями

```c
// Получение списка всех голосований в сети
dap_list_t *dap_chain_net_vote_list(
    dap_chain_net_t *a_net                   // Сеть
);

// Получение детальной информации о голосовании
dap_chain_net_vote_info_t *dap_chain_net_vote_extract_info(
    dap_chain_net_t *a_net,                  // Сеть
    dap_hash_fast_t *a_vote_hash             // Хеш голосования
);

// Освобождение памяти информации о голосовании
void dap_chain_net_vote_info_free(
    dap_chain_net_vote_info_t *a_info        // Информация для освобождения
);
```

### Отмена голосования

```c
// Отмена голосования создателем
dap_chain_net_vote_cancel_result_t dap_chain_net_vote_cancel(
    json_object *a_json_reply,               // JSON ответ
    uint256_t a_fee,                         // Комиссия
    dap_chain_wallet_t *a_wallet,            // Кошелек
    dap_hash_fast_t *a_voting_hash,          // Хеш голосования
    dap_chain_net_t *a_net,                  // Сеть
    const char *a_hash_out_type,             // Тип хеша выхода
    char **a_hash_tx_out                     // Хеш транзакции выхода
);
```

## Типы ошибок

### Ошибки создания голосования

| Код | Константа | Описание |
|-----|-----------|----------|
| 0 | `DAP_CHAIN_NET_VOTE_CREATE_OK` | Успешное создание |
| 1 | `DAP_CHAIN_NET_VOTE_CREATE_LENGTH_QUESTION_OVERSIZE_MAX` | Вопрос слишком длинный |
| 2 | `DAP_CHAIN_NET_VOTE_CREATE_COUNT_OPTION_OVERSIZE_MAX` | Слишком много вариантов |
| 3 | `DAP_CHAIN_NET_VOTE_CREATE_FEE_IS_ZERO` | Нулевая комиссия |
| 4 | `DAP_CHAIN_NET_VOTE_CREATE_SOURCE_ADDRESS_IS_INVALID` | Неверный адрес источника |

### Ошибки голосования

| Код | Константа | Описание |
|-----|-----------|----------|
| 0 | `DAP_CHAIN_NET_VOTE_VOTING_OK` | Успешное голосование |
| 1 | `DAP_CHAIN_NET_VOTE_VOTING_CAN_NOT_FIND_VOTE` | Голосование не найдено |
| 2 | `DAP_CHAIN_NET_VOTE_VOTING_THIS_VOTING_HAVE_MAX_VALUE_VOTES` | Достигнуто максимум голосов |
| 3 | `DAP_CHAIN_NET_VOTE_VOTING_ALREADY_EXPIRED` | Голосование истекло |

### Ошибки отмены голосования

| Код | Константа | Описание |
|-----|-----------|----------|
| 0 | `DAP_CHAIN_NET_VOTE_CANCEL_OK` | Успешная отмена |
| 1 | `DAP_CHAIN_NET_VOTE_CANCEL_HASH_NOT_FOUND` | Хеш не найден |
| 2 | `DAP_CHAIN_NET_VOTE_CANCEL_VOTING_NOT_ACTIVE` | Голосование не активно |

## Принцип работы

### 1. Создание голосования

1. **Формулировка вопроса**: Создание четкого вопроса голосования
2. **Определение вариантов**: Создание списка возможных ответов
3. **Настройка параметров**: Установка правил и ограничений
4. **Публикация**: Создание транзакции голосования в блокчейне

### 2. Процесс голосования

1. **Аутентификация**: Проверка прав голосующего
2. **Выбор варианта**: Выбор одного из предложенных вариантов
3. **Подписание**: Криптографическое подписание голоса
4. **Отправка**: Отправка голоса в блокчейн

### 3. Подсчет результатов

1. **Сбор голосов**: Накопление всех голосов до истечения срока
2. **Валидация**: Проверка корректности всех голосов
3. **Подсчет**: Вычисление результатов голосования
4. **Публикация**: Публикация окончательных результатов

### 4. Управление жизненным циклом

- **Создание**: Инициация нового голосования
- **Активная фаза**: Сбор голосов участников
- **Завершение**: Подведение итогов и публикация результатов
- **Архивирование**: Сохранение результатов для истории

## Типы голосований

### По количеству вариантов

1. **Бинарное**: Да/Нет, За/Против
2. **Множественный выбор**: Один вариант из многих
3. **Ранжирование**: Упорядочивание вариантов по предпочтению
4. **Бюджетное**: Распределение ограниченного ресурса

### По правилам участия

1. **Открытое**: Любой участник сети может голосовать
2. **Ограниченное**: Только держатели определенного токена
3. **Делегированное**: Требуется делегированный ключ
4. **Кворумное**: Требуется минимальное количество участников

### По времени проведения

1. **Фиксированное время**: Строго определенные сроки
2. **Динамическое**: Завершается при достижении условий
3. **Многоэтапное**: Несколько раундов голосования

## Безопасность

### Криптографическая защита

1. **Цифровые подписи**: Все голоса криптографически подписаны
2. **Неизменность**: Голоса нельзя изменить после отправки
3. **Анонимность**: Опциональная анонимность голосования
4. **Верифицируемость**: Возможность проверки корректности подсчета

### Защита от атак

- **Double voting**: Предотвращение повторного голосования
- **Sybil attacks**: Защита через экономические барьеры
- **Timing attacks**: Защита от атак на временные рамки
- **Censorship**: Децентрализованная природа предотвращает цензуру

## Использование

### Создание простого голосования

```c
#include "dap_chain_net_srv_voting.h"

// Параметры голосования
const char *question = "Should we increase the block size to 2MB?";
dap_list_t *options = NULL;

// Добавление вариантов
options = dap_list_append(options, "Yes, increase to 2MB");
options = dap_list_append(options, "No, keep current size");
options = dap_list_append(options, "Increase to 4MB instead");

// Создание голосования
char *vote_hash = NULL;
int result = dap_chain_net_vote_create(
    question,                               // Вопрос
    options,                                // Варианты
    time(NULL) + 604800,                    // Неделя на голосование
    1000,                                   // Максимум 1000 голосов
    dap_chain_coins_to_balance("0.01"),     // Комиссия 0.01 токена
    false,                                  // Без делегированного ключа
    true,                                   // Разрешено менять голос
    wallet,                                 // Кошелек создателя
    net,                                    // Сеть
    "CELL",                                 // Тикер токена
    "hex",                                  // Тип хеша
    &vote_hash                             // Выходной хеш
);

if (result == DAP_CHAIN_NET_VOTE_CREATE_OK) {
    log_info("Vote created successfully: %s", vote_hash);
    free(vote_hash);
} else {
    log_error("Failed to create vote: %d", result);
}

// Освобождение ресурсов
dap_list_free(options);
```

### Голосование в существующем опросе

```c
// Хеш голосования
dap_hash_fast_t vote_hash;
dap_hash_fast_from_str(&vote_hash, "0123456789abcdef...");

// Выбор варианта (индекс 0 - первый вариант)
uint64_t selected_option = 0;

// Голосование
char *tx_hash = NULL;
int vote_result = dap_chain_net_vote_voting(
    cert,                                   // Сертификат
    dap_chain_coins_to_balance("0.001"),    // Комиссия за голос
    wallet,                                 // Кошелек голосующего
    vote_hash,                              // Хеш голосования
    selected_option,                        // Выбранный вариант
    net,                                    // Сеть
    "hex",                                  // Тип хеша
    &tx_hash                               // Хеш транзакции
);

if (vote_result == DAP_CHAIN_NET_VOTE_VOTING_OK) {
    log_info("Vote submitted successfully: %s", tx_hash);
    free(tx_hash);
} else {
    log_error("Failed to submit vote: %d", vote_result);
}
```

### Получение результатов голосования

```c
// Получение результатов
uint64_t *results = dap_chain_net_voting_get_result(ledger, &vote_hash);

if (results) {
    log_info("Voting results:");
    for (uint64_t i = 0; i < options_count; i++) {
        log_info("Option %llu: %llu votes", i, results[i]);
    }
    free(results);
} else {
    log_error("Failed to get voting results");
}
```

### Получение списка голосований

```c
// Получение всех активных голосований
dap_list_t *votes_list = dap_chain_net_vote_list(net);

// Обработка списка
dap_list_t *current = votes_list;
while (current) {
    dap_chain_net_vote_info_t *vote_info = (dap_chain_net_vote_info_t *)current->data;

    log_info("Vote: %s", vote_info->question.question_str);
    log_info("Hash: %s", dap_hash_fast_to_str_static(&vote_info->hash));
    log_info("Expires: %llu", vote_info->expired);

    // Получение детальной информации
    dap_chain_net_vote_info_t *detailed_info =
        dap_chain_net_vote_extract_info(net, &vote_info->hash);

    if (detailed_info) {
        log_info("Options count: %llu", detailed_info->options.count_option);
        for (uint64_t i = 0; i < detailed_info->options.count_option; i++) {
            log_info("Option %llu: %s (%llu votes)",
                    i,
                    detailed_info->options.options[i]->description,
                    detailed_info->options.options[i]->votes_count);
        }
        dap_chain_net_vote_info_free(detailed_info);
    }

    current = current->next;
}

// Освобождение списка
dap_list_free(votes_list);
```

## Производительность

### Характеристики производительности

- **Время создания**: < 30 секунд
- **Время голосования**: < 10 секунд
- **Максимум вариантов**: 100 на голосование
- **Максимум голосов**: 10,000 на голосование
- **Время подсчета**: < 5 секунд

### Оптимизации

1. **Индексирование**: Быстрый поиск по хешам голосований
2. **Кеширование**: Кеширование результатов подсчета
3. **Батчинг**: Группировка операций для оптимизации
4. **Распределение**: Распределенная обработка голосов

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Хранение голосований и результатов в блокчейне
- **Wallet**: Управление балансами для комиссий
- **Stake**: Делегированное голосование на основе ставок
- **Consensus**: Валидация результатов голосования

### Примеры интеграции

```c
// Интеграция с staking для взвешенного голосования
uint256_t get_vote_weight(dap_chain_addr_t *voter_addr) {
    // Получение веса голоса на основе ставки
    dap_chain_net_srv_stake_item_t *stake =
        dap_chain_net_srv_stake_check_pkey_hash(net_id, voter_addr);

    return stake ? stake->value : 0;
}

// Интеграция с wallet для автоматического голосования
void auto_vote_based_on_balance(dap_chain_wallet_t *wallet, dap_hash_fast_t vote_hash) {
    uint256_t balance = dap_chain_wallet_get_balance(wallet);

    // Автоматическое голосование на основе баланса
    if (balance > dap_chain_coins_to_balance("1000")) {
        // Голосовать за увеличение лимитов
        dap_chain_net_vote_voting(NULL, fee, wallet, vote_hash, 0, net, "hex", NULL);
    } else {
        // Голосовать против
        dap_chain_net_vote_voting(NULL, fee, wallet, vote_hash, 1, net, "hex", NULL);
    }
}
```

## Заключение

Voting Service CellFrame SDK предоставляет мощную и гибкую платформу для децентрализованного принятия решений. Сервис поддерживает различные типы голосований, обеспечивает криптографическую защиту и прозрачность процесса. Полная интеграция с блокчейн инфраструктурой гарантирует неизменность результатов и защиту от мошенничества. Модульная архитектура позволяет легко адаптировать сервис под специфические требования различных приложений и организаций.
