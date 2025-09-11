# CellFrame SDK Application Database Service Module

## Обзор

**Application Database Service** - это сервис управления базами данных для децентрализованных приложений в CellFrame SDK. Сервис предоставляет высокоуровневый интерфейс для хранения, поиска и управления данными в блокчейн среде с поддержкой различных типов баз данных и индексов.

## Основные характеристики

- **Децентрализованное хранение**: Распределенное хранение данных
- **Множественные типы БД**: Поддержка различных типов баз данных
- **Индексирование**: Продвинутые возможности индексирования
- **Криптографическая защита**: Защита данных и запросов
- **ACID транзакции**: Гарантии целостности данных

## Архитектура

### Основные структуры данных

#### Конфигурация базы данных

```c
typedef struct dap_chain_net_srv_app_db_config {
    char name[DAP_DB_NAME_SIZE];                     // Имя базы данных
    dap_db_type_t type;                             // Тип базы данных
    uint32_t max_size;                              // Максимальный размер
    uint32_t shard_count;                            // Количество шардов
    bool encryption_enabled;                        // Шифрование включено
    bool backup_enabled;                            // Резервное копирование
    uint32_t retention_days;                        // Срок хранения
} dap_chain_net_srv_app_db_config_t;
```

#### Запрос к базе данных

```c
typedef struct dap_chain_net_srv_app_db_query {
    dap_hash_fast_t query_hash;                      // Хеш запроса
    dap_chain_addr_t requester_addr;                 // Адрес запрашивающего
    char database_name[DAP_DB_NAME_SIZE];            // Имя базы данных
    dap_db_query_type_t query_type;                  // Тип запроса
    char table_name[DAP_DB_TABLE_SIZE];              // Имя таблицы
    char *query_data;                                // Данные запроса
    size_t query_size;                               // Размер запроса
    uint8_t *signature;                              // Подпись
    dap_time_t timestamp;                            // Время запроса
} dap_chain_net_srv_app_db_query_t;
```

#### Результат запроса

```c
typedef struct dap_chain_net_srv_app_db_result {
    dap_hash_fast_t result_hash;                     // Хеш результата
    dap_hash_fast_t query_hash;                      // Хеш исходного запроса
    uint32_t status_code;                            // Код статуса
    char *result_data;                               // Данные результата
    size_t result_size;                              // Размер результата
    uint64_t processing_time;                        // Время обработки
    dap_time_t timestamp;                            // Время выполнения
} dap_chain_net_srv_app_db_result_t;
```

#### Основная структура сервиса

```c
typedef struct dap_chain_net_srv_app_db {
    dap_chain_net_srv_t *parent;                     // Родительский сервис
    dap_list_t *databases;                           // Список баз данных
    dap_hash_fast_t *query_cache;                    // Кеш запросов
    uint64_t total_queries;                          // Общее количество запросов
    uint64_t cache_hits;                             // Попаданий в кеш
    bool maintenance_mode;                           // Режим обслуживания
} dap_chain_net_srv_app_db_t;
```

## Типы баз данных

### По архитектуре

1. **Key-Value Store**: Хранение пар ключ-значение
2. **Document Store**: Хранение документов JSON/XML
3. **Column Family**: Колонно-ориентированные БД
4. **Graph Database**: Графовые базы данных
5. **Time Series**: Базы данных временных рядов

### По распределению

1. **Sharded**: Разделенные на шарды базы данных
2. **Replicated**: Реплицированные базы данных
3. **Distributed**: Распределенные системы
4. **Hybrid**: Комбинированные решения

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация app-db сервиса
int dap_chain_net_srv_app_db_init();

// Деинициализация app-db сервиса
void dap_chain_net_srv_app_db_deinit();
```

### Управление базами данных

```c
// Создание новой базы данных
int dap_chain_net_srv_app_db_create(
    const char *db_name,                            // Имя базы данных
    dap_db_type_t db_type,                          // Тип базы данных
    uint32_t max_size,                              // Максимальный размер
    bool encryption_enabled                         // Шифрование включено
);

// Удаление базы данных
int dap_chain_net_srv_app_db_drop(
    const char *db_name                             // Имя базы данных
);

// Получение списка баз данных
dap_list_t *dap_chain_net_srv_app_db_list();
```

### Операции с данными

```c
// Вставка данных
int dap_chain_net_srv_app_db_insert(
    const char *db_name,                            // Имя базы данных
    const char *table_name,                         // Имя таблицы
    const char *key,                                // Ключ
    const void *data,                               // Данные
    size_t data_size                                // Размер данных
);

// Получение данных
int dap_chain_net_srv_app_db_get(
    const char *db_name,                            // Имя базы данных
    const char *table_name,                         // Имя таблицы
    const char *key,                                // Ключ
    void **data,                                    // Указатель на данные
    size_t *data_size                               // Размер данных
);

// Обновление данных
int dap_chain_net_srv_app_db_update(
    const char *db_name,                            // Имя базы данных
    const char *table_name,                         // Имя таблицы
    const char *key,                                // Ключ
    const void *data,                               // Новые данные
    size_t data_size                                // Размер данных
);

// Удаление данных
int dap_chain_net_srv_app_db_delete(
    const char *db_name,                            // Имя базы данных
    const char *table_name,                         // Имя таблицы
    const char *key                                 // Ключ
);
```

### Запросы и поиск

```c
// Выполнение SQL-подобного запроса
int dap_chain_net_srv_app_db_query(
    const char *db_name,                            // Имя базы данных
    const char *query,                              // SQL запрос
    dap_chain_net_srv_app_db_result_t **result      // Результат
);

// Создание индекса
int dap_chain_net_srv_app_db_create_index(
    const char *db_name,                            // Имя базы данных
    const char *table_name,                         // Имя таблицы
    const char *column_name,                        // Имя колонки
    dap_db_index_type_t index_type                  // Тип индекса
);

// Поиск по индексу
int dap_chain_net_srv_app_db_search(
    const char *db_name,                            // Имя базы данных
    const char *table_name,                         // Имя таблицы
    const char *index_name,                         // Имя индекса
    const char *search_value,                       // Значение поиска
    dap_list_t **results                            // Результаты
);
```

### Управление транзакциями

```c
// Начало транзакции
int dap_chain_net_srv_app_db_begin_transaction(
    const char *db_name                             // Имя базы данных
);

// Фиксация транзакции
int dap_chain_net_srv_app_db_commit_transaction(
    const char *db_name                             // Имя базы данных
);

// Откат транзакции
int dap_chain_net_srv_app_db_rollback_transaction(
    const char *db_name                             // Имя базы данных
);
```

## Безопасность

### Механизмы защиты

1. **Шифрование данных**: Шифрование хранимых данных
2. **Контроль доступа**: Управление правами доступа
3. **Аудит запросов**: Логирование всех операций
4. **Целостность**: Проверка целостности данных

### Защита от угроз

- **SQL injection**: Защита от инъекций запросов
- **Data leakage**: Предотвращение утечек данных
- **Unauthorized access**: Контроль доступа к данным
- **Data tampering**: Защита от модификации данных

## Использование

### Создание и настройка базы данных

```c
#include "dap_chain_net_srv_app_db.h"

// Создание новой базы данных
int result = dap_chain_net_srv_app_db_create(
    "user_profiles",                        // Имя базы данных
    DAP_DB_TYPE_DOCUMENT,                   // Тип: документная БД
    1024 * 1024 * 1024,                     // 1GB максимум
    true                                    // Шифрование включено
);

if (result == 0) {
    log_info("Database created successfully");
} else {
    log_error("Failed to create database: %d", result);
}
```

### Работа с данными

```c
// Структура пользовательского профиля
typedef struct user_profile {
    char username[64];
    char email[128];
    uint32_t age;
    char bio[512];
} user_profile_t;

// Создание профиля пользователя
user_profile_t profile = {
    .username = "john_doe",
    .email = "john@example.com",
    .age = 30,
    .bio = "Blockchain enthusiast"
};

// Вставка данных
int insert_result = dap_chain_net_srv_app_db_insert(
    "user_profiles",                       // База данных
    "profiles",                            // Таблица
    profile.username,                      // Ключ
    &profile,                              // Данные
    sizeof(user_profile_t)                 // Размер
);

if (insert_result == 0) {
    log_info("Profile inserted successfully");
}
```

### Выполнение запросов

```c
// Получение данных
user_profile_t *retrieved_profile = NULL;
size_t data_size = 0;

int get_result = dap_chain_net_srv_app_db_get(
    "user_profiles",                       // База данных
    "profiles",                            // Таблица
    "john_doe",                            // Ключ
    (void **)&retrieved_profile,           // Данные
    &data_size                             // Размер
);

if (get_result == 0 && retrieved_profile) {
    log_info("Retrieved profile: %s (%s)",
             retrieved_profile->username,
             retrieved_profile->email);
    free(retrieved_profile);
}

// SQL-подобный запрос
const char *sql_query = "SELECT * FROM profiles WHERE age > 25";
dap_chain_net_srv_app_db_result_t *query_result = NULL;

int query_exec_result = dap_chain_net_srv_app_db_query(
    "user_profiles",                       // База данных
    sql_query,                             // SQL запрос
    &query_result                         // Результат
);

if (query_exec_result == 0 && query_result) {
    log_info("Query executed successfully, results: %zu bytes",
             query_result->result_size);
    free(query_result->result_data);
    free(query_result);
}
```

### Работа с транзакциями

```c
// Начало транзакции
int tx_begin = dap_chain_net_srv_app_db_begin_transaction("user_profiles");

if (tx_begin == 0) {
    // Вставка нескольких записей
    dap_chain_net_srv_app_db_insert("user_profiles", "profiles", "user1", data1, size1);
    dap_chain_net_srv_app_db_insert("user_profiles", "profiles", "user2", data2, size2);
    dap_chain_net_srv_app_db_update("user_profiles", "profiles", "user3", data3, size3);

    // Фиксация транзакции
    int tx_commit = dap_chain_net_srv_app_db_commit_transaction("user_profiles");

    if (tx_commit == 0) {
        log_info("Transaction committed successfully");
    } else {
        log_error("Transaction commit failed");
        // Откат транзакции
        dap_chain_net_srv_app_db_rollback_transaction("user_profiles");
    }
} else {
    log_error("Failed to begin transaction");
}
```

## Производительность

### Характеристики производительности

- **Время вставки**: < 10 мс для одиночной записи
- **Время чтения**: < 5 мс для одиночной записи
- **Пропускная способность**: 1000+ операций/сек
- **Кеш эффективность**: > 80% попаданий
- **Время запросов**: < 100 мс для сложных запросов

### Оптимизации

1. **Индексирование**: Автоматическое создание индексов
2. **Кеширование**: Многоуровневое кеширование
3. **Шардинг**: Автоматическое распределение данных
4. **Репликация**: Синхронная и асинхронная репликация

## Интеграция

### Совместная работа с другими модулями

- **Chain**: Хранение метаданных в блокчейне
- **Crypto**: Шифрование данных и запросов
- **Net**: Сетевая репликация данных
- **Wallet**: Управление доступом к данным

### Примеры интеграции

```c
// Интеграция с приложением для управления пользователями
class UserManager {
private:
    const char *db_name = "user_app_db";

public:
    bool createUser(const char *username, const char *email) {
        // Проверка существования пользователя
        void *existing_data = NULL;
        size_t data_size = 0;

        if (dap_chain_net_srv_app_db_get(db_name, "users", username,
                                       &existing_data, &data_size) == 0) {
            free(existing_data);
            return false; // Пользователь уже существует
        }

        // Создание нового пользователя
        user_data_t user = {username, email, time(NULL)};
        return dap_chain_net_srv_app_db_insert(db_name, "users", username,
                                             &user, sizeof(user_data_t)) == 0;
    }

    user_data_t *getUser(const char *username) {
        user_data_t *user = NULL;
        size_t data_size = 0;

        if (dap_chain_net_srv_app_db_get(db_name, "users", username,
                                       (void **)&user, &data_size) == 0) {
            return user;
        }
        return NULL;
    }
};

// Интеграция с аналитикой
void collectDatabaseMetrics() {
    // Получение статистики базы данных
    dap_list_t *databases = dap_chain_net_srv_app_db_list();

    dap_list_t *current = databases;
    while (current) {
        const char *db_name = (const char *)current->data;

        // Получение метрик производительности
        uint64_t query_count = get_db_query_count(db_name);
        uint64_t cache_hit_rate = get_db_cache_hit_rate(db_name);
        uint64_t avg_response_time = get_db_avg_response_time(db_name);

        // Отправка метрик в систему мониторинга
        send_metric("db_queries_total", db_name, query_count);
        send_metric("db_cache_hit_rate", db_name, cache_hit_rate);
        send_metric("db_avg_response_time", db_name, avg_response_time);

        current = current->next;
    }

    dap_list_free(databases);
}
```

## Заключение

Application Database Service CellFrame SDK предоставляет мощную и гибкую инфраструктуру для управления данными в децентрализованных приложениях. Сервис сочетает традиционные возможности баз данных с преимуществами блокчейн технологии: неизменность, прозрачность и децентрализацию. Полная интеграция с другими компонентами CellFrame обеспечивает высокую производительность, безопасность и надежность хранения данных.
