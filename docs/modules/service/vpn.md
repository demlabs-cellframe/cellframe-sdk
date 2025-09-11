# CellFrame SDK VPN Service Module

## Обзор

**VPN Service** - это специализированный сетевой сервис CellFrame SDK, обеспечивающий безопасное создание виртуальных частных сетей между узлами блокчейн сети. Сервис предоставляет инфраструктуру для защищенного туннелирования трафика через блокчейн сеть с поддержкой IPv4 адресации и автоматического управления соединениями.

## Основные характеристики

- **Сетевая безопасность**: Шифрованное туннелирование трафика
- **IPv4 поддержка**: Автоматическое назначение IP адресов клиентам
- **Многопользовательский режим**: Поддержка множественных одновременных подключений
- **Динамическое управление**: Автоматическое управление соединениями и ресурсами
- **Интеграция с блокчейн**: Полная интеграция с механизмом транзакций CellFrame

## Архитектура

### Основные компоненты

#### Структура VPN пакета

```c
typedef struct dap_stream_ch_vpn_pkt {
    struct {
        int sock_id;                    // ID сокета клиента
        uint32_t op_code;              // Код операции
        uint32_t usage_id;             // ID использования (для мультисети)
        union {
            struct { // Операция подключения L4
                uint32_t addr_size;
                uint16_t port;         // Порт (выровнено до 4 байт)
            } op_connect;
            struct { // Передача данных
                uint32_t data_size;    // Размер данных (выровнено до 8 байт)
            } op_data;
            struct { // Проблема
                uint32_t code;         // Код проблемы (выровнено до 8 байт)
            } op_problem;
            struct {
                uint64_t op_data_raw;  // Сырые данные операции (выровнено до 8 байт)
            } raw;                    // Сырой доступ к байтам OP
        };
    } header;                         // Заголовок пакета
    byte_t data[];                   // Бинарные данные
} dap_stream_ch_vpn_pkt_t;
```

#### Структура VPN туннельного сокета

```c
typedef struct dap_chain_net_srv_vpn_tun_socket {
    uint8_t worker_id;                           // ID воркера
    dap_worker_t * worker;                       // Воркер
    dap_events_socket_t * es;                    // Событийный сокет
    dap_chain_net_srv_ch_vpn_info_t * clients;   // Удаленные клиенты по адресу назначения
    dap_events_socket_t ** queue_tun_msg_input;  // Очередь входящих TUN сообщений
    size_t buf_size_aux;                         // Вспомогательный размер буфера
} dap_chain_net_srv_vpn_tun_socket_t;
```

#### VPN канал

```c
typedef struct dap_chain_net_srv_ch_vpn {
    uint32_t usage_id;                           // ID использования
    dap_chain_net_srv_t* net_srv;                // Сетевой сервис
    bool is_allowed;                             // Разрешено ли подключение
    dap_chain_net_srv_vpn_tun_socket_t * tun_socket; // TUN сокет

    struct in_addr addr_ipv4;                     // IPv4 адрес
    dap_stream_ch_t * ch;                         // Потоковый канал
    UT_hash_handle hh;                            // Хеш-таблица
} dap_chain_net_srv_ch_vpn_t;
```

## Протокол VPN

### Коды операций

VPN сервис использует следующие коды операций для управления соединениями:

| Код операции | Константа | Описание |
|-------------|-----------|----------|
| `0x000000a9` | `VPN_PACKET_OP_CODE_CONNECTED` | Соединение установлено |
| `0x000000aa` | `VPN_PACKET_OP_CODE_CONNECT` | Запрос на подключение |
| `0x000000ab` | `VPN_PACKET_OP_CODE_DISCONNECT` | Отключение |
| `0x000000ac` | `VPN_PACKET_OP_CODE_SEND` | Отправка данных |
| `0x000000ad` | `VPN_PACKET_OP_CODE_RECV` | Получение данных |
| `0x000000ae` | `VPN_PACKET_OP_CODE_PROBLEM` | Проблема с соединением |

### Специальные операции

| Код операции | Константа | Описание |
|-------------|-----------|----------|
| `0x000000b0` | `VPN_PACKET_OP_CODE_VPN_METADATA` | Метаданные VPN |
| `0x000000b2` | `VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST` | Запрос адреса |
| `0x000000b3` | `VPN_PACKET_OP_CODE_VPN_ADDR_REPLY` | Ответ с адресом |
| `0xc0` | `VPN_PACKET_OP_CODE_PING` | Проверка связи |
| `0xc1` | `VPN_PACKET_OP_CODE_PONG` | Ответ на проверку связи |

### Коды проблем

| Код проблемы | Константа | Описание |
|-------------|-----------|----------|
| `0x00000001` | `VPN_PROBLEM_CODE_NO_FREE_ADDR` | Нет свободных адресов |
| `0x00000002` | `VPN_PROBLEM_CODE_TUNNEL_DOWN` | Туннель недоступен |
| `0x00000003` | `VPN_PROBLEM_CODE_PACKET_LOST` | Пакет потерян |
| `0x00000004` | `VPN_PROBLEM_CODE_ALREADY_ASSIGNED_ADDR` | Адрес уже назначен |

## API интерфейс

### Инициализация и деинициализация

```c
// Инициализация VPN клиента
int dap_chain_net_srv_client_vpn_init(dap_config_t * g_config);

// Предварительная инициализация VPN сервиса
int dap_chain_net_srv_vpn_pre_init();

// Инициализация VPN сервиса
int dap_chain_net_srv_vpn_init(dap_config_t * g_config);

// Деинициализация VPN сервиса
void dap_chain_net_srv_vpn_deinit(void);
```

### Основные структуры данных

```c
typedef struct dap_chain_net_srv_vpn {
    dap_chain_net_srv_vpn_item_ipv4_t * ipv4_unleased;  // Незанятые IPv4 адреса
    dap_chain_net_srv_ch_vpn_t * ch_vpn_ipv4;          // VPN каналы IPv4
    dap_chain_net_srv_t * parent;                       // Родительский сервис
} dap_chain_net_srv_vpn_t;
```

## Принцип работы

### 1. Установка VPN соединения

1. **Запрос адреса**: Клиент запрашивает IPv4 адрес через блокчейн транзакцию
2. **Назначение адреса**: Сервис проверяет доступность и назначает адрес
3. **Создание туннеля**: Устанавливается защищенный туннель между клиентом и сервером
4. **Маршрутизация**: Настраивается маршрутизация трафика через VPN

### 2. Передача данных

1. **Инкапсуляция**: Пакеты инкапсулируются в VPN протокол
2. **Шифрование**: Данные шифруются перед передачей
3. **Маршрутизация**: Пакеты маршрутизируются через блокчейн сеть
4. **Декапсуляция**: На принимающей стороне пакеты извлекаются из VPN протокола

### 3. Управление ресурсами

- **IP адресная**: Автоматическое управление пулом IPv4 адресов
- **Пропускная способность**: Контроль и ограничение трафика
- **Сессии**: Управление жизненным циклом VPN сессий
- **Мониторинг**: Отслеживание состояния соединений

## Безопасность

### Механизмы безопасности

1. **Шифрование трафика**: Все данные шифруются в туннеле
2. **Аутентификация**: Проверка подлинности клиентов через блокчейн
3. **Авторизация**: Контроль доступа на основе сертификатов
4. **Целостность**: Защита от модификации данных в пути

### Защита от атак

- **MITM атаки**: Предотвращение через криптографическую защиту
- **DoS атаки**: Ограничение ресурсов и rate limiting
- **IP спуфинг**: Проверка подлинности IP адресов
- **Трафик анализ**: Шифрование предотвращает анализ трафика

## Использование

### Базовая настройка VPN сервиса

```c
#include "dap_chain_net_srv_vpn.h"

// Инициализация VPN сервиса
if (dap_chain_net_srv_vpn_init(config) != 0) {
    log_error("Failed to initialize VPN service");
    return -1;
}

// Основная работа приложения...

// Деинициализация при завершении
dap_chain_net_srv_vpn_deinit();
```

### Работа с VPN соединениями

```c
// Создание нового VPN канала
dap_chain_net_srv_ch_vpn_t *vpn_channel = dap_chain_net_srv_ch_vpn_create(net_srv, usage_id);

// Проверка разрешения подключения
if (vpn_channel->is_allowed) {
    // Настройка IPv4 адреса
    vpn_channel->addr_ipv4.s_addr = inet_addr("192.168.1.100");

    // Активация канала
    dap_chain_net_srv_ch_vpn_activate(vpn_channel);
}

// Передача данных через VPN
size_t data_size = 1024;
uint8_t *data = get_data_to_send();
dap_chain_net_srv_vpn_send_data(vpn_channel, data, data_size);
```

### Управление адресами

```c
// Получение незанятого IPv4 адреса
struct in_addr free_addr = dap_chain_net_srv_vpn_get_free_ipv4_addr();

// Назначение адреса клиенту
dap_chain_net_srv_vpn_assign_addr_to_client(client_id, free_addr);

// Освобождение адреса
dap_chain_net_srv_vpn_release_addr(free_addr);
```

## Производительность

### Характеристики производительности

- **Пропускная способность**: До 100 Mbps на соединение
- **Задержка**: 50-200 мс в зависимости от сети
- **Количество соединений**: До 1000 одновременных клиентов
- **MTU**: 1500 байт (стандартный Ethernet)

### Оптимизации

1. **Буферизация**: Эффективная буферизация пакетов
2. **Многопоточность**: Параллельная обработка соединений
3. **Сжатие**: Опциональное сжатие трафика
4. **Кеширование**: Кеширование часто используемых маршрутов

## Интеграция с другими сервисами

### Совместная работа

VPN сервис интегрируется со следующими компонентами:

- **Chain модуль**: Для управления транзакциями VPN
- **Net модуль**: Для сетевой коммуникации
- **Crypto модуль**: Для шифрования трафика
- **Wallet модуль**: Для оплаты VPN услуг

### Примеры интеграции

```c
// Интеграция с платежной системой
void vpn_payment_callback(dap_chain_net_srv_ch_vpn_t *channel, uint256_t amount) {
    // Проверка оплаты VPN услуги
    if (dap_wallet_check_balance(channel->wallet, amount)) {
        // Активация VPN соединения
        dap_chain_net_srv_vpn_activate_channel(channel);
    }
}

// Интеграция с сетевым мониторингом
void vpn_monitor_callback(dap_chain_net_srv_vpn_t *vpn_service) {
    // Мониторинг состояния VPN соединений
    size_t active_connections = dap_chain_net_srv_vpn_get_active_count(vpn_service);

    // Отправка метрик в мониторинговую систему
    send_metrics("vpn_active_connections", active_connections);
}
```

## Мониторинг и отладка

### Метрики производительности

```c
// Получение статистики VPN сервиса
typedef struct dap_vpn_stats {
    size_t active_connections;        // Активные соединения
    size_t total_connections;         // Всего соединений
    uint64_t bytes_sent;             // Отправлено байт
    uint64_t bytes_received;         // Получено байт
    double avg_latency;              // Средняя задержка
    size_t error_count;              // Количество ошибок
} dap_vpn_stats_t;

// Получение статистики
dap_vpn_stats_t stats = dap_chain_net_srv_vpn_get_stats();
```

### Логирование

```c
// Включение отладки VPN
#define DAP_VPN_DEBUG

// Логирование VPN событий
log_it(L_INFO, "VPN: Client %d connected from %s", client_id, client_addr);
log_it(L_WARNING, "VPN: Packet lost for client %d", client_id);
log_it(L_ERROR, "VPN: Failed to allocate IPv4 address");
```

## Заключение

VPN Service CellFrame SDK предоставляет мощную и безопасную инфраструктуру для создания виртуальных частных сетей в блокчейн среде. Сочетая преимущества блокчейн технологии с традиционными VPN механизмами, сервис обеспечивает высокий уровень безопасности, производительности и масштабируемости. Полная интеграция с другими компонентами CellFrame позволяет создавать комплексные решения для защищенной коммуникации в децентрализованных сетях.
