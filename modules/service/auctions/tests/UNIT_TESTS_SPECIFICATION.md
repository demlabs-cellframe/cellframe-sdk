# Спецификация юнит-тестов для модуля аукционов

## 📋 Обзор

Данная спецификация описывает полный план юнит-тестов для модуля аукционов (`dap_chain_net_srv_auctions`), включая тестирование компоновки транзакций, состояний аукционов и интеграции с леджером.

## 🎯 Основные области тестирования

### 1. 🗃️ **Тестирование кэша аукционов**

#### 1.1 Инициализация и очистка кэша
- `test_auction_cache_create()` - создание кэша
- `test_auction_cache_delete()` - удаление кэша
- `test_auction_cache_concurrent_init()` - параллельная инициализация

#### 1.2 Управление аукционами в кэше
- `test_auction_cache_add_auction()` - добавление аукциона
- `test_auction_cache_find_auction()` - поиск по хешу
- `test_auction_cache_find_auction_by_name()` - поиск по имени
- `test_auction_cache_update_auction_status()` - обновление статуса
- `test_auction_cache_remove_auction()` - удаление аукциона

#### 1.3 Управление ставками в кэше
- `test_auction_cache_add_bid()` - добавление ставки
- `test_auction_cache_find_bid()` - поиск ставки
- `test_auction_cache_withdraw_bid()` - снятие ставки
- `test_auction_cache_update_bid_status()` - обновление статуса ставки

#### 1.4 Статистика и счетчики
- `test_auction_cache_counters()` - проверка счетчиков
- `test_auction_cache_stats()` - получение статистики

### 2. 🔄 **Тестирование состояний аукционов**

#### 2.1 Переходы состояний (COMPLETED)
- `test_auction_status_transitions()` - валидные переходы
  - CREATED → ACTIVE (при запуске)
  - ACTIVE → ENDED (при завершении)
  - ACTIVE → CANCELLED (при отмене)
  - CREATED → CANCELLED (отмена до запуска)
- `test_auction_invalid_status_transitions()` - невалидные переходы
  - ENDED → ACTIVE
  - CANCELLED → ACTIVE
  - ENDED → CREATED

#### 2.2 Статусы и их обработка (COMPLETED)
- `test_auction_status_to_str()` - преобразование в строку
- `test_auction_status_from_event_type()` - получение из события
- `test_auction_status_validation()` - валидация статусов

### 3. 📦 **Тестирование транзакций аукционов**

#### 3.1 События аукционов
- `test_auction_started_event_processing()` - обработка запуска
  - Валидация event_data_size
  - Парсинг dap_chain_tx_event_data_auction_started_t
  - Добавление в кэш
  - Обновление счетчиков
- `test_auction_ended_event_processing()` - обработка завершения
  - Валидация event_data_size
  - Парсинг dap_chain_tx_event_data_ended_t
  - Установка победителей
  - Обновление статуса на ENDED
- `test_auction_cancelled_event_processing()` - обработка отмены
  - Обновление статуса на CANCELLED
  - Уменьшение active_auctions

#### 3.2 Транзакции ставок
- `test_auction_bid_tx_create()` - создание транзакции ставки
  - Валидация входных параметров
  - Создание условного выхода
  - Подпись транзакции
  - Добавление в mempool
- `test_auction_bid_tx_validation()` - валидация ставок
  - Проверка существования аукциона
  - Проверка статуса аукциона (ACTIVE)
  - Валидация суммы ставки
  - Проверка project_id

#### 3.3 Транзакции возврата средств
- `test_auction_bid_withdraw_tx_create()` - создание возврата
  - Поиск исходной ставки
  - Создание транзакции возврата
  - Валидация комиссий
- `test_auction_bid_withdraw_validation()` - валидация возврата
  - Проверка существования ставки
  - Проверка прав на возврат
  - Статус ставки

### 4. 🔗 **Тестирование интеграции с леджером**

#### 4.1 Callback обработчики событий
- `test_auction_event_callback_added()` - добавление событий
- `test_auction_event_callback_deleted()` - удаление событий
- `test_auction_event_callback_invalid_params()` - невалидные параметры
- `test_auction_event_callback_concurrent()` - параллельная обработка

#### 4.2 Синхронизация с леджером
- `test_auction_ledger_sync()` - синхронизация состояния
- `test_auction_ledger_recovery()` - восстановление после сбоя
- `test_auction_ledger_rollback()` - откат транзакций

#### 4.3 Verificator функции
- `test_auction_bid_verificator()` - проверка ставок
- `test_auction_bid_updater()` - обновление после верификации

### 5. 🧮 **Тестирование обработки данных**

#### 5.1 Структуры данных событий
- `test_auction_started_data_parsing()` - парсинг данных запуска
  - Валидация размера буфера
  - Чтение массива project_ids
  - Обработка некорректных данных
- `test_auction_ended_data_parsing()` - парсинг данных завершения
  - Валидация размера буфера  
  - Чтение массива winners
  - Обработка пустых winners

#### 5.2 Boundary conditions
- `test_auction_data_buffer_underflow()` - недостаток данных
- `test_auction_data_buffer_overflow()` - переполнение
- `test_auction_max_projects_limit()` - максимум проектов
- `test_auction_max_winners_limit()` - максимум победителей

### 6. 🔒 **Тестирование безопасности и ошибок**

#### 6.1 Обработка ошибок
- `test_auction_null_pointer_handling()` - NULL указатели
- `test_auction_invalid_hash_handling()` - невалидные хеши
- `test_auction_memory_allocation_failure()` - ошибки выделения памяти
- `test_auction_cache_corruption_recovery()` - восстановление кэша

#### 6.2 Concurrent access
- `test_auction_cache_thread_safety()` - потокобезопасность
- `test_auction_rwlock_behavior()` - поведение блокировок
- `test_auction_race_conditions()` - гонки потоков

### 7. 📊 **Тестирование производительности**

#### 7.1 Масштабируемость
- `test_auction_cache_large_dataset()` - большие объемы данных
- `test_auction_lookup_performance()` - производительность поиска
- `test_auction_memory_usage()` - использование памяти

#### 7.2 Стресс-тесты
- `test_auction_high_load()` - высокая нагрузка
- `test_auction_rapid_status_changes()` - частые изменения
- `test_auction_concurrent_transactions()` - параллельные транзакции

## 🛠️ **Вспомогательные функции для тестов**

### Mock объекты
- `mock_dap_chain_net_t` - сетевые структуры
- `mock_dap_ledger_t` - леджер для тестов
- `mock_dap_chain_tx_event_t` - события транзакций

### Утилиты тестирования
- `create_test_auction()` - создание тестового аукциона
- `create_test_bid()` - создание тестовой ставки
- `create_test_event()` - создание тестового события
- `assert_auction_state()` - проверка состояния аукциона
- `cleanup_test_data()` - очистка тестовых данных

### Генераторы данных
- `generate_test_hash()` - генерация тестовых хешей
- `generate_test_address()` - генерация адресов
- `generate_auction_event_data()` - генерация данных событий

## 📈 **Критерии покрытия**

### Покрытие кода
- **Цель**: 95%+ покрытие строк кода
- **Ветвления**: 90%+ покрытие условных переходов
- **Функции**: 100% покрытие публичных функций

### Функциональное покрытие
- Все состояния аукционов протестированы
- Все типы событий протестированы  
- Все пути обработки ошибок протестированы
- Все граничные условия протестированы

### Интеграционное покрытие
- Взаимодействие с леджером
- Взаимодействие с mempool
- Взаимодействие с кэшем

## 🚀 **План реализации**

### Фаза 1: Базовые тесты (1-2 дня)
1. Тесты кэша аукционов
2. Тесты состояний
3. Основные mock объекты

### Фаза 2: Транзакционные тесты (2-3 дня)
1. Тесты событий аукционов
2. Тесты транзакций ставок
3. Тесты возврата средств

### Фаза 3: Интеграционные тесты (2-3 дня)
1. Тесты callback'ов леджера
2. Тесты verificator'ов
3. Тесты синхронизации

### Фаза 4: Продвинутые тесты (2-3 дня)
1. Тесты безопасности
2. Стресс-тесты
3. Тесты производительности

---

*Данная спецификация обеспечивает полное покрытие тестами модуля аукционов и гарантирует надежность работы всех компонентов системы.*
