# Спецификация юнит-тестов для модуля stake-ext

## 📋 Обзор

Данная спецификация описывает полный план юнит-тестов для модуля stake-ext (`dap_chain_net_srv_stake_ext`), включая тестирование компоновки транзакций, состояний stake-ext и интеграции с леджером.

## 🎯 Основные области тестирования

### 1. 🗃️ **Тестирование кэша stake-ext**

#### 1.1 Инициализация и очистка кэша
- `test_stake_ext_cache_create()` - создание кэша
- `test_stake_ext_cache_delete()` - удаление кэша
- `test_stake_ext_cache_concurrent_init()` - параллельная инициализация

#### 1.2 Управление stake-ext в кэше
- `test_stake_ext_cache_add_stake_ext()` - добавление stake-ext
- `test_stake_ext_cache_find_stake_ext()` - поиск по хешу
- `test_stake_ext_cache_find_stake_ext_by_name()` - поиск по имени
- `test_stake_ext_cache_update_stake_ext_status()` - обновление статуса
- `test_stake_ext_cache_remove_stake_ext()` - удаление stake-ext

#### 1.3 Управление блокировками в кэше
- `test_stake_ext_cache_add_lock()` - добавление блокировки
- `test_stake_ext_cache_find_lock()` - поиск блокировки
- `test_stake_ext_cache_unlock_lock()` - разблокировка
- `test_stake_ext_cache_update_lock_status()` - обновление статуса блокировки

#### 1.4 Статистика и счетчики
- `test_stake_ext_cache_counters()` - проверка счетчиков
- `test_stake_ext_cache_stats()` - получение статистики

### 2. 🔄 **Тестирование состояний stake-ext**

#### 2.1 Переходы состояний (COMPLETED)
- `test_stake_ext_status_transitions()` - валидные переходы
  - CREATED → ACTIVE (при запуске)
  - ACTIVE → ENDED (при завершении)
  - ACTIVE → CANCELLED (при отмене)
  - CREATED → CANCELLED (отмена до запуска)
- `test_stake_ext_invalid_status_transitions()` - невалидные переходы
  - ENDED → ACTIVE
  - CANCELLED → ACTIVE
  - ENDED → CREATED

#### 2.2 Статусы и их обработка (COMPLETED)
- `test_stake_ext_status_to_str()` - преобразование в строку
- `test_stake_ext_status_from_event_type()` - получение из события
- `test_stake_ext_status_validation()` - валидация статусов

### 3. 📦 **Тестирование транзакций stake-ext**

#### 3.1 События stake-ext
- `test_stake_ext_started_event_processing()` - обработка запуска
  - Валидация event_data_size
  - Парсинг dap_chain_tx_event_data_stake_ext_started_t
  - Добавление в кэш
  - Обновление счетчиков
- `test_stake_ext_ended_event_processing()` - обработка завершения
  - Валидация event_data_size
  - Парсинг dap_chain_tx_event_data_ended_t
  - Установка победителей
  - Обновление статуса на ENDED
- `test_stake_ext_cancelled_event_processing()` - обработка отмены
  - Обновление статуса на CANCELLED
  - Уменьшение active_stake_ext

#### 3.2 Транзакции блокировок
- `test_stake_ext_lock_tx_create()` - создание транзакции блокировки
  - Валидация входных параметров
  - Создание условного выхода
  - Подпись транзакции
  - Добавление в mempool
- `test_stake_ext_lock_tx_validation()` - валидация блокировок
  - Проверка существования stake-ext
  - Проверка статуса stake-ext (ACTIVE)
  - Валидация суммы блокировки
  - Проверка project_id

#### 3.3 Транзакции разблокировки
- `test_stake_ext_unlock_tx_create()` - создание разблокировки
  - Поиск исходной блокировки
  - Создание транзакции разблокировки
  - Валидация комиссий
- `test_stake_ext_unlock_validation()` - валидация разблокировки
  - Проверка существования блокировки
  - Проверка прав на разблокировку
  - Статус блокировки

### 4. 🔗 **Тестирование интеграции с леджером**

#### 4.1 Callback обработчики событий
- `test_stake_ext_event_callback_added()` - добавление событий
- `test_stake_ext_event_callback_deleted()` - удаление событий
- `test_stake_ext_event_callback_invalid_params()` - невалидные параметры
- `test_stake_ext_event_callback_concurrent()` - параллельная обработка

#### 4.2 Синхронизация с леджером
- `test_stake_ext_ledger_sync()` - синхронизация состояния
- `test_stake_ext_ledger_recovery()` - восстановление после сбоя
- `test_stake_ext_ledger_rollback()` - откат транзакций

#### 4.3 Verificator функции
- `test_stake_ext_lock_verificator()` - проверка блокировок
- `test_stake_ext_lock_updater()` - обновление после верификации

### 5. 🧮 **Тестирование обработки данных**

#### 5.1 Структуры данных событий
- `test_stake_ext_started_data_parsing()` - парсинг данных запуска
  - Валидация размера буфера
  - Чтение массива project_ids
  - Обработка некорректных данных
- `test_stake_ext_ended_data_parsing()` - парсинг данных завершения
  - Валидация размера буфера  
  - Чтение массива winners
  - Обработка пустых winners

#### 5.2 Boundary conditions
- `test_stake_ext_data_buffer_underflow()` - недостаток данных
- `test_stake_ext_data_buffer_overflow()` - переполнение
- `test_stake_ext_max_projects_limit()` - максимум проектов
- `test_stake_ext_max_winners_limit()` - максимум победителей

### 6. 🔒 **Тестирование безопасности и ошибок**

#### 6.1 Обработка ошибок
- `test_stake_ext_null_pointer_handling()` - NULL указатели
- `test_stake_ext_invalid_hash_handling()` - невалидные хеши
- `test_stake_ext_memory_allocation_failure()` - ошибки выделения памяти
- `test_stake_ext_cache_corruption_recovery()` - восстановление кэша

#### 6.2 Concurrent access
- `test_stake_ext_cache_thread_safety()` - потокобезопасность
- `test_stake_ext_rwlock_behavior()` - поведение блокировок
- `test_stake_ext_race_conditions()` - гонки потоков

### 7. 📊 **Тестирование производительности**

#### 7.1 Масштабируемость
- `test_stake_ext_cache_large_dataset()` - большие объемы данных
- `test_stake_ext_lookup_performance()` - производительность поиска
- `test_stake_ext_memory_usage()` - использование памяти

#### 7.2 Стресс-тесты
- `test_stake_ext_high_load()` - высокая нагрузка
- `test_stake_ext_rapid_status_changes()` - частые изменения
- `test_stake_ext_concurrent_transactions()` - параллельные транзакции

## 🛠️ **Вспомогательные функции для тестов**

### Mock объекты
- `mock_dap_chain_net_t` - сетевые структуры
- `mock_dap_ledger_t` - леджер для тестов
- `mock_dap_chain_tx_event_t` - события транзакций

### Утилиты тестирования
- `create_test_stake_ext()` - создание тестового stake-ext
- `create_test_lock()` - создание тестовой блокировки
- `create_test_event()` - создание тестового события
- `assert_stake_ext_state()` - проверка состояния stake-ext
- `cleanup_test_data()` - очистка тестовых данных

### Генераторы данных
- `generate_test_hash()` - генерация тестовых хешей
- `generate_test_address()` - генерация адресов
- `generate_stake_ext_event_data()` - генерация данных событий

## 📈 **Критерии покрытия**

### Покрытие кода
- **Цель**: 95%+ покрытие строк кода
- **Ветвления**: 90%+ покрытие условных переходов
- **Функции**: 100% покрытие публичных функций

### Функциональное покрытие
- Все состояния stake-ext протестированы
- Все типы событий протестированы  
- Все пути обработки ошибок протестированы
- Все граничные условия протестированы

### Интеграционное покрытие
- Взаимодействие с леджером
- Взаимодействие с mempool
- Взаимодействие с кэшем

## 🚀 **План реализации**

### Фаза 1: Базовые тесты (1-2 дня)
1. Тесты кэша stake-ext
2. Тесты состояний
3. Основные mock объекты

### Фаза 2: Транзакционные тесты (2-3 дня)
1. Тесты событий stake-ext
2. Тесты транзакций блокировок
3. Тесты разблокировки

### Фаза 3: Интеграционные тесты (2-3 дня)
1. Тесты callback'ов леджера
2. Тесты verificator'ов
3. Тесты синхронизации

### Фаза 4: Продвинутые тесты (2-3 дня)
1. Тесты безопасности
2. Стресс-тесты
3. Тесты производительности

---

*Данная спецификация обеспечивает полное покрытие тестами модуля stake-ext и гарантирует надежность работы всех компонентов системы.*
