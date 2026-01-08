# Cellframe Performance Tests

## Обзор

Этот каталог содержит performance тесты для Cellframe SDK. В отличие от обычных unit/integration тестов, эти тесты **НЕ ЗАПУСКАЮТСЯ ПО УМОЛЧАНИЮ** и предназначены для ручного запуска при необходимости профилирования производительности.

## TPS Test (dap_tps_test.c)

### Назначение

Тест измеряет пропускную способность (TPS - Transactions Per Second) обработки транзакций в mempool.

### Что было перенесено из `#ifdef DAP_TPS_TEST`

Весь код, который раньше был разбросан по production коду под `#ifdef DAP_TPS_TEST`, теперь изолирован в этом тесте:

1. **L_TPS log level** - специальный уровень логирования для TPS метрик
2. **Файловая синхронизация** (`/opt/cellframe-node/share/ca/*`) - теперь в `/tmp/cellframe-tps-test/`
3. **Увеличенные размеры** - 100MB atom size и 128MB packet size (опции теста)
4. **TX_NO_PREVIOUS validation** - обход валидации для нагрузочного тестирования (опция)
5. **Подавление логов** - режим `without_logs` для чистых метрик

### Сборка

```bash
cd build
cmake .. -DBUILD_PERFORMANCE_TESTS=ON
make tps-test
```

### Запуск

```bash
# Базовый запуск (10k транзакций, стандартные настройки)
./tests/performance/tps-test

# С опциями
./tests/performance/tps-test --tx-count 100000 --large-atoms --no-suppress-logs
```

### Опции

- `--tx-count N` - количество транзакций для теста (default: 10000)
- `--large-atoms` - использовать 100MB atom size вместо 10MB
- `--large-packets` - использовать 128MB packet size вместо 4MB
- `--no-suppress-logs` - показывать все логи (default: только L_TPS)
- `--accept-no-previous` - принимать TX_NO_PREVIOUS (для экстремального нагрузочного тестирования)

### Результаты

Тест выводит:
- Время начала и окончания
- Количество обработанных транзакций
- Длительность в секундах
- **TPS (Transactions Per Second)** - главная метрика

### Контрольные файлы

Тест использует файлы в `/tmp/cellframe-tps-test/` для синхронизации фаз:
- `mempool_start.txt` - начало загрузки транзакций
- `mempool_finish.txt` - окончание загрузки
- `mempool_ready.txt` - mempool готов к обработке
- `tps_start.txt` - начало TPS измерения
- `without_logs.txt` - режим подавления логов

## Почему это НЕ в production?

Performance тесты:
1. **Изменяют поведение системы** - увеличенные буферы, обход валидации
2. **Требуют специальных условий** - контрольные файлы, синхронизация
3. **Нужны редко** - только при профилировании
4. **Замедляют сборку** - дополнительные зависимости

## Философия "Infinite Resources"

Мы **НЕ делаем упрощений**! Весь TPS функционал сохранён полностью:
- ✅ Все метрики перенесены
- ✅ Все опции доступны
- ✅ Вся логика работает
- ✅ Production код чистый
- ✅ Тесты изолированы

## Добавление новых performance тестов

1. Создать `<test_name>.c` в этом каталоге
2. Добавить executable в `CMakeLists.txt`
3. Использовать `#ifdef DAP_TPS_TEST` внутри теста (НЕ в production!)
4. Документировать в этом README
