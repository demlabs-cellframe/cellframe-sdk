# CellFrame SDK Hello World Example

## Описание

Этот пример демонстрирует самый простой способ начать работу с CellFrame SDK. Он показывает базовую инициализацию SDK, создание сети и цепочки, а также правильное завершение работы.

## Что делает пример

1. **Инициализация CellFrame SDK** - показывает как правильно инициализировать SDK
2. **Создание сети** - демонстрирует создание блокчейн-сети
3. **Создание цепочки** - показывает как создать новую блокчейн-цепочку
4. **Работа с кошельком** - демонстрирует создание и использование кошелька
5. **Управление ресурсами** - показывает правильную очистку ресурсов

## Сборка и запуск

### Требования
- CellFrame SDK установлен и настроен
- DAP SDK установлен (зависимость)
- Компилятор C (GCC или Clang)
- CMake 3.10+

### Сборка

```bash
# Из директории примера
mkdir build
cd build
cmake ..
make
```

### Запуск

```bash
./hello_cellframe
```

### Ожидаемый вывод

```
CellFrame SDK Hello World Example
==================================

Initializing CellFrame SDK...
✓ CellFrame SDK initialized successfully

Creating test network...
✓ Network 'hello_network' created successfully
  Network ID: 12345

Creating blockchain...
✓ Chain 'hello_chain' created successfully

Chain Information:
  Name: hello_chain
  ID: 67890

Time Management Example:
  Current time: 2025-01-09 12:34:56 UTC

Wallet Creation Example:
✓ Wallet created successfully
  Wallet address: CF1A2B3C4D5E6F...
✓ Wallet resources freed

Cleaning up resources...
✓ Chain resources freed
✓ Network resources freed
✓ CellFrame SDK shut down successfully

==================================
Example completed successfully!
You can now explore more advanced CellFrame SDK features:
  - Wallet operations
  - Transaction creation
  - Consensus algorithms
  - Network communication
```

## Структура кода

### main.c
- `main()` - основная функция
- Инициализация и завершение SDK
- Создание сети и цепочки
- Демонстрация работы с кошельком

### CMakeLists.txt
- Конфигурация сборки
- Подключение CellFrame SDK
- Настройки компилятора

## Следующие шаги

После изучения этого примера вы можете перейти к:

1. **Операции с кошельком**: [basic_wallet](../basic_wallet/)
2. **Создание транзакций**: [simple_transaction](../simple_transaction/)
3. **Алгоритмы консенсуса**: [consensus_demo](../consensus_demo/)

## Безопасность

Этот пример демонстрирует безопасные практики:
- Проверка возвращаемых значений
- Правильное управление памятью
- Корректная очистка ресурсов
- Использование пост-квантовых алгоритмов (Dilithium)

## Используемые алгоритмы

### Криптография
- **Dilithium**: Пост-квантовый алгоритм цифровых подписей
- **Рекомендация**: Используйте пост-квантовые алгоритмы для новых проектов

### Консенсус
- По умолчанию используется DAG PoA (Proof of Authority)
- Поддерживаются: DAG PoA, DAG PoS, Block PoW, ESBOCS

## Устранение неполадок

### Ошибка инициализации
```
ERROR: Failed to initialize CellFrame SDK
```
**Решение**: Убедитесь, что CellFrame SDK и DAP SDK правильно установлены.

### Ошибка создания сети
```
ERROR: Failed to create network
```
**Решение**: Проверьте, что нет конфликтов с существующими сетями.

### Ошибка компиляции
```
fatal error: dap_chain.h: No such file or directory
```
**Решение**: Убедитесь, что пути к заголовочным файлам указаны правильно.

## Дополнительная информация

- **Документация**: [../../README.md](../../README.md)
- **API Reference**: [../../modules/](../../modules/)
- **Архитектура**: [../../architecture.md](../../architecture.md)

## Советы по разработке

1. **Всегда проверяйте возвращаемые значения** всех функций
2. **Правильно освобождайте ресурсы** в обратном порядке создания
3. **Используйте пост-квантовые алгоритмы** для новых проектов
4. **Тестируйте на разных платформах** (Linux, macOS, Windows)
