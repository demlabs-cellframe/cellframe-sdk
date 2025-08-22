# 🧪 СИСТЕМА ТЕСТИРОВАНИЯ БИЛЛИНГОВОГО МОДУЛЯ

## 📋 **АРХИТЕКТУРА ТЕСТОВ**

### **⚡ КАТЕГОРИИ ТЕСТОВ**

| **Категория** | **Время выполнения** | **По умолчанию** | **Описание** |
|---------------|---------------------|------------------|--------------|
| **FAST** | < 100ms каждый | ✅ Включены | Быстрые unit тесты |
| **INTEGRATION** | < 1s каждый | ✅ Включены | Интеграционные тесты |
| **STRESS** | Переменное | ❌ Отключены | Стресс тесты |
| **PERFORMANCE** | До 60s | ❌ Отключены | Бенчмарки производительности |
| **LONG_RUNNING** | > 10s | ❌ Отключены | Долгие тесты стабильности |

## 🛠️ **СБОРКА ТЕСТОВ**

### **Базовая сборка (только быстрые + интеграционные):**
```bash
cd /home/happy-sloth/WORK/cellframe-node/build
cmake .. 
make billing_tests
```

### **Сборка со стресс-тестами:**
```bash
cmake -DENABLE_STRESS_TESTS=ON ..
make billing_tests
```

### **Сборка со всеми категориями тестов:**
```bash
cmake -DENABLE_STRESS_TESTS=ON \
      -DENABLE_PERFORMANCE_TESTS=ON \
      -DENABLE_LONG_RUNNING_TESTS=ON \
      -DENABLE_VALGRIND_TESTS=ON ..
make billing_tests
```

## 🚀 **ЗАПУСК ТЕСТОВ**

### **🎯 Быстрый запуск для разработки (по умолчанию):**
```bash
# Только быстрые тесты (< 10 секунд общее время)
./billing_tests --category=FAST

# Быстрые + интеграционные (< 1 минуты)
./billing_tests --category=DEFAULT
# или просто
./billing_tests
```

### **🔧 Специфические категории:**
```bash
# Только интеграционные тесты
./billing_tests --category=INTEGRATION

# Только стресс тесты (если собраны)
./billing_tests --category=STRESS

# Все доступные тесты
./billing_tests --category=ALL
```

### **📊 Конфигурация вывода:**
```bash
# Подробный вывод
./billing_tests --verbose

# JUnit XML для CI/CD
./billing_tests --output=junit --output-file=test_results.xml

# JSON формат
./billing_tests --output=json --output-file=results.json

# Остановка на первой ошибке
./billing_tests --stop-on-failure
```

### **⚡ Параллельный запуск:**
```bash
# Параллельный запуск тестов (для стресс-тестов)
./billing_tests --category=STRESS --parallel=4
```

## 📈 **CI/CD ИНТЕГРАЦИЯ**

### **GitHub Actions / GitLab CI примеры:**

#### **Быстрая проверка в PR:**
```yaml
- name: Quick Tests
  run: |
    cd build
    ./billing_tests --category=FAST --output=junit --output-file=quick-results.xml
```

#### **Полная проверка в main:**
```yaml
- name: Full Tests  
  run: |
    cd build
    cmake -DENABLE_STRESS_TESTS=ON ..
    make billing_tests
    ./billing_tests --category=DEFAULT --output=junit --output-file=full-results.xml
```

#### **Ночные стресс-тесты:**
```yaml
- name: Nightly Stress Tests
  run: |
    cd build
    cmake -DENABLE_STRESS_TESTS=ON -DENABLE_PERFORMANCE_TESTS=ON ..
    make billing_tests
    ./billing_tests --category=ALL --output=junit --output-file=stress-results.xml
```

## 🧰 **РАЗРАБОТКА ТЕСТОВ**

### **Создание быстрого теста:**
```c
#include "billing_test_framework.h"

FAST_TEST(my_feature_test, "Test my new feature")
{
    // Тест должен выполняться < 100ms
    TEST_ASSERT_EQUAL(expected, actual);
    return TEST_RESULT_PASS;
}
```

### **Создание стресс-теста:**
```c
#ifdef ENABLE_STRESS_TESTS

STRESS_TEST(my_stress_test, "Stress test for my feature")
{
    // Тест может выполняться долго
    BENCHMARK_START();
    
    // ... тяжелые операции ...
    
    BENCHMARK_END("My stress operation");
    return TEST_RESULT_PASS;
}

#endif // ENABLE_STRESS_TESTS
```

### **Условная компиляция:**
```c
// Код только для стресс-тестов
IF_STRESS_ENABLED({
    // Создание больших массивов данных
    large_data_array = malloc(HUGE_SIZE);
})

// Код только для тестов производительности  
IF_PERFORMANCE_ENABLED({
    // Инициализация профилировщика
    init_profiler();
})
```

## 🎛️ **КОНФИГУРАЦИЯ ВРЕМЕНИ ВЫПОЛНЕНИЯ**

### **Переопределение таймаутов:**
```c
// В тестовом файле
#define TEST_TIMEOUT_FAST          50    // Ускорить быстрые тесты
#define TEST_TIMEOUT_INTEGRATION   500   // Ускорить интеграционные
```

### **Имитация времени для долгих операций:**
```c
// Вместо реального ожидания
test_simulate_time_passage(60000); // Симуляция 60 секунд

// Ускорение таймеров в тестах
#define GRACE_PERIOD_TEST_MS  100   // Вместо 60000ms в продакшене
```

## 📊 **ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ**

### **Локальная разработка:**
```bash
# Быстрая проверка после изменений (5-10 секунд)
make billing_tests && ./billing_tests --category=FAST

# Проверка интеграции перед коммитом (30-60 секунд)  
./billing_tests --category=DEFAULT

# Отладка конкретного теста
./billing_tests --category=FAST --verbose --stop-on-failure
```

### **Перед релизом:**
```bash
# Полная проверка со стресс-тестами
cmake -DENABLE_STRESS_TESTS=ON ..
make billing_tests
./billing_tests --category=ALL --verbose
```

### **Профилирование производительности:**
```bash
# Сборка с бенчмарками
cmake -DENABLE_PERFORMANCE_TESTS=ON ..
make billing_tests
./billing_tests --category=PERFORMANCE --output=json --output-file=benchmarks.json
```

## 🔍 **ОТЛАДКА ТЕСТОВ**

### **Использование с Valgrind:**
```bash
# Проверка утечек памяти (если включен ENABLE_VALGRIND_TESTS)
make test_valgrind

# Ручной запуск с valgrind
valgrind --tool=memcheck --leak-check=full ./billing_tests --category=FAST
```

### **Использование с GDB:**
```bash
# Отладка упавшего теста
gdb ./billing_tests
(gdb) run --category=FAST --stop-on-failure
```

### **ThreadSanitizer для race conditions:**
```bash
# Сборка с ThreadSanitizer
cmake -DCMAKE_C_FLAGS="-fsanitize=thread" ..
make billing_tests
./billing_tests --category=STRESS
```

## 📋 **СПИСОК КОМАНД**

### **Make targets:**
```bash
make test_fast           # Только быстрые тесты
make test_integration    # Только интеграционные  
make test_stress         # Только стресс (если включены)
make test_performance    # Только производительность (если включены)
make test_default        # Быстрые + интеграционные
make test_all           # Все включенные тесты
make test_ci_quick      # CI быстрая проверка
make test_ci_full       # CI полная проверка
make test_valgrind      # Проверка с valgrind (если включена)
```

### **Получение справки:**
```bash
./billing_tests --help          # Полная справка
./billing_tests --list          # Список доступных тестов
```

---

## 🎯 **РЕКОМЕНДАЦИИ ПО ИСПОЛЬЗОВАНИЮ**

### **✅ Для ежедневной разработки:**
- Используйте `--category=FAST` после каждого изменения
- Запускайте `--category=DEFAULT` перед коммитом
- **Время выполнения:** 10-60 секунд

### **✅ Для CI/CD пайплайнов:**
- **Pull Request проверки:** `FAST` категория (быстро)
- **Merge в main:** `DEFAULT` категория (надежно)  
- **Ночные сборки:** `ALL` категории (полное покрытие)

### **✅ Для нагрузочного тестирования:**
- Включайте `STRESS` и `PERFORMANCE` только когда нужно
- Используйте параллельный запуск для ускорения
- Сохраняйте результаты в файлы для анализа

### **❌ Избегайте:**
- Запуска всех тестов в обычной разработке
- Включения стресс-тестов в быстрых CI проверках
- Игнорирования таймаутов в долгих тестах
