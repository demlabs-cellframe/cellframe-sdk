#!/usr/bin/env python3
"""
Продвинутый фиксер типов для остальных предупреждений
Работает с конкретными паттернами типов
"""
import subprocess
import re

def count_warnings():
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def get_warning_samples():
    """Получить образцы предупреждений для анализа"""
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    warnings = [line for line in result.stderr.split('\n') if 'warning:' in line]
    return warnings[:10]  # Первые 10 для анализа

def safe_batch_fix(commands, description):
    """Безопасное применение пакета команд"""
    print(f"🔧 {description}")
    
    for cmd in commands:
        subprocess.run(cmd, shell=True)
    
    if not check_build():
        print(f"❌ Сборка сломалась, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    warnings = count_warnings()
    print(f"✅ Успешно: {warnings} предупреждений")
    
    # Коммитим
    subprocess.run(["git", "add", "modules/"])
    subprocess.run(["git", "commit", "-m", f"fix: {description}\\n\\nWarnings: {warnings}"])
    
    return True

# Основная логика
print("🎯 Продвинутый фиксер типов")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Анализируем образцы предупреждений
samples = get_warning_samples()
print("📋 Образцы предупреждений:")
for i, sample in enumerate(samples[:3]):
    print(f"  {i+1}. {sample}")

# Применяем пакеты исправлений
batches = [
    {
        'commands': [
            "find modules/ -name '*.c' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {} \\;",
        ],
        'description': 'Convert json_object_object_add to dap_json_object_add_object'
    },
    {
        'commands': [
            "find modules/ -name '*.c' -exec sed -i 's/json_object \\*/dap_json_t */g' {} \\;",
        ],
        'description': 'Convert json_object* types to dap_json_t*'
    },
    {
        'commands': [
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_string(\\([^)]*\\)))/dap_json_object_add_string(\\1, \\2, \\3)/g' {} \\;",
        ],
        'description': 'Fix dap_json_object_add_object with json_object_new_string'
    },
    {
        'commands': [
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_int(\\([^)]*\\)))/dap_json_object_add_int(\\1, \\2, \\3)/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_uint64(\\([^)]*\\)))/dap_json_object_add_uint64(\\1, \\2, \\3)/g' {} \\;",
        ],
        'description': 'Fix dap_json_object_add_object with numeric types'
    },
    {
        'commands': [
            "find modules/ -name '*.c' -exec sed -i 's/dap_dap_json/dap_json/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_t_t/dap_json_t/g' {} \\;",
        ],
        'description': 'Clean up double replacements'
    }
]

success_count = 0
for batch in batches:
    if safe_batch_fix(batch['commands'], batch['description']):
        success_count += 1
    else:
        print(f"❌ Остановлено на: {batch['description']}")
        break

final = count_warnings()
print(f"\n🏁 Продвинутая миграция завершена:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных пакетов: {success_count}/{len(batches)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")
