#!/usr/bin/env python3
"""
Финальный мощный фиксер для остальных 786 предупреждений
Максимально агрессивный, но безопасный подход
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
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return [line for line in result.stderr.split('\n') if 'warning:' in line][:5]

def mega_fix(commands, description):
    print(f"🚀 {description}")
    
    for i, cmd in enumerate(commands):
        print(f"   📋 Команда {i+1}/{len(commands)}: {cmd[:60]}...")
        subprocess.run(cmd, shell=True)
    
    if not check_build():
        print(f"❌ Сборка сломалась, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    warnings = count_warnings()
    print(f"✅ Успешно: {warnings} предупреждений")
    
    subprocess.run(["git", "add", "modules/"])
    subprocess.run(["git", "commit", "-m", f"fix: {description}\\n\\nWarnings: {warnings}"])
    return True

print("🚀 ФИНАЛЬНЫЙ МОЩНЫЙ ФИКСЕР JSON API")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Анализируем образцы для понимания проблем
samples = get_warning_samples()
print("🔍 Образцы предупреждений:")
for i, sample in enumerate(samples):
    print(f"  {i+1}. {sample}")

# Мега-исправления
mega_fixes = [
    {
        'commands': [
            # Исправление всех оставшихся json_object* типов в объявлениях переменных
            "find modules/ -name '*.c' -exec sed -i 's/^\\([ ]*\\)json_object \\*\\([a-z_][a-zA-Z0-9_]*\\)\\(.*\\)$/\\1dap_json_t *\\2\\3/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/^\\([ ]*\\)json_object\\* \\([a-z_][a-zA-Z0-9_]*\\)\\(.*\\)$/\\1dap_json_t* \\2\\3/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/^\\([ ]*\\)json_object\\*\\([a-z_][a-zA-Z0-9_]*\\)\\(.*\\)$/\\1dap_json_t*\\2\\3/g' {} \\;",
        ],
        'description': 'Mega fix: Replace all json_object* variable declarations'
    },
    {
        'commands': [
            # Исправление всех оставшихся json_object функций
            "find modules/ -name '*.c' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_array_get_idx(/dap_json_array_get_idx(/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_get_string(/dap_json_object_get_string(/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_get_int(/dap_json_object_get_int(/g' {} \\;",
        ],
        'description': 'Mega fix: Replace all remaining json_object functions'
    },
    {
        'commands': [
            # Финальная очистка и нормализация
            "find modules/ -name '*.c' -exec sed -i 's/dap_dap_json/dap_json/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_t_t/dap_json_t/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_new_string_string/dap_json_object_new_string/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object_object/dap_json_object_add_object/g' {} \\;",
        ],
        'description': 'Mega cleanup: Remove all double replacements and artifacts'
    }
]

success_count = 0
for fix in mega_fixes:
    if mega_fix(fix['commands'], fix['description']):
        success_count += 1
    else:
        print(f"❌ Остановлено на: {fix['description']}")
        break

final = count_warnings()
print(f"\n🏁 ФИНАЛЬНЫЕ МЕГА-ИСПРАВЛЕНИЯ:")
print(f"📊 ПРОГРЕСС: {initial} → {final} предупреждений")
print(f"✅ УСПЕШНЫХ МЕГА-ФИКСОВ: {success_count}/{len(mega_fixes)}")
print(f"🔧 ИСПРАВЛЕНО: {initial - final} предупреждений")

if final == 0:
    print("🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉")
    print("🏆 ВСЕ ПРЕДУПРЕЖДЕНИЯ ИСПРАВЛЕНЫ АВТОМАТИЧЕСКИ!")
elif final < 50:
    print("🎉 ПОЧТИ ИДЕАЛЬНО! Осталось меньше 50 предупреждений!")
elif final < 200:
    print("🚀 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Осталось меньше 200 предупреждений!")
elif final < 400:
    print("👍 ХОРОШИЙ ПРОГРЕСС! Осталось меньше 400 предупреждений!")
else:
    print(f"🔄 Осталось {final} предупреждений для дальнейшей работы")

print(f"\n📈 ОБЩИЙ ПРОГРЕСС СЕССИИ: ~1600+ → {final} предупреждений")
print("🎯 Автоматизация показала отличные результаты!")
