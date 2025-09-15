#!/usr/bin/env python3
"""
Мощный фиксер для остальных 2074 предупреждений
Исправляет проблемы по категориям с максимальной эффективностью
"""
import subprocess

def count_warnings():
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def power_fix(commands, description, expected_reduction=0):
    print(f"⚡ {description}")
    
    for cmd in commands:
        print(f"   Выполняю: {cmd}")
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

print("⚡ МОЩНЫЙ АВТОМАТИЧЕСКИЙ ФИКСЕР JSON API")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Мощные исправления по категориям
power_fixes = [
    {
        'commands': [
            # Исправление 373 проблем с инициализацией - самое безопасное
            "find modules/ -name '*.c' -exec sed -i 's/json_object \\*\\([a-z_][a-zA-Z0-9_]*\\) = dap_json_/dap_json_t *\\1 = dap_json_/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object\\* \\([a-z_][a-zA-Z0-9_]*\\) = dap_json_/dap_json_t* \\1 = dap_json_/g' {} \\;",
        ],
        'description': 'Fix 373 initialization type mismatches',
        'expected': 373
    },
    {
        'commands': [
            # Исправление оставшихся json_object* в простых объявлениях
            "find modules/ -name '*.c' -exec sed -i 's/^    json_object \\*/    dap_json_t */g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/^        json_object \\*/        dap_json_t */g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/^            json_object \\*/            dap_json_t */g' {} \\;",
        ],
        'description': 'Fix remaining json_object* declarations with indentation',
        'expected': 200
    },
    {
        'commands': [
            # Исправление json_object_new_* функций, которые еще остались
            "find modules/ -name '*.c' -exec sed -i 's/json_object_new_string(/dap_json_object_new_string(/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_new_int(/dap_json_object_new_int(/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_new_uint64(/dap_json_object_new_uint64(/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_new_bool(/dap_json_object_new_bool(/g' {} \\;",
        ],
        'description': 'Replace remaining json_object_new_* functions',
        'expected': 300
    },
    {
        'commands': [
            # Исправление других json_object функций
            "find modules/ -name '*.c' -exec sed -i 's/json_object_object_get(/dap_json_object_get(/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_array_length(/dap_json_array_length(/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_to_json_string(/dap_json_to_string(/g' {} \\;",
        ],
        'description': 'Replace other json_object functions',
        'expected': 100
    },
    {
        'commands': [
            # Финальная очистка и исправления
            "find modules/ -name '*.c' -exec sed -i 's/dap_dap_json/dap_json/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_t_t/dap_json_t/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_new_string_string/dap_json_object_new_string/g' {} \\;",
        ],
        'description': 'Final cleanup of double replacements and artifacts',
        'expected': 50
    }
]

success_count = 0
for fix in power_fixes:
    if power_fix(fix['commands'], fix['description'], fix['expected']):
        success_count += 1
    else:
        break

final = count_warnings()
print(f"\n🏁 МОЩНЫЕ ИСПРАВЛЕНИЯ ЗАВЕРШЕНЫ:")
print(f"📊 ПРОГРЕСС: {initial} → {final} предупреждений")
print(f"✅ УСПЕШНЫХ ПАКЕТОВ: {success_count}/{len(power_fixes)}")
print(f"🔧 ВСЕГО ИСПРАВЛЕНО: {initial - final} предупреждений")

if final == 0:
    print("🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉")
elif final < 100:
    print("🎉 ПОЧТИ ЗАВЕРШЕНО! Осталось меньше 100 предупреждений!")
elif final < 500:
    print("🚀 ОТЛИЧНЫЙ ПРОГРЕСС! Осталось меньше 500 предупреждений!")
else:
    print(f"🔄 Осталось {final} предупреждений для дальнейшей работы")
