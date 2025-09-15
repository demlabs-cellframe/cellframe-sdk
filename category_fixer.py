#!/usr/bin/env python3
"""
Категориальный фиксер - исправления по типам проблем
"""
import subprocess

def count_warnings():
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def apply_category_fix(commands, description):
    print(f"🎯 {description}")
    
    for cmd in commands:
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

print("🎯 Категориальные исправления JSON API")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Категориальные исправления
categories = [
    {
        'commands': [
            # Исправление наиболее частых проблем с dap_json_object_add_object
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_string(\\([^)]*\\)))/dap_json_object_add_string(\\1, \\2, \\3)/g' {} \\;",
        ],
        'description': 'Fix 966 dap_json_object_add_object with string issues'
    },
    {
        'commands': [
            # Исправление числовых типов
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_int(\\([^)]*\\)))/dap_json_object_add_int(\\1, \\2, \\3)/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_uint64(\\([^)]*\\)))/dap_json_object_add_uint64(\\1, \\2, \\3)/g' {} \\;",
        ],
        'description': 'Fix numeric type issues in dap_json_object_add_object'
    },
    {
        'commands': [
            # Исправление булевых типов
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_bool(\\([^)]*\\)))/dap_json_object_add_bool(\\1, \\2, \\3)/g' {} \\;",
        ],
        'description': 'Fix boolean type issues in dap_json_object_add_object'
    }
]

success_count = 0
for category in categories:
    if apply_category_fix(category['commands'], category['description']):
        success_count += 1
    else:
        break

final = count_warnings()
print(f"\n🏁 Категориальные исправления завершены:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных категорий: {success_count}/{len(categories)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")

if final < 100:
    print("🎉 Почти завершено! Осталось меньше 100 предупреждений!")
elif final < 500:
    print("🚀 Отличный прогресс! Осталось меньше 500 предупреждений!")
else:
    print("🔄 Продолжаем работу над оставшимися предупреждениями")
