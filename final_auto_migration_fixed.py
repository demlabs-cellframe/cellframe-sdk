#!/usr/bin/env python3
"""
Исправленный финальный автоматический мигратор JSON API
"""
import os
import re
import subprocess

def check_build():
    """Проверить сборку проекта"""
    result = subprocess.run(
        ["make", "-j4"], 
        cwd="build",
        capture_output=True
    )
    return result.returncode == 0

def count_warnings():
    """Подсчитать предупреждения"""
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(
        ["make", "-j4"], 
        cwd="build",
        capture_output=True, text=True
    )
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def apply_single_fix(command, description):
    """Применить одно исправление с проверкой"""
    print(f"🔧 {description}")
    
    # Применяем исправление
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"❌ Ошибка выполнения команды")
        return False
    
    # Проверяем сборку
    if not check_build():
        print(f"❌ Сборка сломалась, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    warnings = count_warnings()
    print(f"✅ Успешно: {warnings} предупреждений")
    
    # Коммитим успешное исправление
    subprocess.run(["git", "add", "modules/"])
    subprocess.run(["git", "commit", "-m", f"fix: {description}\n\nWarnings: {warnings}"])
    
    return True

# Основная логика
print("🎯 Финальная автоматическая миграция JSON API")

initial_warnings = count_warnings()
print(f"📊 Начальное количество: {initial_warnings} предупреждений")

# Список исправлений для применения по одному
fixes = [
    ("find modules/ -name '*.c' -exec sed -i 's/json_object \\*/dap_json_t */g' {} \\;", 
     "Замена всех json_object* на dap_json_t*"),
    
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {} \\;",
     "Замена json_object_object_add на dap_json_object_add_object"),
    
    ("find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_string(\\([^)]*\\)))/dap_json_object_add_string(\\1, \\2, \\3)/g' {} \\;",
     "Исправление dap_json_object_add_object с json_object_new_string"),
    
    ("find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_int(\\([^)]*\\)))/dap_json_object_add_int(\\1, \\2, \\3)/g' {} \\;",
     "Исправление dap_json_object_add_object с json_object_new_int"),
    
    ("find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_uint64(\\([^)]*\\)))/dap_json_object_add_uint64(\\1, \\2, \\3)/g' {} \\;",
     "Исправление dap_json_object_add_object с json_object_new_uint64"),
    
    ("find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\\([^,]*\\), \\([^,]*\\), json_object_new_bool(\\([^)]*\\)))/dap_json_object_add_bool(\\1, \\2, \\3)/g' {} \\;",
     "Исправление dap_json_object_add_object с json_object_new_bool"),
    
    ("find modules/ -name '*.c' -exec sed -i 's/dap_dap_json/dap_json/g' {} \\;",
     "Очистка двойных замен dap_dap_json"),
    
    ("find modules/ -name '*.c' -exec sed -i 's/dap_json_t_t/dap_json_t/g' {} \\;",
     "Очистка двойных замен dap_json_t_t"),
]

# Применяем исправления по одному
success_count = 0
for command, description in fixes:
    if apply_single_fix(command, description):
        success_count += 1
    else:
        print(f"❌ Остановлено на исправлении: {description}")
        break

final_warnings = count_warnings()
print(f"\n🏁 Результат автоматической миграции:")
print(f"📊 Начальные предупреждения: {initial_warnings}")
print(f"📊 Финальные предупреждения: {final_warnings}")
print(f"✅ Успешных исправлений: {success_count}/{len(fixes)}")
print(f"🔧 Исправлено: {initial_warnings - final_warnings} предупреждений")

if final_warnings == 0:
    print("🎉 МИГРАЦИЯ ПОЛНОСТЬЮ ЗАВЕРШЕНА!")
else:
    print(f"🔄 Осталось {final_warnings} предупреждений для ручной доработки")
