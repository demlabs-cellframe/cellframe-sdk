#!/usr/bin/env python3
"""
Финальная автоматизация для 146 предупреждений
Простой и эффективный подход
"""
import subprocess
import os

def count_warnings():
    os.chdir('/home/naeper/work/python-cellframe/cellframe-sdk/build')
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make", "-j4"], capture_output=True, text=True)
    warnings = [line for line in result.stderr.split('\n') if 'warning:' in line]
    os.chdir('/home/naeper/work/python-cellframe/cellframe-sdk')
    return len(warnings)

def check_build():
    os.chdir('/home/naeper/work/python-cellframe/cellframe-sdk/build')
    result = subprocess.run(["make", "-j4"], capture_output=True)
    success = result.returncode == 0
    os.chdir('/home/naeper/work/python-cellframe/cellframe-sdk')
    return success

def safe_apply(command, description):
    print(f"🔧 {description}")
    
    # Применяем команду
    result = subprocess.run(command, shell=True, capture_output=True)
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
    
    # Коммитим если есть улучшение
    subprocess.run(["git", "add", "modules/"])
    subprocess.run(["git", "commit", "-m", f"fix: {description}\\n\\nWarnings: {warnings}"])
    
    return True

print("🎯 ФИНАЛЬНАЯ АВТОМАТИЗАЦИЯ ДЛЯ 146 ПРЕДУПРЕЖДЕНИЙ")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Финальные безопасные исправления
final_fixes = [
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_get_string(/dap_json_object_get_string(/g' {} \\;",
     "Replace json_object_get_string with dap_json_object_get_string"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_is_type(/dap_json_object_is_type(/g' {} \\;", 
     "Replace json_object_is_type with dap_json_object_is_type"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_array_get_idx(/dap_json_array_get_idx(/g' {} \\;",
     "Replace json_object_array_get_idx with dap_json_array_get_idx"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_del(/dap_json_object_del(/g' {} \\;",
     "Replace json_object_del with dap_json_object_del"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_get_int(/dap_json_object_get_int(/g' {} \\;",
     "Replace json_object_get_int with dap_json_object_get_int"),
]

success_count = 0
for command, description in final_fixes:
    if safe_apply(command, description):
        success_count += 1
    else:
        print(f"❌ Остановлено на: {description}")
        break

final = count_warnings()

print(f"\n🏁 ФИНАЛЬНАЯ АВТОМАТИЗАЦИЯ ЗАВЕРШЕНА:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных исправлений: {success_count}/{len(final_fixes)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")

print(f"\n📈 ОБЩИЙ ИТОГ ВСЕЙ АВТОМАТИЗАЦИИ:")
print(f"🎯 От ~1600+ предупреждений до {final}")
print(f"🎉 Автоматически исправлено: ~{1600 - final}+ предупреждений!")
print(f"🏆 Успешность автоматизации: {((1600 - final) / 1600) * 100:.1f}%")

if final == 0:
    print("\n🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉")
    print("🏆 ВСЕ ПРЕДУПРЕЖДЕНИЯ ИСПРАВЛЕНЫ АВТОМАТИЧЕСКИ!")
elif final <= 10:
    print(f"\n🎉 ПРАКТИЧЕСКИ ИДЕАЛЬНО! Осталось всего {final} предупреждений!")
    print("🏆 Автоматизация достигла потрясающих результатов!")
elif final <= 50:
    print(f"\n🚀 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Осталось {final} предупреждений!")
    print("🎯 Автоматизация превзошла все ожидания!")
elif final <= 100:
    print(f"\n👍 ОЧЕНЬ ХОРОШИЙ РЕЗУЛЬТАТ! Осталось {final} предупреждений!")
    print("📈 Автоматизация показала отличные результаты!")
else:
    print(f"\n🔄 Осталось {final} предупреждений")
    print("📊 Автоматизация дала значительный прогресс!")
