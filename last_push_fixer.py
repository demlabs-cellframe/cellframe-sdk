#!/usr/bin/env python3
"""
Последний рывок - финальные простые исправления
"""
import subprocess

def count_warnings():
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def last_fix(command, description):
    print(f"🎯 {description}")
    subprocess.run(command, shell=True)
    
    if not check_build():
        print(f"❌ Сборка сломалась, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    warnings = count_warnings()
    improvement = warnings < count_warnings() if warnings > 0 else True
    
    print(f"✅ Результат: {warnings} предупреждений")
    
    if improvement:
        subprocess.run(["git", "add", "modules/"])
        subprocess.run(["git", "commit", "-m", f"fix: {description}\\n\\nWarnings: {warnings}"])
    
    return True

print("🎯 ПОСЛЕДНИЙ РЫВОК К ФИНИШУ!")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Последние простые исправления
last_fixes = [
    ("find modules/ -name '*.c' -exec sed -i 's/dap_dap_json/dap_json/g' {} \\;",
     "Final cleanup of dap_dap_json"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {} \\;",
     "Convert remaining json_object_object_add"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_to_json_string(/dap_json_to_string(/g' {} \\;",
     "Convert json_object_to_json_string"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_get_string(/dap_json_object_get_string(/g' {} \\;",
     "Convert json_object_get_string"),
]

success_count = 0
for command, description in last_fixes:
    if last_fix(command, description):
        success_count += 1
    else:
        break

final = count_warnings()

print(f"\n🏁 ПОСЛЕДНИЙ РЫВОК ЗАВЕРШЕН:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных исправлений: {success_count}/{len(last_fixes)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")

print(f"\n📈 ОБЩИЙ ПРОГРЕСС ВСЕЙ СЕССИИ:")
print(f"🎯 От ~1600+ предупреждений до {final}")
print(f"🎉 Исправлено автоматически: ~{1600 - final}+ предупреждений!")

if final == 0:
    print("\n🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉")
    print("🏆 ВСЕ ПРЕДУПРЕЖДЕНИЯ ИСПРАВЛЕНЫ АВТОМАТИЧЕСКИ!")
elif final < 100:
    print(f"\n🎉 ПОЧТИ ИДЕАЛЬНО! Осталось всего {final} предупреждений!")
    print("🚀 Это уже легко исправить вручную!")
elif final < 300:
    print(f"\n🚀 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Осталось {final} предупреждений!")
    print("👍 Автоматизация показала превосходные результаты!")
else:
    print(f"\n🔄 Осталось {final} предупреждений")
    print("📈 Но прогресс впечатляющий!")
