#!/usr/bin/env python3
"""
Простой финальный фиксер для остальных 826 предупреждений
Только безопасные замены
"""
import subprocess

def count_warnings():
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def simple_fix(command, description):
    print(f"🔧 {description}")
    subprocess.run(command, shell=True)
    
    if not check_build():
        print(f"❌ Сборка сломалась, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    warnings = count_warnings()
    print(f"✅ Успешно: {warnings} предупреждений")
    
    subprocess.run(["git", "add", "modules/"])
    subprocess.run(["git", "commit", "-m", f"fix: {description}\\n\\nWarnings: {warnings}"])
    return True

print("🔧 ПРОСТОЙ ФИНАЛЬНЫЙ ФИКСЕР")

initial = count_warnings()
print(f"📊 Остальные предупреждения: {initial}")

# Только самые безопасные исправления
safe_fixes = [
    ("find modules/ -name '*.c' -exec sed -i 's/dap_dap_json/dap_json/g' {} \\;",
     "Clean any remaining double replacements"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {} \\;",
     "Replace remaining json_object_object_add calls"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_array_length(/dap_json_array_length(/g' {} \\;",
     "Replace json_object_array_length calls"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_object_get(/dap_json_object_get(/g' {} \\;",
     "Replace json_object_object_get calls"),
]

success_count = 0
for command, description in safe_fixes:
    if simple_fix(command, description):
        success_count += 1
    else:
        break

final = count_warnings()
print(f"\n🏁 ПРОСТЫЕ ИСПРАВЛЕНИЯ ЗАВЕРШЕНЫ:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных исправлений: {success_count}/{len(safe_fixes)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")

if final == 0:
    print("🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉")
elif final < 100:
    print("🎉 ПОЧТИ ИДЕАЛЬНО! Осталось меньше 100 предупреждений!")
elif final < 300:
    print("🚀 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Осталось меньше 300 предупреждений!")
else:
    print(f"🔄 Осталось {final} предупреждений для финальной доработки")
