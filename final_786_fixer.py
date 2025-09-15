#!/usr/bin/env python3
"""
Финальный фиксер для остальных 786 предупреждений
Быстрые и точные исправления
"""
import subprocess

def count_warnings():
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def quick_fix(command, description):
    print(f"⚡ {description}")
    subprocess.run(command, shell=True)
    
    if not check_build():
        print(f"❌ Сборка сломалась, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    warnings = count_warnings()
    print(f"✅ Успешно: {warnings} предупреждений")
    
    if warnings < count_warnings():  # Если есть улучшение
        subprocess.run(["git", "add", "modules/"])
        subprocess.run(["git", "commit", "-m", f"fix: {description}\\n\\nWarnings: {warnings}"])
    
    return True

print("⚡ ФИНАЛЬНЫЙ ФИКСЕР ДЛЯ 786 ПРЕДУПРЕЖДЕНИЙ")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Быстрые финальные исправления
quick_fixes = [
    ("find modules/ -name '*.c' -exec sed -i 's/json_object \\*/dap_json_t */g' {} \\;",
     "Replace all remaining json_object* with dap_json_t*"),
    
    ("find modules/ -name '*.c' -exec sed -i 's/dap_dap_json/dap_json/g' {} \\;",
     "Clean double dap_dap_json"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/dap_json_t_t/dap_json_t/g' {} \\;",
     "Clean double dap_json_t_t"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {} \\;",
     "Replace remaining json_object_object_add"),
]

success_count = 0
for command, description in quick_fixes:
    if quick_fix(command, description):
        success_count += 1
    else:
        break

final = count_warnings()
print(f"\n🏁 ФИНАЛЬНЫЕ ИСПРАВЛЕНИЯ:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных исправлений: {success_count}/{len(quick_fixes)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")

if final == 0:
    print("🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉")
elif final < 50:
    print("🎉 ПОЧТИ ИДЕАЛЬНО! Осталось меньше 50 предупреждений!")
elif final < 200:
    print("🚀 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Осталось меньше 200 предупреждений!")
else:
    print(f"🔄 Осталось {final} предупреждений")
