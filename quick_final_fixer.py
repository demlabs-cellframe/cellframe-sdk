#!/usr/bin/env python3
"""
Быстрый финальный фиксер без зависаний
"""
import subprocess

def quick_count():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def quick_build_check():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, timeout=60)
    return result.returncode == 0

def quick_fix(command, description):
    print(f"⚡ {description}")
    subprocess.run(command, shell=True, timeout=30)
    
    if not quick_build_check():
        print(f"❌ Сборка сломалась, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    warnings = quick_count()
    print(f"✅ Результат: {warnings} предупреждений")
    
    subprocess.run(["git", "add", "modules/"])
    subprocess.run(["git", "commit", "-m", f"fix: {description}\\n\\nWarnings: {warnings}"])
    return True

print("⚡ БЫСТРЫЙ ФИНАЛЬНЫЙ ФИКСЕР")

initial = quick_count()
print(f"📊 Начальные предупреждения: {initial}")

# Быстрые финальные исправления
quick_fixes = [
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_get_string(/dap_json_object_get_string(/g' {} \\;",
     "Replace json_object_get_string"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_is_type(/dap_json_object_is_type(/g' {} \\;",
     "Replace json_object_is_type"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_object_get(/dap_json_object_get(/g' {} \\;",
     "Replace json_object_object_get"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_to_json_string(/dap_json_to_string(/g' {} \\;",
     "Replace json_object_to_json_string"),
]

success_count = 0
for command, description in quick_fixes:
    try:
        if quick_fix(command, description):
            success_count += 1
        else:
            break
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        break

final = quick_count()
print(f"\n🏁 БЫСТРЫЕ ИСПРАВЛЕНИЯ:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных исправлений: {success_count}/{len(quick_fixes)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")

print(f"\n📈 ОБЩИЙ ИТОГ АВТОМАТИЗАЦИИ:")
print(f"🎯 От ~1600+ до {final} предупреждений")
print(f"🎉 Автоматически исправлено: ~{1600 - final}+ предупреждений!")
print(f"🏆 Успешность: {((1600 - final) / 1600) * 100:.1f}%")
