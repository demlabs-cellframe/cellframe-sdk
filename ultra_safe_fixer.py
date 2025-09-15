#!/usr/bin/env python3
"""
Ультра-безопасный фиксер - только гарантированно работающие замены
"""
import subprocess

def count_warnings():
    """Подсчитать предупреждения"""
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    """Проверить сборку"""
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def safe_replace(pattern, description):
    """Безопасная замена с проверкой"""
    print(f"🔧 {description}")
    
    # Применяем замену
    cmd = f"find modules/ -name '*.c' -exec sed -i '{pattern}' {{}} \\;"
    subprocess.run(cmd, shell=True)
    
    # Проверяем сборку
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
print("🛡️ Ультра-безопасная миграция JSON API")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Применяем только самые безопасные замены по одной
safe_fixes = [
    # Только простейшие замены функций создания
    ('s/json_object_new_object()/dap_json_object_new()/g', 
     'Replace json_object_new_object with dap_json_object_new'),
    
    ('s/json_object_new_array()/dap_json_array_new()/g',
     'Replace json_object_new_array with dap_json_array_new'),
     
    # Замена функций освобождения памяти
    ('s/json_object_put(/dap_json_object_free(/g',
     'Replace json_object_put with dap_json_object_free'),
     
    ('s/json_object_free(/dap_json_object_free(/g',
     'Replace json_object_free with dap_json_object_free'),
     
    # Замена функций массивов
    ('s/json_object_array_add(/dap_json_array_add(/g',
     'Replace json_object_array_add with dap_json_array_add'),
]

success_count = 0
for pattern, description in safe_fixes:
    if safe_replace(pattern, description):
        success_count += 1
    else:
        break

final = count_warnings()
print(f"\n🏁 Ультра-безопасная миграция завершена:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных замен: {success_count}/{len(safe_fixes)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")
