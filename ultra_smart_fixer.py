#!/usr/bin/env python3
"""
Ультра-умный фиксер для финального рывка
Анализирует конкретные строки и делает точечные исправления
"""
import subprocess
import re
import os

def count_warnings():
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def get_detailed_warnings():
    """Получить детальные предупреждения с анализом"""
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    
    warnings = []
    for line in result.stderr.split('\n'):
        if 'warning:' in line and 'incompatible pointer type' in line:
            match = re.match(r'([^:]+):(\d+):\d+: warning: (.+)', line)
            if match:
                file_path, line_num, message = match.groups()
                warnings.append({
                    'file': file_path,
                    'line': int(line_num),
                    'message': message
                })
    return warnings

def smart_fix_line(file_path, line_num, message):
    """Умное исправление конкретной строки"""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        if line_num > len(lines):
            return False
            
        original_line = lines[line_num - 1]
        fixed_line = original_line
        
        # Умные исправления на основе анализа сообщения
        if 'dap_json_object_add_object' in message and 'argument 3' in message:
            # Проблема с третьим аргументом - обычно json_object_new_*
            if 'json_object_new_string(' in fixed_line:
                fixed_line = re.sub(
                    r'dap_json_object_add_object\(([^,]+), ([^,]+), json_object_new_string\(([^)]+)\)\)',
                    r'dap_json_object_add_string(\1, \2, \3)',
                    fixed_line
                )
            elif 'json_object_new_int(' in fixed_line:
                fixed_line = re.sub(
                    r'dap_json_object_add_object\(([^,]+), ([^,]+), json_object_new_int\(([^)]+)\)\)',
                    r'dap_json_object_add_int(\1, \2, \3)',
                    fixed_line
                )
            elif 'json_object_new_uint64(' in fixed_line:
                fixed_line = re.sub(
                    r'dap_json_object_add_object\(([^,]+), ([^,]+), json_object_new_uint64\(([^)]+)\)\)',
                    r'dap_json_object_add_uint64(\1, \2, \3)',
                    fixed_line
                )
                
        elif 'dap_json_object_add_object' in message and 'argument 1' in message:
            # Проблема с первым аргументом - неправильный тип переменной
            fixed_line = re.sub(r'json_object\*', 'dap_json_t*', fixed_line)
            
        elif 'dap_json_array_add' in message:
            # Проблемы с массивами
            fixed_line = re.sub(r'json_object\*', 'dap_json_t*', fixed_line)
            
        elif 'initialization' in message:
            # Проблемы с инициализацией
            fixed_line = re.sub(
                r'json_object \*([a-z_][a-zA-Z0-9_]*) = dap_json_',
                r'dap_json_t *\1 = dap_json_',
                fixed_line
            )
        
        if fixed_line != original_line:
            lines[line_num - 1] = fixed_line
            with open(file_path, 'w') as f:
                f.writelines(lines)
            return True
            
    except Exception as e:
        print(f"Ошибка при исправлении {file_path}:{line_num}: {e}")
        
    return False

def batch_smart_fix(warnings_batch, batch_num):
    """Пакетное умное исправление"""
    print(f"🧠 Умное исправление пакета {batch_num} ({len(warnings_batch)} предупреждений)")
    
    fixes_applied = 0
    for warning in warnings_batch:
        if smart_fix_line(warning['file'], warning['line'], warning['message']):
            fixes_applied += 1
    
    if not check_build():
        print(f"❌ Пакет {batch_num} сломал сборку, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    warnings = count_warnings()
    print(f"✅ Пакет {batch_num}: {fixes_applied} исправлений, {warnings} предупреждений")
    
    if fixes_applied > 0:
        subprocess.run(["git", "add", "modules/"])
        subprocess.run(["git", "commit", "-m", f"fix: smart batch {batch_num} - {fixes_applied} targeted fixes\\n\\nWarnings: {warnings}"])
    
    return True

# Основная логика
print("🧠 УЛЬТРА-УМНЫЙ ФИКСЕР - ФИНАЛЬНЫЙ РЫВОК!")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Получаем детальные предупреждения
warnings = get_detailed_warnings()
print(f"🔍 Найдено {len(warnings)} детальных предупреждений")

# Разбиваем на пакеты по 50 предупреждений
batch_size = 50
batches = [warnings[i:i+batch_size] for i in range(0, len(warnings), batch_size)]
print(f"📦 Создано {len(batches)} пакетов по {batch_size} предупреждений")

# Обрабатываем пакеты
success_batches = 0
for i, batch in enumerate(batches):
    if batch_smart_fix(batch, i + 1):
        success_batches += 1
    else:
        print(f"❌ Остановлено на пакете {i + 1}")
        break

final = count_warnings()
print(f"\n🏁 УЛЬТРА-УМНЫЕ ИСПРАВЛЕНИЯ:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешных пакетов: {success_batches}/{len(batches)}")
print(f"🔧 Исправлено: {initial - final} предупреждений")

print(f"\n📈 ОБЩИЙ ПРОГРЕСС ВСЕЙ СЕССИИ:")
print(f"🎯 От ~1600+ предупреждений до {final}")
print(f"🎉 Автоматически исправлено: ~{1600 - final}+ предупреждений!")

if final == 0:
    print("\n🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉")
    print("🏆 ВСЕ ПРЕДУПРЕЖДЕНИЯ ИСПРАВЛЕНЫ АВТОМАТИЧЕСКИ!")
elif final < 50:
    print(f"\n🎉 ПОЧТИ ИДЕАЛЬНО! Осталось всего {final} предупреждений!")
elif final < 200:
    print(f"\n🚀 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Осталось {final} предупреждений!")
else:
    print(f"\n👍 ХОРОШИЙ ПРОГРЕСС! Осталось {final} предупреждений")
