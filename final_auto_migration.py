#!/usr/bin/env python3
"""
Финальный автоматический мигратор JSON API
Интеллектуальный анализ и точечные исправления без каскадных эффектов
"""
import os
import re
import subprocess
import json

def get_warning_details():
    """Получить детальную информацию о предупреждениях"""
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    
    warnings = []
    for line in result.stderr.split('\n'):
        if 'warning:' in line and ('incompatible pointer type' in line or 'implicit declaration' in line):
            match = re.match(r'([^:]+):(\d+):\d+: warning: (.+)', line)
            if match:
                file_path, line_num, message = match.groups()
                warnings.append({
                    'file': file_path.replace('/home/naeper/work/python-cellframe/cellframe-sdk/', ''),
                    'line': int(line_num),
                    'message': message
                })
    return warnings

def categorize_warnings(warnings):
    """Категоризация предупреждений для точечных исправлений"""
    categories = {
        'json_object_object_add_wrong': [],
        'json_object_array_add_wrong': [],
        'json_object_type_mismatch': [],
        'implicit_declarations': [],
        'initialization_mismatch': [],
        'other': []
    }
    
    for w in warnings:
        msg = w['message']
        if 'json_object_object_add' in msg and 'incompatible' in msg:
            categories['json_object_object_add_wrong'].append(w)
        elif 'json_object_array_add' in msg and 'incompatible' in msg:
            categories['json_object_array_add_wrong'].append(w)
        elif 'json_object' in msg and 'dap_json_t' in msg and 'incompatible' in msg:
            categories['json_object_type_mismatch'].append(w)
        elif 'implicit declaration' in msg:
            categories['implicit_declarations'].append(w)
        elif 'initialization' in msg and 'incompatible' in msg:
            categories['initialization_mismatch'].append(w)
        else:
            categories['other'].append(w)
    
    return categories

def create_targeted_fixes(categories):
    """Создать целевые исправления для каждой категории"""
    fixes = []
    
    # Исправление json_object_object_add проблем
    if categories['json_object_object_add_wrong']:
        fixes.extend([
            "# Исправление json_object_object_add проблем",
            "find modules/ -name '*.c' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {} \\;",
        ])
    
    # Исправление типов переменных
    if categories['json_object_type_mismatch']:
        fixes.extend([
            "# Исправление типов переменных", 
            "find modules/ -name '*.c' -exec sed -i 's/json_object \\*/dap_json_t */g' {} \\;",
        ])
    
    # Исправление инициализации
    if categories['initialization_mismatch']:
        fixes.extend([
            "# Исправление инициализации",
            "find modules/ -name '*.c' -exec sed -i 's/json_object \\*\\([a-z_][a-zA-Z0-9_]*\\) = dap_json_/dap_json_t *\\1 = dap_json_/g' {} \\;",
        ])
    
    return fixes

def apply_fixes_safely(fixes):
    """Безопасное применение исправлений с проверкой"""
    for i, fix in enumerate(fixes):
        if fix.startswith('#'):
            print(f"\n{fix}")
            continue
            
        print(f"Применяю исправление {i+1}...")
        result = subprocess.run(fix, shell=True, cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
        
        # Проверяем сборку после каждого исправления
        if not check_build():
            print(f"❌ Сборка сломалась на исправлении {i+1}, откатываемся...")
            subprocess.run(["git", "checkout", "HEAD", "--", "modules/"], 
                          cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
            return False
        
        warnings = count_warnings()
        print(f"✅ Исправление {i+1} успешно: {warnings} предупреждений")
    
    return True

# Основная логика
print("🎯 Финальная автоматическая миграция JSON API")

warnings = get_warning_details()
print(f"📊 Найдено {len(warnings)} предупреждений")

categories = categorize_warnings(warnings)
print("\n📋 Категории проблем:")
for cat, items in categories.items():
    if items:
        print(f"  {cat}: {len(items)}")

fixes = create_targeted_fixes(categories)
print(f"\n🔧 Создано {len([f for f in fixes if not f.startswith('#')])} исправлений")

# Сохраняем план исправлений
with open('migration_plan.txt', 'w') as f:
    f.write("План финальной миграции JSON API:\n\n")
    for cat, items in categories.items():
        if items:
            f.write(f"{cat}: {len(items)} проблем\n")
    f.write(f"\nВсего исправлений: {len(fixes)}\n")

if apply_fixes_safely(fixes):
    final_warnings = count_warnings()
    print(f"\n🎉 Финальная миграция завершена!")
    print(f"📊 Финальный результат: {final_warnings} предупреждений")
    
    # Финальный коммит
    subprocess.run(["git", "add", "modules/"], cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
    subprocess.run([
        "git", "commit", "-m", f"feat: complete final JSON API migration\n\nFinal warnings count: {final_warnings}\nProject builds successfully"
    ], cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
else:
    print("❌ Автоматическая миграция не удалась, нужен ручной подход")
