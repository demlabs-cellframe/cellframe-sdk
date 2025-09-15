#!/usr/bin/env python3
"""
Продвинутый автоматический фиксер JSON API миграции
Анализирует каждое предупреждение и создает точные исправления
"""
import os
import re
import subprocess

def get_all_warnings():
    """Получить все предупреждения с детальной информацией"""
    # Чистая пересборка
    subprocess.run(["make", "clean"], cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build")
    
    result = subprocess.run(
        ["make", "-j4"], 
        cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
        capture_output=True, text=True
    )
    
    warnings = []
    for line in result.stderr.split('\n'):
        if 'warning:' in line:
            # Парсим строку предупреждения
            match = re.match(r'([^:]+):(\d+):\d+: warning: (.+)', line)
            if match:
                file_path, line_num, message = match.groups()
                warnings.append({
                    'file': file_path,
                    'line': int(line_num),
                    'message': message,
                    'original_line': line
                })
    return warnings

def analyze_warning_types(warnings):
    """Анализ типов предупреждений для создания стратегии"""
    types = {}
    for w in warnings:
        msg = w['message']
        if 'incompatible pointer type' in msg:
            if 'dap_json_object_add_object' in msg:
                types['add_object_wrong_type'] = types.get('add_object_wrong_type', 0) + 1
            elif 'dap_json_array_add' in msg:
                types['array_add_wrong_type'] = types.get('array_add_wrong_type', 0) + 1
            elif 'initialization' in msg:
                types['init_wrong_type'] = types.get('init_wrong_type', 0) + 1
            else:
                types['other_incompatible'] = types.get('other_incompatible', 0) + 1
        elif 'implicit declaration' in msg:
            types['implicit_declaration'] = types.get('implicit_declaration', 0) + 1
        else:
            types['other'] = types.get('other', 0) + 1
    return types

def create_mass_fix_commands(warning_types):
    """Создать команды массового исправления на основе анализа"""
    commands = []
    
    if warning_types.get('add_object_wrong_type', 0) > 0:
        # Массовая замена неправильных dap_json_object_add_object
        commands.extend([
            # Исправление вызовов с json_object_new_* функциями
            r"find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\([^,]*\), \([^,]*\), json_object_new_string(\([^)]*\)))/dap_json_object_add_string(\1, \2, \3)/g' {} \;",
            r"find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\([^,]*\), \([^,]*\), json_object_new_int(\([^)]*\)))/dap_json_object_add_int(\1, \2, \3)/g' {} \;",
            r"find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\([^,]*\), \([^,]*\), json_object_new_uint64(\([^)]*\)))/dap_json_object_add_uint64(\1, \2, \3)/g' {} \;",
            r"find modules/ -name '*.c' -exec sed -i 's/dap_json_object_add_object(\([^,]*\), \([^,]*\), json_object_new_bool(\([^)]*\)))/dap_json_object_add_bool(\1, \2, \3)/g' {} \;",
        ])
    
    if warning_types.get('array_add_wrong_type', 0) > 0:
        # Исправление типов для dap_json_array_add
        commands.append(r"find modules/ -name '*.c' -exec sed -i 's/json_object\*/dap_json_t*/g' {} \;")
    
    if warning_types.get('init_wrong_type', 0) > 0:
        # Исправление инициализации
        commands.extend([
            r"find modules/ -name '*.c' -exec sed -i 's/json_object \*\([a-z_][a-zA-Z0-9_]*\) = dap_json_/dap_json_t *\1 = dap_json_/g' {} \;",
            r"find modules/ -name '*.c' -exec sed -i 's/json_object\* \([a-z_][a-zA-Z0-9_]*\) = dap_json_/dap_json_t* \1 = dap_json_/g' {} \;",
        ])
    
    return commands

# Основная логика
print("🔍 Анализ предупреждений...")
warnings = get_all_warnings()
print(f"Найдено {len(warnings)} предупреждений")

warning_types = analyze_warning_types(warnings)
print(f"Типы проблем: {warning_types}")

commands = create_mass_fix_commands(warning_types)
print(f"Создано {len(commands)} команд для исправления")

# Сохраняем команды в файл для выполнения
with open('/home/naeper/work/python-cellframe/cellframe-sdk/mass_fix_commands.sh', 'w') as f:
    f.write("#!/bin/bash\n")
    f.write("# Автоматические команды массового исправления\n")
    for cmd in commands:
        f.write(f"{cmd}\n")

print("Команды сохранены в mass_fix_commands.sh")
print("Готов к выполнению массовых исправлений!")
