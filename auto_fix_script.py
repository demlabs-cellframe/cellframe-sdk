#!/usr/bin/env python3
"""
Автоматический скрипт для исправления JSON API миграции
"""
import os
import re
import subprocess
import sys

def get_warnings():
    """Получить список предупреждений"""
    result = subprocess.run(
        ["make", "-j4"], 
        cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
        capture_output=True, text=True
    )
    warnings = []
    for line in result.stderr.split('\n'):
        if 'warning:' in line and 'incompatible pointer type' in line:
            warnings.append(line)
    return warnings

def analyze_warning_patterns(warnings):
    """Анализ паттернов предупреждений"""
    patterns = {}
    for warning in warnings:
        if 'dap_json_object_add_object' in warning:
            patterns['add_object'] = patterns.get('add_object', 0) + 1
        elif 'dap_json_array_add' in warning:
            patterns['array_add'] = patterns.get('array_add', 0) + 1
        elif 'initialization' in warning:
            patterns['initialization'] = patterns.get('initialization', 0) + 1
    return patterns

def create_targeted_sed(patterns):
    """Создать целевой sed скрипт на основе паттернов"""
    sed_commands = []
    
    if patterns.get('initialization', 0) > 0:
        # Исправление инициализации переменных
        sed_commands.extend([
            's/json_object \\*\\([a-z_][a-zA-Z0-9_]*\\) = dap_json_/dap_json_t *\\1 = dap_json_/g',
            's/json_object\\* \\([a-z_][a-zA-Z0-9_]*\\) = dap_json_/dap_json_t* \\1 = dap_json_/g'
        ])
    
    return sed_commands

# Основная логика
warnings = get_warnings()
patterns = analyze_warning_patterns(warnings)

print(f"Найдено {len(warnings)} предупреждений")
print(f"Паттерны: {patterns}")

# Создаем sed скрипт
sed_commands = create_targeted_sed(patterns)
if sed_commands:
    with open('/home/naeper/work/python-cellframe/cellframe-sdk/auto_fix.sed', 'w') as f:
        for cmd in sed_commands:
            f.write(f"{cmd}\n")
    print("Создан auto_fix.sed")
else:
    print("Паттерны не найдены")
