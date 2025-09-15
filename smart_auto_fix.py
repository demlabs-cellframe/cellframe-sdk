#!/usr/bin/env python3
"""
Умный автоматический скрипт для JSON API миграции
Анализирует конкретные ошибки и создает точные исправления
"""
import os
import re
import subprocess

def get_detailed_warnings():
    """Получить детальный список предупреждений с номерами строк"""
    result = subprocess.run(
        ["make", "clean"], 
        cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
        capture_output=True, text=True
    )
    
    result = subprocess.run(
        ["make", "-j4"], 
        cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
        capture_output=True, text=True
    )
    
    warnings = []
    for line in result.stderr.split('\n'):
        if 'warning:' in line and 'incompatible pointer type' in line:
            # Парсим: /path/file.c:123:45: warning: message
            match = re.match(r'([^:]+):(\d+):\d+: warning: (.+)', line)
            if match:
                file_path, line_num, message = match.groups()
                warnings.append({
                    'file': file_path,
                    'line': int(line_num),
                    'message': message
                })
    return warnings

def fix_file_issues(file_path, issues):
    """Исправить проблемы в конкретном файле"""
    if not os.path.exists(file_path):
        return False
        
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    changes_made = False
    
    for issue in sorted(issues, key=lambda x: x['line'], reverse=True):
        line_idx = issue['line'] - 1
        if line_idx >= len(lines):
            continue
            
        original_line = lines[line_idx]
        fixed_line = original_line
        
        # Исправления на основе типа проблемы
        if 'dap_json_object_add_object' in issue['message']:
            # Проблемы с dap_json_object_add_object - часто нужно заменить на add_string
            if 'json_object_new_string(' in fixed_line:
                # Заменяем на dap_json_object_add_string
                pattern = r'dap_json_object_add_object\(([^,]+), ([^,]+), json_object_new_string\(([^)]+)\)\)'
                replacement = r'dap_json_object_add_string(\1, \2, \3)'
                fixed_line = re.sub(pattern, replacement, fixed_line)
            elif 'json_object_new_int(' in fixed_line:
                pattern = r'dap_json_object_add_object\(([^,]+), ([^,]+), json_object_new_int\(([^)]+)\)\)'
                replacement = r'dap_json_object_add_int(\1, \2, \3)'
                fixed_line = re.sub(pattern, replacement, fixed_line)
            elif 'json_object_new_uint64(' in fixed_line:
                pattern = r'dap_json_object_add_object\(([^,]+), ([^,]+), json_object_new_uint64\(([^)]+)\)\)'
                replacement = r'dap_json_object_add_uint64(\1, \2, \3)'
                fixed_line = re.sub(pattern, replacement, fixed_line)
                
        elif 'dap_json_array_add' in issue['message']:
            # Проблемы с типами в dap_json_array_add
            if 'json_object' in fixed_line and 'dap_json_t' not in fixed_line:
                # Заменяем json_object* на dap_json_t* в этой строке
                fixed_line = re.sub(r'json_object\*', 'dap_json_t*', fixed_line)
                
        elif 'initialization' in issue['message']:
            # Проблемы с инициализацией
            pattern = r'json_object \*([a-z_][a-zA-Z0-9_]*) = dap_json_'
            replacement = r'dap_json_t *\1 = dap_json_'
            fixed_line = re.sub(pattern, replacement, fixed_line)
        
        if fixed_line != original_line:
            lines[line_idx] = fixed_line
            changes_made = True
            print(f"Исправлено в {file_path}:{issue['line']}")
    
    if changes_made:
        with open(file_path, 'w') as f:
            f.writelines(lines)
        return True
    return False

# Основная логика
warnings = get_detailed_warnings()
print(f"Найдено {len(warnings)} предупреждений для автоматического исправления")

# Группируем предупреждения по файлам
files_issues = {}
for warning in warnings:
    file_path = warning['file']
    if file_path not in files_issues:
        files_issues[file_path] = []
    files_issues[file_path].append(warning)

# Исправляем каждый файл
total_fixed = 0
for file_path, issues in files_issues.items():
    if fix_file_issues(file_path, issues):
        total_fixed += len(issues)
        print(f"Исправлен файл {file_path}: {len(issues)} проблем")

print(f"Всего исправлено: {total_fixed} проблем")
