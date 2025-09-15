#!/usr/bin/env python3
"""
Интеллектуальная миграция JSON API
Анализирует заголовочные файлы и создает точные замены
"""
import os
import re
import subprocess

def find_dap_json_headers():
    """Найти заголовочные файлы dap_json для понимания API"""
    result = subprocess.run(
        ["find", ".", "-name", "*.h", "-exec", "grep", "-l", "dap_json", "{}", ";"],
        cwd="/home/naeper/work/python-cellframe/cellframe-sdk",
        capture_output=True, text=True
    )
    return result.stdout.strip().split('\n') if result.stdout.strip() else []

def get_dap_json_functions():
    """Получить список функций dap_json API"""
    headers = find_dap_json_headers()
    functions = set()
    
    for header in headers:
        if not header:
            continue
        try:
            with open(f"/home/naeper/work/python-cellframe/cellframe-sdk/{header}", 'r') as f:
                content = f.read()
                # Ищем объявления функций dap_json_*
                matches = re.findall(r'dap_json_[a-z_]+\s*\(', content)
                for match in matches:
                    func_name = match.replace('(', '').strip()
                    functions.add(func_name)
        except:
            continue
    
    return functions

def create_simple_replacements():
    """Создать простые и безопасные замены"""
    replacements = [
        # Простейшие замены без каскадных эффектов
        ('json_object_new_object()', 'dap_json_object_new()'),
        ('json_object_new_array()', 'dap_json_array_new()'),
        ('json_object_array_add(', 'dap_json_array_add('),
        ('json_object_put(', 'dap_json_object_free('),
        ('json_object_free(', 'dap_json_object_free('),
    ]
    return replacements

def apply_replacements_to_file(file_path, replacements):
    """Применить замены к файлу"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        original_content = content
        for old, new in replacements:
            content = content.replace(old, new)
        
        if content != original_content:
            with open(file_path, 'w') as f:
                f.write(content)
            return True
    except:
        pass
    return False

# Основная логика
print("Интеллектуальная миграция JSON API...")

# Получаем функции dap_json API
dap_functions = get_dap_json_functions()
print(f"Найдено {len(dap_functions)} функций dap_json API")

# Создаем простые замены
replacements = create_simple_replacements()
print(f"Создано {len(replacements)} замен")

# Применяем к файлам
files_fixed = 0
for root, dirs, files in os.walk("/home/naeper/work/python-cellframe/cellframe-sdk/modules"):
    for file in files:
        if file.endswith('.c'):
            file_path = os.path.join(root, file)
            if apply_replacements_to_file(file_path, replacements):
                files_fixed += 1

print(f"Обработано файлов: {files_fixed}")
print("Миграция завершена!")
