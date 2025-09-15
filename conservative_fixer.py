#!/usr/bin/env python3
"""
Консервативный фиксер - только безопасные замены
"""
import os
import subprocess

def apply_conservative_fixes():
    """Применить только безопасные исправления"""
    
    # 1. Исправление двойных замен (если есть)
    subprocess.run([
        "find", "modules/", "-name", "*.c", "-exec", 
        "sed", "-i", "s/dap_dap_json/dap_json/g", "{}", ";"
    ], cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
    
    # 2. Замена оставшихся json_object_object_add на простые паттерны
    patterns = [
        's/json_object_object_add(\([^,]*\), "\([^"]*\)", json_object_new_string("\([^"]*\)"))/dap_json_object_add_string(\\1, "\\2", "\\3")/g',
        's/json_object_object_add(\([^,]*\), "\([^"]*\)", json_object_new_int(\([0-9][^)]*\)))/dap_json_object_add_int(\\1, "\\2", \\3)/g',
        's/json_object_object_add(\([^,]*\), "\([^"]*\)", json_object_new_uint64(\([0-9][^)]*\)))/dap_json_object_add_uint64(\\1, "\\2", \\3)/g',
    ]
    
    for pattern in patterns:
        subprocess.run([
            "find", "modules/", "-name", "*.c", "-exec", 
            "sed", "-i", pattern, "{}", ";"
        ], cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
    
    # 3. Замена простых типов переменных
    subprocess.run([
        "find", "modules/", "-name", "*.c", "-exec", 
        "sed", "-i", "s/json_object \\*\\([a-z_][a-zA-Z0-9_]*\\);/dap_json_t *\\1;/g", "{}", ";"
    ], cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
    
    print("Консервативные исправления применены")

# Откатимся к рабочему состоянию и применим консервативные исправления
print("Откат к последнему рабочему коммиту...")
subprocess.run(["git", "checkout", "HEAD", "--", "modules/"], 
               cwd="/home/naeper/work/python-cellframe/cellframe-sdk")

print("Применение консервативных исправлений...")
apply_conservative_fixes()

print("Проверка результата...")
result = subprocess.run(
    ["make", "clean"], 
    cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
    capture_output=True
)

result = subprocess.run(
    ["make", "-j4"], 
    cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
    capture_output=True, text=True
)

warnings_count = len([line for line in result.stderr.split('\n') if 'warning:' in line])
build_success = result.returncode == 0

print(f"Результат: {warnings_count} предупреждений")
print(f"Сборка: {'✅ SUCCESS' if build_success else '❌ FAILED'}")
