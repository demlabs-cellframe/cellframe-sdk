#!/usr/bin/env python3
"""
Итеративный фиксер - применяет исправления порциями с проверкой сборки
"""
import subprocess
import time

def check_build():
    """Проверить сборку проекта"""
    result = subprocess.run(
        ["make", "-j4"], 
        cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
        capture_output=True
    )
    return result.returncode == 0

def count_warnings():
    """Подсчитать предупреждения"""
    subprocess.run(["make", "clean"], cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build")
    result = subprocess.run(
        ["make", "-j4"], 
        cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
        capture_output=True, text=True
    )
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def apply_fix_batch(batch_num):
    """Применить порцию исправлений"""
    fixes = [
        # Batch 1: Простые замены типов
        [
            "find modules/ -name '*.c' -exec sed -i 's/json_object \\*\\([a-z_][a-zA-Z0-9_]*\\);/dap_json_t *\\1;/g' {} \\;",
        ],
        # Batch 2: Исправление json_object_object_add
        [
            "find modules/ -name '*.c' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {} \\;",
        ],
        # Batch 3: Исправление типов в присваиваниях
        [
            "find modules/ -name '*.c' -exec sed -i 's/json_object \\*\\([a-z_][a-zA-Z0-9_]*\\) =/dap_json_t *\\1 =/g' {} \\;",
        ],
        # Batch 4: Очистка двойных замен
        [
            "find modules/ -name '*.c' -exec sed -i 's/dap_dap_json/dap_json/g' {} \\;",
            "find modules/ -name '*.c' -exec sed -i 's/dap_json_t_t/dap_json_t/g' {} \\;",
        ]
    ]
    
    if batch_num < len(fixes):
        for cmd in fixes[batch_num]:
            subprocess.run(cmd, shell=True, cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
        return True
    return False

# Основная логика
print("🚀 Итеративное исправление с проверкой сборки...")

initial_warnings = count_warnings()
print(f"Начальное количество предупреждений: {initial_warnings}")

batch = 0
while batch < 4:
    print(f"\n📦 Применение batch {batch + 1}...")
    
    if not apply_fix_batch(batch):
        break
        
    # Проверяем сборку
    if not check_build():
        print(f"❌ Сборка сломалась на batch {batch + 1}, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"], 
                      cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
        break
    
    # Считаем предупреждения
    warnings = count_warnings()
    print(f"✅ Batch {batch + 1} успешен: {warnings} предупреждений")
    
    # Коммитим успешный batch
    subprocess.run(["git", "add", "modules/"], cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
    subprocess.run([
        "git", "commit", "-m", f"fix: apply JSON migration batch {batch + 1}\n\nWarnings: {initial_warnings} → {warnings}"
    ], cwd="/home/naeper/work/python-cellframe/cellframe-sdk")
    
    initial_warnings = warnings
    batch += 1

print(f"\n🏁 Итеративное исправление завершено. Финальные предупреждения: {count_warnings()}")
