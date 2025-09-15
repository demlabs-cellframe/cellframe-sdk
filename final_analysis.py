#!/usr/bin/env python3
"""
Финальный анализ оставшихся предупреждений
"""
import subprocess
import re
from collections import defaultdict

def analyze_remaining_warnings():
    """Детальный анализ оставшихся предупреждений"""
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    
    warnings = []
    for line in result.stderr.split('\n'):
        if 'warning:' in line:
            warnings.append(line)
    
    # Анализ по типам
    types = defaultdict(int)
    files = defaultdict(int)
    
    for warning in warnings:
        # Подсчет по файлам
        match = re.match(r'([^:]+):', warning)
        if match:
            file_path = match.group(1)
            file_name = file_path.split('/')[-1]
            files[file_name] += 1
        
        # Подсчет по типам проблем
        if 'incompatible pointer type' in warning:
            if 'dap_json_object_add_object' in warning:
                types['dap_json_object_add_object incompatible'] += 1
            elif 'dap_json_array_add' in warning:
                types['dap_json_array_add incompatible'] += 1
            elif 'initialization' in warning:
                types['initialization incompatible'] += 1
            else:
                types['other incompatible'] += 1
        elif 'implicit declaration' in warning:
            types['implicit declaration'] += 1
        else:
            types['other'] += 1
    
    return warnings, types, files

# Основная логика
warnings, types, files = analyze_remaining_warnings()

print(f"📊 ФИНАЛЬНЫЙ АНАЛИЗ: {len(warnings)} предупреждений")
print("\n🔍 ТОП-10 ТИПОВ ПРОБЛЕМ:")
for problem_type, count in sorted(types.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {count:4d} - {problem_type}")

print("\n📁 ТОП-10 ФАЙЛОВ С ПРОБЛЕМАМИ:")
for file_name, count in sorted(files.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {count:4d} - {file_name}")

print("\n💡 РЕКОМЕНДАЦИИ:")
if types['dap_json_object_add_object incompatible'] > 0:
    print(f"  🎯 {types['dap_json_object_add_object incompatible']} проблем с dap_json_object_add_object - нужны специфичные замены")
if types['dap_json_array_add incompatible'] > 0:
    print(f"  🎯 {types['dap_json_array_add incompatible']} проблем с dap_json_array_add - нужна замена типов")
if types['initialization incompatible'] > 0:
    print(f"  🎯 {types['initialization incompatible']} проблем с инициализацией - нужна замена типов переменных")

# Создаем план следующих действий
with open('final_migration_plan.txt', 'w') as f:
    f.write(f"ФИНАЛЬНЫЙ ПЛАН МИГРАЦИИ JSON API\n")
    f.write(f"================================\n\n")
    f.write(f"Всего предупреждений: {len(warnings)}\n\n")
    f.write("ТОП ПРОБЛЕМ:\n")
    for problem_type, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
        f.write(f"  {count:4d} - {problem_type}\n")
    f.write("\nПРОБЛЕМНЫЕ ФАЙЛЫ:\n")
    for file_name, count in sorted(files.items(), key=lambda x: x[1], reverse=True):
        f.write(f"  {count:4d} - {file_name}\n")

print("\n📝 План сохранен в final_migration_plan.txt")
print("🎯 Готов к созданию специфичных исправлений!")
