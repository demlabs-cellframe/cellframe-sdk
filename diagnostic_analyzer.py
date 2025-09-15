#!/usr/bin/env python3
"""
Диагностический анализатор остальных предупреждений
Детальный анализ для понимания что именно нужно исправить
"""
import subprocess
import re
from collections import defaultdict

def get_all_warnings_detailed():
    """Получить все предупреждения с максимальными деталями"""
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    
    warnings = []
    for line in result.stderr.split('\n'):
        if 'warning:' in line:
            warnings.append(line.strip())
    return warnings

def analyze_warning_patterns(warnings):
    """Детальный анализ паттернов предупреждений"""
    patterns = defaultdict(int)
    files = defaultdict(int)
    functions = defaultdict(int)
    
    for warning in warnings:
        # Анализ по файлам
        file_match = re.search(r'/([^/]+\.c):', warning)
        if file_match:
            files[file_match.group(1)] += 1
        
        # Анализ по функциям
        func_matches = re.findall(r'(dap_json_[a-z_]+|json_object_[a-z_]+)', warning)
        for func in func_matches:
            functions[func] += 1
        
        # Анализ по типам проблем
        if 'incompatible pointer type' in warning:
            if 'argument 1' in warning:
                patterns['argument_1_incompatible'] += 1
            elif 'argument 2' in warning:
                patterns['argument_2_incompatible'] += 1
            elif 'argument 3' in warning:
                patterns['argument_3_incompatible'] += 1
            elif 'initialization' in warning:
                patterns['initialization_incompatible'] += 1
            else:
                patterns['other_incompatible'] += 1
        elif 'implicit declaration' in warning:
            patterns['implicit_declaration'] += 1
        else:
            patterns['other_warning'] += 1
    
    return patterns, files, functions

def create_targeted_sed_scripts(patterns, functions):
    """Создать целевые sed скрипты на основе анализа"""
    scripts = []
    
    # Скрипт для исправления наиболее частых функций
    top_functions = sorted(functions.items(), key=lambda x: x[1], reverse=True)[:5]
    
    if any('json_object_' in func for func, count in top_functions):
        script_content = "# Targeted function replacements\n"
        for func, count in top_functions:
            if func.startswith('json_object_'):
                new_func = func.replace('json_object_', 'dap_json_')
                script_content += f"s/{func}(/{new_func}(/g\n"
        
        with open('targeted_functions.sed', 'w') as f:
            f.write(script_content)
        scripts.append('targeted_functions.sed')
    
    # Скрипт для исправления типов на основе паттернов
    if patterns['argument_1_incompatible'] > 100:
        with open('fix_argument1.sed', 'w') as f:
            f.write("# Fix argument 1 type issues\n")
            f.write("s/json_object\\*/dap_json_t*/g\n")
        scripts.append('fix_argument1.sed')
    
    return scripts

# Основная логика
print("🔍 ДИАГНОСТИЧЕСКИЙ АНАЛИЗ ОСТАЛЬНЫХ ПРЕДУПРЕЖДЕНИЙ")

warnings = get_all_warnings_detailed()
print(f"📊 Всего предупреждений: {len(warnings)}")

patterns, files, functions = analyze_warning_patterns(warnings)

print("\n📋 ТОП-10 ТИПОВ ПРОБЛЕМ:")
for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {count:4d} - {pattern}")

print("\n📁 ТОП-10 ПРОБЛЕМНЫХ ФАЙЛОВ:")
for file_name, count in sorted(files.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {count:4d} - {file_name}")

print("\n🔧 ТОП-10 ПРОБЛЕМНЫХ ФУНКЦИЙ:")
for func, count in sorted(functions.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {count:4d} - {func}")

# Создаем целевые скрипты
scripts = create_targeted_sed_scripts(patterns, functions)
print(f"\n📝 Создано {len(scripts)} целевых sed скриптов")

# Сохраняем детальный отчет
with open('diagnostic_report.txt', 'w') as f:
    f.write(f"ДИАГНОСТИЧЕСКИЙ ОТЧЕТ ОСТАЛЬНЫХ {len(warnings)} ПРЕДУПРЕЖДЕНИЙ\n")
    f.write("=" * 60 + "\n\n")
    
    f.write("ТИПЫ ПРОБЛЕМ:\n")
    for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
        f.write(f"  {count:4d} - {pattern}\n")
    
    f.write("\nПРОБЛЕМНЫЕ ФАЙЛЫ:\n")
    for file_name, count in sorted(files.items(), key=lambda x: x[1], reverse=True):
        f.write(f"  {count:4d} - {file_name}\n")
    
    f.write("\nПРОБЛЕМНЫЕ ФУНКЦИИ:\n")
    for func, count in sorted(functions.items(), key=lambda x: x[1], reverse=True):
        f.write(f"  {count:4d} - {func}\n")

print("📄 Детальный отчет сохранен в diagnostic_report.txt")
print("🎯 Готов к созданию финальных целевых исправлений!")
