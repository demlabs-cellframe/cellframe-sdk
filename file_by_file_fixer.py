#!/usr/bin/env python3
"""
Фиксер файл за файлом - обрабатывает самые проблемные файлы по отдельности
"""
import subprocess
import re

def count_warnings():
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    return len([line for line in result.stderr.split('\n') if 'warning:' in line])

def check_build():
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True)
    return result.returncode == 0

def get_top_problem_files():
    """Получить файлы с наибольшим количеством предупреждений"""
    subprocess.run(["make", "clean"], cwd="build")
    result = subprocess.run(["make", "-j4"], cwd="build", capture_output=True, text=True)
    
    file_counts = {}
    for line in result.stderr.split('\n'):
        if 'warning:' in line:
            match = re.match(r'([^:]+):', line)
            if match:
                file_path = match.group(1)
                file_name = file_path.split('/')[-1]
                file_counts[file_name] = file_counts.get(file_name, 0) + 1
    
    # Возвращаем топ-5 файлов
    return sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]

def fix_single_file(file_name, description):
    """Исправить один конкретный файл"""
    print(f"🎯 {description}: {file_name}")
    
    commands = [
        f"find modules/ -name '{file_name}' -exec sed -i 's/json_object \\*/dap_json_t */g' {{}} \\;",
        f"find modules/ -name '{file_name}' -exec sed -i 's/json_object_object_add(/dap_json_object_add_object(/g' {{}} \\;",
        f"find modules/ -name '{file_name}' -exec sed -i 's/dap_dap_json/dap_json/g' {{}} \\;",
    ]
    
    for cmd in commands:
        subprocess.run(cmd, shell=True)
    
    if not check_build():
        print(f"❌ Файл {file_name} сломал сборку, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", f"modules/"])
        return False
    
    warnings = count_warnings()
    print(f"✅ Файл {file_name} исправлен: {warnings} предупреждений")
    
    subprocess.run(["git", "add", "modules/"])
    subprocess.run(["git", "commit", "-m", f"fix: migrate JSON API in {file_name}\\n\\nWarnings: {warnings}"])
    return True

print("🎯 ФИКСЕР ФАЙЛ ЗА ФАЙЛОМ")

initial = count_warnings()
print(f"📊 Начальные предупреждения: {initial}")

# Получаем топ проблемных файлов
top_files = get_top_problem_files()
print("\n📁 ТОП-5 ПРОБЛЕМНЫХ ФАЙЛОВ:")
for file_name, count in top_files:
    print(f"  {count:3d} предупреждений - {file_name}")

# Исправляем файлы по одному
success_count = 0
for file_name, count in top_files:
    if count > 20:  # Исправляем только файлы с большим количеством проблем
        if fix_single_file(file_name, f"Fix {count} warnings"):
            success_count += 1
        else:
            print(f"❌ Остановлено на файле: {file_name}")
            break

final = count_warnings()
print(f"\n🏁 ИСПРАВЛЕНИЯ ПО ФАЙЛАМ:")
print(f"📊 {initial} → {final} предупреждений")
print(f"✅ Успешно исправленных файлов: {success_count}")
print(f"🔧 Исправлено: {initial - final} предупреждений")

if final == 0:
    print("🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉")
elif final < 100:
    print("🎉 ПОЧТИ ЗАВЕРШЕНО! Осталось меньше 100 предупреждений!")
elif final < 300:
    print("🚀 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Осталось меньше 300 предупреждений!")
else:
    print(f"🔄 Осталось {final} предупреждений")
