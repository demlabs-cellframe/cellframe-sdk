#!/usr/bin/env python3
"""
Фиксер без зависаний - только быстрые операции
"""
import subprocess
import signal

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Операция превысила время ожидания")

def quick_count():
    """Быстрый подсчет без зависаний"""
    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(30)  # 30 секунд максимум
        
        result = subprocess.run(
            ["make", "-j4"], 
            cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
            capture_output=True, text=True, timeout=25
        )
        
        signal.alarm(0)  # Отключаем таймер
        return len([line for line in result.stderr.split('\n') if 'warning:' in line])
        
    except (subprocess.TimeoutExpired, TimeoutError):
        signal.alarm(0)
        print("⏰ Подсчет предупреждений занял слишком много времени")
        return -1

def quick_build_check():
    """Быстрая проверка сборки"""
    try:
        result = subprocess.run(
            ["make", "-j4"], 
            cwd="/home/naeper/work/python-cellframe/cellframe-sdk/build",
            capture_output=True, timeout=30
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("⏰ Сборка занимает слишком много времени")
        return False

def no_hang_fix(command, description):
    print(f"⚡ {description}")
    
    # Применяем команду
    result = subprocess.run(command, shell=True, timeout=10)
    if result.returncode != 0:
        print(f"❌ Ошибка выполнения")
        return False
    
    # Быстрая проверка сборки
    if not quick_build_check():
        print(f"❌ Проблемы со сборкой, откатываемся...")
        subprocess.run(["git", "checkout", "HEAD", "--", "modules/"])
        return False
    
    print(f"✅ Применено успешно")
    
    # Коммитим
    subprocess.run(["git", "add", "modules/"])
    subprocess.run(["git", "commit", "-m", f"fix: {description}"])
    
    return True

print("⚡ ФИКСЕР БЕЗ ЗАВИСАНИЙ")

# Только самые простые и быстрые исправления
quick_fixes = [
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_get_string(/dap_json_object_get_string(/g' {} \\;",
     "Replace json_object_get_string"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_is_type(/dap_json_object_is_type(/g' {} \\;",
     "Replace json_object_is_type"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_get_int(/dap_json_object_get_int(/g' {} \\;",
     "Replace json_object_get_int"),
     
    ("find modules/ -name '*.c' -exec sed -i 's/json_object_del(/dap_json_object_del(/g' {} \\;",
     "Replace json_object_del"),
]

success_count = 0
for command, description in quick_fixes:
    try:
        if no_hang_fix(command, description):
            success_count += 1
        else:
            break
    except Exception as e:
        print(f"❌ Исключение: {e}")
        break

print(f"\n🏁 БЫСТРЫЕ ИСПРАВЛЕНИЯ:")
print(f"✅ Успешных исправлений: {success_count}/{len(quick_fixes)}")

# Финальный подсчет (если получится)
try:
    final = quick_count()
    if final >= 0:
        print(f"📊 Финальные предупреждения: {final}")
        print(f"📈 Общий прогресс: ~1600+ → {final}")
        print(f"🎉 Автоматизация: {((1600 - final) / 1600) * 100:.1f}% завершено")
except:
    print("📊 Финальный подсчет недоступен (возможно, длительная сборка)")

print("⚡ Фиксер без зависаний завершен!")
