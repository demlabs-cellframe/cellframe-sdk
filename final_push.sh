#!/bin/bash
# Финальный рывок - простые bash команды

echo "🎯 ФИНАЛЬНЫЙ РЫВОК К ЗАВЕРШЕНИЮ МИГРАЦИИ"

# Функция для проверки сборки
check_build() {
    cd build && make -j4 > /dev/null 2>&1
    return $?
}

# Функция для подсчета предупреждений
count_warnings() {
    cd build && make clean > /dev/null 2>&1 && make -j4 2>&1 | grep "warning:" | wc -l
}

initial=$(count_warnings)
echo "📊 Начальные предупреждения: $initial"

# Простые исправления по одному
fixes=(
    "find modules/ -name '*.c' -exec sed -i 's/json_object_get_string(/dap_json_object_get_string(/g' {} \;"
    "find modules/ -name '*.c' -exec sed -i 's/json_object_is_type(/dap_json_object_is_type(/g' {} \;"  
    "find modules/ -name '*.c' -exec sed -i 's/json_object_array_get_idx(/dap_json_array_get_idx(/g' {} \;"
    "find modules/ -name '*.c' -exec sed -i 's/json_object_object_get(/dap_json_object_get(/g' {} \;"
)

descriptions=(
    "Replace json_object_get_string"
    "Replace json_object_is_type"
    "Replace json_object_array_get_idx"
    "Replace json_object_object_get"
)

success=0
for i in "${!fixes[@]}"; do
    echo "🔧 ${descriptions[$i]}"
    
    # Применяем исправление
    eval "${fixes[$i]}"
    
    # Проверяем сборку
    if check_build; then
        warnings=$(count_warnings)
        echo "✅ Успешно: $warnings предупреждений"
        
        # Коммитим
        git add modules/
        git commit -m "fix: ${descriptions[$i]}

Warnings: $warnings"
        ((success++))
    else
        echo "❌ Сборка сломалась, откатываемся..."
        git checkout HEAD -- modules/
        break
    fi
done

final=$(count_warnings)
echo ""
echo "🏁 ФИНАЛЬНЫЙ РЫВОК ЗАВЕРШЕН:"
echo "📊 $initial → $final предупреждений"
echo "✅ Успешных исправлений: $success/${#fixes[@]}"
echo "🔧 Исправлено: $((initial - final)) предупреждений"

echo ""
echo "📈 ОБЩИЙ ИТОГ ВСЕЙ АВТОМАТИЗАЦИИ:"
echo "🎯 От ~1600+ предупреждений до $final"
echo "🎉 Автоматически исправлено: ~$((1600 - final))+ предупреждений!"
echo "🏆 Успешность: $(echo "scale=1; ((1600 - $final) / 1600) * 100" | bc)%"

if [ $final -eq 0 ]; then
    echo ""
    echo "🎉🎉🎉 МИГРАЦИЯ JSON API ПОЛНОСТЬЮ ЗАВЕРШЕНА! 🎉🎉🎉"
    echo "🏆 ВСЕ ПРЕДУПРЕЖДЕНИЯ ИСПРАВЛЕНЫ АВТОМАТИЧЕСКИ!"
elif [ $final -lt 100 ]; then
    echo ""
    echo "🎉 ПОЧТИ ИДЕАЛЬНО! Осталось всего $final предупреждений!"
elif [ $final -lt 300 ]; then
    echo ""
    echo "🚀 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! Осталось $final предупреждений!"
else
    echo ""
    echo "👍 ХОРОШИЙ ПРОГРЕСС! Осталось $final предупреждений"
fi
