# Minimal JSON Migration - Only the safest replacements
# Только замена функций, НЕ типов

# 1. Самые безопасные замены функций
s/json_object_new_object()/dap_json_object_new()/g
s/json_object_new_array()/dap_json_array_new()/g

# 2. Замена функций освобождения
s/json_object_put(/dap_json_object_free(/g
s/json_object_free(/dap_json_object_free(/g

# 3. Замена функций массивов
s/json_object_array_add(/dap_json_array_add(/g
