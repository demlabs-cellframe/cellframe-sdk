# Safe JSON API Migration Script - Step by step
# Этап 1: Замена базовых функций создания объектов
s/json_object_new_object()/dap_json_object_new()/g
s/json_object_new_array()/dap_json_array_new()/g

# Этап 2: Замена функций освобождения памяти
s/json_object_free(/dap_json_object_free(/g

# Этап 3: Замена функций массивов
s/json_object_array_add(/dap_json_array_add(/g

# Этап 4: Замена простых типов переменных (но не в заголовках функций)
s/json_object\* \([a-z_][a-zA-Z0-9_]*\) =/dap_json_t* \1 =/g
s/json_object\*\([a-z_][a-zA-Z0-9_]*\) =/dap_json_t*\1 =/g
