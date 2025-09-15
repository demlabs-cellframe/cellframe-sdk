# JSON API Migration Script
# Замена основных типов
s/json_object\*/dap_json_t*/g

# Замена функций создания объектов
s/json_object_new_object()/dap_json_object_new()/g
s/json_object_new_array()/dap_json_array_new()/g

# Замена функций освобождения памяти
s/json_object_free(/dap_json_object_free(/g

# Замена функций добавления в массив
s/json_object_array_add(/dap_json_array_add(/g

# Замена json_object_object_add с новыми строками - самые частые паттерны
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_string(\([^)]*\)))/dap_json_object_add_string(\1, \2, \3)/g
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_int(\([^)]*\)))/dap_json_object_add_int(\1, \2, \3)/g
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_uint64(\([^)]*\)))/dap_json_object_add_uint64(\1, \2, \3)/g
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_bool(\([^)]*\)))/dap_json_object_add_bool(\1, \2, \3)/g

# Замена остальных json_object_object_add на универсальную
s/json_object_object_add(/dap_json_object_add_object(/g

# Замена других функций
s/json_object_object_get(/dap_json_object_get(/g
s/json_object_to_json_string(/dap_json_to_string(/g
