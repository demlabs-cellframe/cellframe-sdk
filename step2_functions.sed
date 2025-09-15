# ШАГ 2: Замена json-c функций на dap_json функции

# Функции создания объектов
s/json_object_new_object()/dap_json_object_new()/g
s/json_object_new_array()/dap_json_array_new()/g

# Функции освобождения памяти
s/json_object_put(/dap_json_object_free(/g
s/json_object_free(/dap_json_object_free(/g

# Функции работы с массивами
s/json_object_array_add(/dap_json_array_add(/g
s/json_object_array_length(/dap_json_array_length(/g

# Функции работы с объектами
s/json_object_object_get(/dap_json_object_get(/g
s/json_object_to_json_string(/dap_json_to_string(/g
