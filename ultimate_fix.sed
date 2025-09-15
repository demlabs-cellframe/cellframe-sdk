# Ultimate JSON Migration Fix - All patterns in one pass

# Исправление двойных замен сначала
s/dap_dap_json/dap_json/g

# Замена всех json_object* на dap_json_t* (кроме параметров функций)
s/json_object\*/dap_json_t*/g

# Замена всех оставшихся json_object_* функций
s/json_object_new_object()/dap_json_object_new()/g
s/json_object_new_array()/dap_json_array_new()/g
s/json_object_new_string(/dap_json_object_new_string(/g
s/json_object_new_int(/dap_json_object_new_int(/g
s/json_object_new_uint64(/dap_json_object_new_uint64(/g
s/json_object_new_bool(/dap_json_object_new_bool(/g

s/json_object_put(/dap_json_object_free(/g
s/json_object_free(/dap_json_object_free(/g
s/json_object_array_add(/dap_json_array_add(/g
s/json_object_array_length(/dap_json_array_length(/g
s/json_object_object_get(/dap_json_object_get(/g
s/json_object_object_add(/dap_json_object_add_object(/g
s/json_object_to_json_string(/dap_json_to_string(/g

# Исправление специфичных паттернов после замен
s/dap_json_object_add_object(\([^,]*\), \([^,]*\), dap_json_object_new_string(\([^)]*\)))/dap_json_object_add_string(\1, \2, \3)/g
s/dap_json_object_add_object(\([^,]*\), \([^,]*\), dap_json_object_new_int(\([^)]*\)))/dap_json_object_add_int(\1, \2, \3)/g
s/dap_json_object_add_object(\([^,]*\), \([^,]*\), dap_json_object_new_uint64(\([^)]*\)))/dap_json_object_add_uint64(\1, \2, \3)/g
s/dap_json_object_add_object(\([^,]*\), \([^,]*\), dap_json_object_new_bool(\([^)]*\)))/dap_json_object_add_bool(\1, \2, \3)/g

# Финальная очистка двойных замен
s/dap_dap_json/dap_json/g
s/dap_json_t_t/dap_json_t/g
