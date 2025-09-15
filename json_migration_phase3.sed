# JSON Migration Phase 3 - Remaining functions and types
# Замена оставшихся json_object_object_add
s/json_object_object_add(/dap_json_object_add_object(/g

# Замена типов в объявлениях переменных
s/json_object\*/dap_json_t*/g

# Замена других функций
s/json_object_array_length(/dap_json_array_length(/g
s/json_object_object_get(/dap_json_object_get(/g
