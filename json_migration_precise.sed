# Precise JSON Migration - Only safe replacements
# 1. Замена простых функций создания объектов (безопасно)
s/json_object_new_object()/dap_json_object_new()/g
s/json_object_new_array()/dap_json_array_new()/g

# 2. Замена функций освобождения памяти (безопасно)
s/json_object_free(/dap_json_object_free(/g

# 3. Замена функций массивов (безопасно)
s/json_object_array_add(/dap_json_array_add(/g

# 4. Замена только в простых объявлениях переменных (очень точно)
s/json_object\* \([a-z_][a-zA-Z0-9_]*\) = json_object_new_object()/dap_json_t* \1 = dap_json_object_new()/g
s/json_object\* \([a-z_][a-zA-Z0-9_]*\) = json_object_new_array()/dap_json_t* \1 = dap_json_array_new()/g

# 5. Замена простых вызовов json_object_object_add с литералами
s/json_object_object_add(\([^,()]*\), "\([^"]*\)", json_object_new_string("\([^"]*\)"))/dap_json_object_add_string(\1, "\2", "\3")/g
s/json_object_object_add(\([^,()]*\), "\([^"]*\)", json_object_new_int(\([^)]*\)))/dap_json_object_add_int(\1, "\2", \3)/g
s/json_object_object_add(\([^,()]*\), "\([^"]*\)", json_object_new_uint64(\([^)]*\)))/dap_json_object_add_uint64(\1, "\2", \3)/g
