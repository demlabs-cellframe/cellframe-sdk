# Smart JSON Migration - Based on actual warning patterns
# 1. Замена json_object_put на dap_json_object_free (самая частая проблема)
s/json_object_put(/dap_json_object_free(/g

# 2. Замена json_object_array_add на dap_json_array_add
s/json_object_array_add(/dap_json_array_add(/g

# 3. Замена json_object_free на dap_json_object_free
s/json_object_free(/dap_json_object_free(/g

# 4. Замена создания объектов
s/json_object_new_object()/dap_json_object_new()/g
s/json_object_new_array()/dap_json_array_new()/g
s/json_object_new_string(/dap_json_object_new_string(/g

# 5. Замена простых типов переменных (только локальные переменные)
s/json_object \*\([a-z_][a-zA-Z0-9_]*\) =/dap_json_t *\1 =/g
s/json_object\* \([a-z_][a-zA-Z0-9_]*\) =/dap_json_t* \1 =/g
s/json_object\*\([a-z_][a-zA-Z0-9_]*\) =/dap_json_t*\1 =/g
