# ШАГ 3: Замена сигнатур вызовов json_object_object_add

# Замена json_object_object_add с json_object_new_string на dap_json_object_add_string
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_string(\([^)]*\)))/dap_json_object_add_string(\1, \2, \3)/g

# Замена json_object_object_add с json_object_new_int на dap_json_object_add_int  
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_int(\([^)]*\)))/dap_json_object_add_int(\1, \2, \3)/g

# Замена json_object_object_add с json_object_new_uint64 на dap_json_object_add_uint64
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_uint64(\([^)]*\)))/dap_json_object_add_uint64(\1, \2, \3)/g

# Замена json_object_object_add с json_object_new_bool на dap_json_object_add_bool
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_bool(\([^)]*\)))/dap_json_object_add_bool(\1, \2, \3)/g

# Замена остальных json_object_object_add на универсальную функцию
s/json_object_object_add(/dap_json_object_add_object(/g
