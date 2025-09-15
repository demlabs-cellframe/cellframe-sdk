# JSON object_add Migration - Very precise patterns
# Замена только очень конкретных паттернов json_object_object_add

# С двойными кавычками и простыми переменными
s/json_object_object_add(\([a-z_][a-zA-Z0-9_]*\), "\([^"]*\)", json_object_new_string("\([^"]*\)"))/dap_json_object_add_string(\1, "\2", "\3")/g

# С переменными в качестве значений строк
s/json_object_object_add(\([a-z_][a-zA-Z0-9_]*\), "\([^"]*\)", json_object_new_string(\([a-z_][a-zA-Z0-9_]*\)))/dap_json_object_add_string(\1, "\2", \3)/g

# С числовыми значениями
s/json_object_object_add(\([a-z_][a-zA-Z0-9_]*\), "\([^"]*\)", json_object_new_int(\([a-z_][a-zA-Z0-9_]*\)))/dap_json_object_add_int(\1, "\2", \3)/g
s/json_object_object_add(\([a-z_][a-zA-Z0-9_]*\), "\([^"]*\)", json_object_new_uint64(\([a-z_][a-zA-Z0-9_]*\)))/dap_json_object_add_uint64(\1, "\2", \3)/g

# С булевыми значениями
s/json_object_object_add(\([a-z_][a-zA-Z0-9_]*\), "\([^"]*\)", json_object_new_bool(\([a-z_][a-zA-Z0-9_]*\)))/dap_json_object_add_bool(\1, "\2", \3)/g
