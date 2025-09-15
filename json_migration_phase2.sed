# JSON Migration Phase 2 - Object addition functions
# Замена json_object_object_add с простыми строками
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_string(\([^)]*\)))/dap_json_object_add_string(\1, \2, \3)/g
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_int(\([^)]*\)))/dap_json_object_add_int(\1, \2, \3)/g
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_uint64(\([^)]*\)))/dap_json_object_add_uint64(\1, \2, \3)/g
s/json_object_object_add(\([^,]*\), \([^,]*\), json_object_new_bool(\([^)]*\)))/dap_json_object_add_bool(\1, \2, \3)/g
