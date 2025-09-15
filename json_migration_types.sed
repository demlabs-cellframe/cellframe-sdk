# JSON Types Migration - Variable declarations only
# Замена типов только в простых объявлениях переменных
s/json_object\* \([a-z_][a-zA-Z0-9_]*\);/dap_json_t* \1;/g
s/json_object\*\([a-z_][a-zA-Z0-9_]*\);/dap_json_t*\1;/g
s/json_object \* \([a-z_][a-zA-Z0-9_]*\);/dap_json_t * \1;/g

# Замена в простых присваиваниях
s/json_object\* \([a-z_][a-zA-Z0-9_]*\) = NULL;/dap_json_t* \1 = NULL;/g
s/json_object\*\([a-z_][a-zA-Z0-9_]*\) = NULL;/dap_json_t*\1 = NULL;/g
