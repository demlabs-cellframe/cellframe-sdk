# ШАГ 1: Замена только структур json_object* на dap_json_t*
# Очень точные паттерны для избежания проблем

# Замена в объявлениях переменных
s/json_object \* \([a-z_][a-zA-Z0-9_]*\)/dap_json_t * \1/g
s/json_object\* \([a-z_][a-zA-Z0-9_]*\)/dap_json_t* \1/g
s/json_object\*\([a-z_][a-zA-Z0-9_]*\)/dap_json_t*\1/g

# Замена в присваиваниях NULL
s/json_object \* \([a-z_][a-zA-Z0-9_]*\) = NULL/dap_json_t * \1 = NULL/g
s/json_object\* \([a-z_][a-zA-Z0-9_]*\) = NULL/dap_json_t* \1 = NULL/g
