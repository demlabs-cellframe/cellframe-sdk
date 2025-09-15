# ШАГ 4: Очистка двойных замен и исправление проблем

# Исправление двойных замен
s/dap_dap_json/dap_json/g
s/dap_json_t_t/dap_json_t/g

# Исправление смешанных типов в инициализации
s/json_object \*\([a-z_][a-zA-Z0-9_]*\) = dap_json_/dap_json_t *\1 = dap_json_/g
s/json_object\* \([a-z_][a-zA-Z0-9_]*\) = dap_json_/dap_json_t* \1 = dap_json_/g
s/json_object\*\([a-z_][a-zA-Z0-9_]*\) = dap_json_/dap_json_t*\1 = dap_json_/g
