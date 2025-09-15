# Aggressive JSON Types Migration
# Замена всех json_object* на dap_json_t* (кроме заголовков функций)
s/json_object\*/dap_json_t*/g

# Исправление возможных двойных замен
s/dap_dap_json_t/dap_json_t/g
s/dap_json_t_t/dap_json_t/g
