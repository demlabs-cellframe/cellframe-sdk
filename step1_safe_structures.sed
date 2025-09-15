# ШАГ 1: Безопасная замена структур - только локальные переменные
# НЕ трогаем заголовки функций

# Замена в объявлениях локальных переменных (с отступами)
s/^    json_object \* \([a-z_][a-zA-Z0-9_]*\)/    dap_json_t * \1/g
s/^        json_object \* \([a-z_][a-zA-Z0-9_]*\)/        dap_json_t * \1/g
s/^            json_object \* \([a-z_][a-zA-Z0-9_]*\)/            dap_json_t * \1/g
s/^                json_object \* \([a-z_][a-zA-Z0-9_]*\)/                dap_json_t * \1/g

# Замена в присваиваниях с отступами
s/^    json_object\* \([a-z_][a-zA-Z0-9_]*\)/    dap_json_t* \1/g
s/^        json_object\* \([a-z_][a-zA-Z0-9_]*\)/        dap_json_t* \1/g
s/^            json_object\* \([a-z_][a-zA-Z0-9_]*\)/            dap_json_t* \1/g
s/^                json_object\* \([a-z_][a-zA-Z0-9_]*\)/                dap_json_t* \1/g
