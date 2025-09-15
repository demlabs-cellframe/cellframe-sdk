#!/bin/bash
# Автоматические команды массового исправления
find modules/ -name '*.c' -exec sed -i 's/json_object\*/dap_json_t*/g' {} \;
find modules/ -name '*.c' -exec sed -i 's/json_object \*\([a-z_][a-zA-Z0-9_]*\) = dap_json_/dap_json_t *\1 = dap_json_/g' {} \;
find modules/ -name '*.c' -exec sed -i 's/json_object\* \([a-z_][a-zA-Z0-9_]*\) = dap_json_/dap_json_t* \1 = dap_json_/g' {} \;
