# Fix double replacements created by sed
s/dap_dap_json/dap_json/g
s/dap_json_t_t/dap_json_t/g
s/dap_json_object_new_string(/dap_json_object_new_string(/g

# Remove extra dap_ prefixes
s/dap_dap_/dap_/g
