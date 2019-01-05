#pragma once
#include <stdbool.h>

int dap_chain_global_db_init(const char *a_storage_path);

void dap_chain_global_db_deinit();

char* dap_chain_global_db_get(const char *a_key);
bool dap_chain_global_db_set(const char *a_key, const char *a_value);

char* dap_chain_global_db_load();
bool dap_chain_global_db_save(char *data);
