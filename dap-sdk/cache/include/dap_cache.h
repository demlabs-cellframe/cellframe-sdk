#include <utlist.h>
#include "dap_hash.h"

typedef struct dap_cache{
    uint64_t data_size;
    uint64_t key_size;
    struct dap_cache *next, *prev;
    byte_t *key_and_data;
}dap_cache_t;

/* Reading config and load data from disk and global_db*/
int dap_cache_init();
/* Save cache to disk and/or global_db*/
void dap_cahce_deinit();

byte_t* dap_cache_pop(const char *a_name_group, int a_idx, size_t *a_out_data_size);
int dap_cache_remove(const char *a_name_group, void *key, size_t a_key_size, void *a_data, size_t a_data_size);
int dap_cache_remove_data(const char *a_name_group, void *a_data, size_t a_data_size);
int dap_cache_append(const char *a_name_group, void *key, size_t a_key_size, void *a_data, size_t a_data_size);
int dap_cache_appbegin(const char *a_name_group, void *key, size_t a_key_size, void *a_data, size_t a_data_size);
byte_t* dap_cache_find(const char *a_name_group, void *key, size_t a_key_size, size_t *a_out_data_size);

int dap_cache_save_file(const char *a_name_group);
int dap_cache_save_global_db(const char *a_name_group);
int dap_cache_flush(const char *a_name_group);
int dap_cache_clear(const char *a_name_group);