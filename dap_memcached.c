#include "dap_memcached.h"
#include <libmemcached/memcached.h>

static memcached_st *_memc;
static time_t _expiration;

int dap_memcached_init(const char *server_host, uint16_t port, time_t expiration)
{
    _expiration = expiration;
    memcached_return rc;
    memcached_server_st *servers = NULL;

    char *test_key = "test_key";
    char *test_value = "test_value";

    _memc = memcached_create(NULL);

    servers= memcached_server_list_append(servers, server_host, port, &rc);
    rc= memcached_server_push(_memc, servers);

    if (rc != MEMCACHED_SUCCESS) {
        log_it(L_ERROR, "Couldn't add server: %s", memcached_strerror(_memc, rc));
        return -1;
    }

    if(dap_memcache_put(test_key, test_value, strlen(test_value)) != true) {
        return -2;
    }

    if(_expiration == 0) {
        log_it(L_WARNING, "Init memcached module without expiration value");
    }

    return 0;
}


bool dap_memcache_put(const char* key, void *value, size_t value_size)
{
    memcached_return rc;
    rc = memcached_set(_memc, key, strlen(key), value, value_size, _expiration, (uint32_t)0);
    if (rc != MEMCACHED_SUCCESS) {
        log_it(L_ERROR, "%s", memcached_strerror(_memc, rc));
        return false;
    }
    return true;
}

bool dap_memcache_get(const char* key, size_t * value_size, void ** result)
{
    memcached_return rc;
    *result = memcached_get(_memc, key, strlen(key), value_size, NULL, &rc);
    return rc == MEMCACHED_SUCCESS;
}

/**
 * @brief dap_memcached_deinit
 */
void dap_memcached_deinit()
{

}
