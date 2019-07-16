#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "dap_common.h"

/**
 * @brief dap_memcached_init
 * @param server_host
 * @param port
 * @return
 */
int dap_memcached_init(const char *server_host, uint16_t port);

/**
 * @brief is_dap_memcache_enable
 * @return
 */
bool dap_memcache_is_enable(void);

/**
 * @brief dap_memcached_deinit
 */
void dap_memcached_deinit(void);

/**
 * @brief dap_memcache_put
 * @param key
 * @param value
 * @param value_size
 * @param expiration if 0 value is never expire
 * @return
 */
bool dap_memcache_put(const char* key, void *value, size_t value_size, time_t expiration);

/**
 * @brief dap_memcache_get
 * @param key
 * @return true if key found
 */
bool dap_memcache_get(const char* key, size_t * value_size, void ** result);

/**
 * @brief dap_memcache_delete
 * @param key
 * @return
 */
bool dap_memcache_delete(const char* key);
