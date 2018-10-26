#pragma once

#undef LOG_TAG
#define LOG_TAG "dap_memcached"

#include <stdint.h>
#include <stdbool.h>

#include "dap_common.h"

/**
 * @brief dap_memcached_init
 * @param server_host
 * @param port
 * @param expiration key value in mamcached store. If zero - expiration disable
 * @return
 */
int dap_memcached_init(const char *server_host, uint16_t port, time_t expiration);

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
 * @return
 */
bool dap_memcache_put(const char* key, void *value, size_t value_size);

/**
 * @brief dap_memcache_get
 * @param key
 * @return true if key found
 */
bool dap_memcache_get(const char* key, size_t * value_size, void ** result);
