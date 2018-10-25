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
void dap_memcached_deinit(void);

bool dap_memcache_put(const char* key, void *value, size_t value_size);
