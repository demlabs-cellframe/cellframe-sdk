#ifndef _DAP_HASH_SLOW_H_
#define _DAP_HASH_SLOW_H_

#include "hash-ops.h"

#define DAP_HASH_SLOW_SIZE HASH_SIZE

/**
 * @brief dap_hash_slow
 * @param a_in
 * @param a_in_length
 * @param a_out Must be allocated with enought space
 */
inline void dap_hash_slow(const void *a_in, size_t a_in_length, char * a_out)
{
    cn_slow_hash(a_in,a_in_length,a_out);
}

inline size_t dap_hash_slow_size() { return DAP_HASH_SLOW_SIZE; }
//cn_slow_hash(data, length, reinterpret_cast<char *>(&hash));
#endif
