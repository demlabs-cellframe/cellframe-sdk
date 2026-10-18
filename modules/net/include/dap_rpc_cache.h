/*
 * Universal cache for ready-made (already serialized) RPC replies.
 *
 * A cache class groups replies of one kind (block dump, tx history, wallet
 * outputs, DEX orderbook, ...) and carries its own policy from the node
 * config ([rpc_cache] class_<name>_{ttl_ms,max_bytes,max_items}). Invalidation
 * is epoch-based: a chain/ledger event bumps the class epoch and every entry
 * of the class becomes stale at once.
 *
 * The builder callback produces the serialized payload on a miss. It is called
 * without any engine lock held; the engine copies the payload (and owns that
 * copy), the caller gets its own copy to free with DAP_DELETE.
 */
#ifndef DAP_RPC_CACHE_H
#define DAP_RPC_CACHE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dap_rpc_cache_class dap_rpc_cache_class_t;

/* Returns 0 on success. Build the serialized reply in *a_out_json (allocated
 * with DAP_NEW/DAP_strdup, the engine frees it) and its length in *a_out_len.
 * A non-zero return or a NULL payload means "nothing to cache". */
typedef int (*dap_rpc_cache_build_cb_t)(void *a_ctx, char **a_out_json, size_t *a_out_len);

int  dap_rpc_cache_init(void);
void dap_rpc_cache_deinit(void);

/* Find or lazily create the class with the configured policy. */
dap_rpc_cache_class_t *dap_rpc_cache_class_get(const char *a_name);

/* Cached payload copy (DAP_DELETE by the caller), or NULL on miss/stale. */
char *dap_rpc_cache_get(dap_rpc_cache_class_t *a_class, const char *a_key, size_t *a_out_len);
/* Store (or refresh) one payload. The engine keeps its own copy. */
void dap_rpc_cache_put(dap_rpc_cache_class_t *a_class, const char *a_key,
                       const char *a_json, size_t a_len);

/* Cached payload copy (DAP_DELETE by the caller) or the freshly built one. */
char *dap_rpc_cache_get_or_build(dap_rpc_cache_class_t *a_class, const char *a_key,
                                 dap_rpc_cache_build_cb_t a_build, void *a_ctx,
                                 size_t *a_out_len);

/* Drop every entry of the class (bumps its epoch). */
void dap_rpc_cache_invalidate(dap_rpc_cache_class_t *a_class);
/* Drop every entry of every class. */
void dap_rpc_cache_invalidate_all(void);
/* Drop every entry of the named class (no-op when it was never used). */
void dap_rpc_cache_invalidate_name(const char *a_name);

/* Human-readable counters into a_buf; returns the number of bytes written. */
size_t dap_rpc_cache_stats(char *a_buf, size_t a_buf_size);

#ifdef __cplusplus
}
#endif

#endif // DAP_RPC_CACHE_H
