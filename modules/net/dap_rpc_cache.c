#include "dap_rpc_cache.h"

#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_time.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define LOG_TAG "dap_rpc_cache"

#define DAP_RPC_CACHE_DEFAULT_TTL_MS     2000ULL
#define DAP_RPC_CACHE_DEFAULT_MAX_BYTES  (16ULL * 1024ULL * 1024ULL)
#define DAP_RPC_CACHE_DEFAULT_MAX_ITEMS  512ULL

typedef struct dap_rpc_cache_entry {
    char *key;              // NULL-terminated
    char *json;             // NULL-terminated, len excludes the terminator
    size_t len;
    uint64_t ts_ms;
    uint64_t epoch;
    UT_hash_handle hh;
} dap_rpc_cache_entry_t;

struct dap_rpc_cache_class {
    char name[64];
    uint64_t ttl_ms;
    size_t max_bytes;
    size_t max_items;
    size_t cur_bytes;
    size_t cur_items;
    uint64_t epoch;
    uint64_t hits, misses, evicts;
    pthread_rwlock_t lock;
    dap_rpc_cache_entry_t *entries;
    struct dap_rpc_cache_class *next;
};

// Per-class presets: a class without [rpc-server] cache_class_* overrides starts here.
static const struct {
    const char *name;
    uint64_t ttl_ms;
    uint64_t max_bytes;
    uint64_t max_items;
} s_class_presets[] = {
    { "block_dump",     300000, 64ull << 20, 32  },
    { "block_list",      60000, 32ull << 20, 256 },
    { "tx_history",      60000, 32ull << 20, 256 },
    { "wallet_outputs",   2000, 16ull << 20, 256 },
    { "dex_history",     10000, 32ull << 20, 128 },
    { "dex_orderbook",    2000, 16ull << 20, 128 },
    { "net_version",      2000,  1ull << 20, 16  },
};

static dap_rpc_cache_class_t *s_classes = NULL;
static pthread_rwlock_t s_classes_lock = PTHREAD_RWLOCK_INITIALIZER;
static bool s_inited = false;
static bool s_enabled = false;
static const char *s_disabled_reason = "not initialized";

static uint64_t s_now_ms(void)
{
    return dap_nanotime_now() / 1000000ULL;
}

static void s_entry_free(dap_rpc_cache_entry_t *a_entry)
{
    if (!a_entry)
        return;
    DAP_DELETE(a_entry->key);
    DAP_DELETE(a_entry->json);
    DAP_DELETE(a_entry);
}

static void s_class_clear_locked(dap_rpc_cache_class_t *a_class)
{
    dap_rpc_cache_entry_t *l_entry = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_class->entries, l_entry, l_tmp) {
        HASH_DEL(a_class->entries, l_entry);
        s_entry_free(l_entry);
    }
    a_class->cur_bytes = 0;
    a_class->cur_items = 0;
}

static void s_class_evict_lru_locked(dap_rpc_cache_class_t *a_class, size_t a_need_bytes)
{
    while (a_class->entries
           && (a_class->cur_items >= a_class->max_items
               || a_class->cur_bytes + a_need_bytes > a_class->max_bytes)) {
        dap_rpc_cache_entry_t *l_entry = NULL, *l_tmp = NULL, *l_oldest = NULL;
        HASH_ITER(hh, a_class->entries, l_entry, l_tmp) {
            if (!l_oldest || l_entry->ts_ms < l_oldest->ts_ms)
                l_oldest = l_entry;
        }
        if (!l_oldest)
            break;
        a_class->cur_bytes -= l_oldest->len + 1;
        a_class->cur_items--;
        a_class->evicts++;
        HASH_DEL(a_class->entries, l_oldest);
        s_entry_free(l_oldest);
    }
}

int dap_rpc_cache_init(void)
{
    // The reply cache exists to absorb public RPC load: without an RPC server it
    // has no user and must not allocate or look anything up. A host that wants it
    // for the local CLI only can set require_rpc_server=false explicitly.
    bool l_master = dap_config_get_item_bool_default(g_config, "rpc-server", "cache_enabled", true);
    bool l_require_rpc = dap_config_get_item_bool_default(g_config, "rpc-server", "cache_require_rpc_server", true);
    bool l_rpc_server = dap_config_get_item_bool_default(g_config, "rpc-server", "enable", false);
    s_enabled = l_master && (!l_require_rpc || l_rpc_server);
    s_disabled_reason = !l_master ? "[rpc-server] cache_enabled=false"
                                 : "RPC server is disabled ([rpc-server] enable=false)";
    s_inited = s_enabled;
    if (!s_enabled)
        log_it(L_NOTICE, "RPC reply cache disabled: %s", s_disabled_reason);
    return 0;
}

void dap_rpc_cache_deinit(void)
{
    pthread_rwlock_wrlock(&s_classes_lock);
    dap_rpc_cache_class_t *l_class = s_classes;
    while (l_class) {
        dap_rpc_cache_class_t *l_next = l_class->next;
        pthread_rwlock_wrlock(&l_class->lock);
        s_class_clear_locked(l_class);
        pthread_rwlock_unlock(&l_class->lock);
        pthread_rwlock_destroy(&l_class->lock);
        DAP_DELETE(l_class);
        l_class = l_next;
    }
    s_classes = NULL;
    pthread_rwlock_unlock(&s_classes_lock);
    s_inited = false;
    s_enabled = false;
    s_disabled_reason = "deinitialized";
}

dap_rpc_cache_class_t *dap_rpc_cache_class_get(const char *a_name)
{
    if (!a_name || !*a_name || !s_enabled)
        return NULL;

    pthread_rwlock_rdlock(&s_classes_lock);
    for (dap_rpc_cache_class_t *l_it = s_classes; l_it; l_it = l_it->next) {
        if (!strcmp(l_it->name, a_name)) {
            pthread_rwlock_unlock(&s_classes_lock);
            return l_it;
        }
    }
    pthread_rwlock_unlock(&s_classes_lock);

    dap_rpc_cache_class_t *l_class = DAP_NEW_Z(dap_rpc_cache_class_t);
    if (!l_class) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    dap_strncpy(l_class->name, a_name, sizeof(l_class->name) - 1);
    uint64_t l_def_ttl = DAP_RPC_CACHE_DEFAULT_TTL_MS,
             l_def_bytes = DAP_RPC_CACHE_DEFAULT_MAX_BYTES,
             l_def_items = DAP_RPC_CACHE_DEFAULT_MAX_ITEMS;
    for (size_t i = 0; i < sizeof(s_class_presets) / sizeof(s_class_presets[0]); i++) {
        if (!strcmp(s_class_presets[i].name, a_name)) {
            l_def_ttl = s_class_presets[i].ttl_ms;
            l_def_bytes = s_class_presets[i].max_bytes;
            l_def_items = s_class_presets[i].max_items;
            break;
        }
    }
    char *l_key = dap_strdup_printf("cache_class_%s_ttl_ms", a_name);
    l_class->ttl_ms = dap_config_get_item_uint64_default(g_config, "rpc-server", l_key, l_def_ttl);
    DAP_DELETE(l_key);
    l_key = dap_strdup_printf("cache_class_%s_max_bytes", a_name);
    l_class->max_bytes = dap_config_get_item_uint64_default(g_config, "rpc-server", l_key, l_def_bytes);
    DAP_DELETE(l_key);
    l_key = dap_strdup_printf("cache_class_%s_max_items", a_name);
    l_class->max_items = dap_config_get_item_uint64_default(g_config, "rpc-server", l_key, l_def_items);
    DAP_DELETE(l_key);
    pthread_rwlock_init(&l_class->lock, NULL);

    pthread_rwlock_wrlock(&s_classes_lock);
    // Another thread may have created it meanwhile; keep the first one.
    for (dap_rpc_cache_class_t *l_it = s_classes; l_it; l_it = l_it->next) {
        if (!strcmp(l_it->name, a_name)) {
            pthread_rwlock_unlock(&s_classes_lock);
            pthread_rwlock_destroy(&l_class->lock);
            DAP_DELETE(l_class);
            return l_it;
        }
    }
    l_class->next = s_classes;
    s_classes = l_class;
    pthread_rwlock_unlock(&s_classes_lock);

    log_it(L_INFO, "RPC cache class '%s' registered (ttl %" DAP_UINT64_FORMAT_U " ms, "
                   "%zu bytes max, %zu items max)",
           l_class->name, l_class->ttl_ms, l_class->max_bytes, l_class->max_items);
    return l_class;
}

dap_rpc_cache_class_t *dap_rpc_cache_class_find(const char *a_name)
{
    if (!a_name || !*a_name)
        return NULL;
    dap_rpc_cache_class_t *l_found = NULL;
    pthread_rwlock_rdlock(&s_classes_lock);
    for (dap_rpc_cache_class_t *l_it = s_classes; l_it; l_it = l_it->next) {
        if (!strcmp(l_it->name, a_name)) {
            l_found = l_it;
            break;
        }
    }
    pthread_rwlock_unlock(&s_classes_lock);
    return l_found;
}

bool dap_rpc_cache_is_enabled(void)
{
    return s_enabled;
}

bool dap_rpc_cache_class_has_entries(dap_rpc_cache_class_t *a_class)
{
    if (!a_class)
        return false;
    pthread_rwlock_rdlock(&a_class->lock);
    bool l_has = a_class->entries != NULL;
    pthread_rwlock_unlock(&a_class->lock);
    return l_has;
}

char *dap_rpc_cache_get(dap_rpc_cache_class_t *a_class, const char *a_key, size_t *a_out_len)
{
    if (!a_class || !a_key)
        return NULL;
    if (a_out_len)
        *a_out_len = 0;
    uint64_t l_now = s_now_ms();
    char *l_reply = NULL;
    dap_rpc_cache_entry_t *l_entry = NULL;
    pthread_rwlock_rdlock(&a_class->lock);
    HASH_FIND_STR(a_class->entries, a_key, l_entry);
    if (l_entry && l_entry->epoch == a_class->epoch
            && (l_now - l_entry->ts_ms) <= a_class->ttl_ms) {
        l_reply = dap_strdup(l_entry->json);
        if (l_reply && a_out_len)
            *a_out_len = l_entry->len;
        __atomic_add_fetch(&a_class->hits, 1, __ATOMIC_RELAXED);
    } else {
        __atomic_add_fetch(&a_class->misses, 1, __ATOMIC_RELAXED);
    }
    pthread_rwlock_unlock(&a_class->lock);
    return l_reply;
}

void dap_rpc_cache_put(dap_rpc_cache_class_t *a_class, const char *a_key,
                       const char *a_json, size_t a_len)
{
    if (!a_class || !a_key || !a_json)
        return;
    if (!a_len)
        a_len = strlen(a_json);
    if (a_len > a_class->max_bytes)
        return;
    char *l_copy = dap_strdup(a_json);
    char *l_key = dap_strdup(a_key);
    if (!l_copy || !l_key) {
        DAP_DEL_MULTY(l_copy, l_key);
        return;
    }
    uint64_t l_now = s_now_ms();
    dap_rpc_cache_entry_t *l_entry = NULL;
    pthread_rwlock_wrlock(&a_class->lock);
    HASH_FIND_STR(a_class->entries, a_key, l_entry);
    if (l_entry) {
        a_class->cur_bytes -= l_entry->len;
        DAP_DELETE(l_entry->json);
        l_entry->json = l_copy;
        l_entry->len = a_len;
        l_entry->ts_ms = l_now;
        l_entry->epoch = a_class->epoch;
        a_class->cur_bytes += a_len;
        DAP_DELETE(l_key);
    } else {
        s_class_evict_lru_locked(a_class, a_len + 1);
        dap_rpc_cache_entry_t *l_new = DAP_NEW_Z(dap_rpc_cache_entry_t);
        if (!l_new) {
            DAP_DEL_MULTY(l_copy, l_key);
            pthread_rwlock_unlock(&a_class->lock);
            return;
        }
        l_new->key = l_key;
        l_new->json = l_copy;
        l_new->len = a_len;
        l_new->ts_ms = l_now;
        l_new->epoch = a_class->epoch;
        HASH_ADD_STR(a_class->entries, key, l_new);
        a_class->cur_bytes += a_len + 1;
        a_class->cur_items++;
    }
    pthread_rwlock_unlock(&a_class->lock);
}

char *dap_rpc_cache_get_or_build(dap_rpc_cache_class_t *a_class, const char *a_key,
                                 dap_rpc_cache_build_cb_t a_build, void *a_ctx,
                                 size_t *a_out_len)
{
    if (!a_class || !a_key || !a_build)
        return NULL;
    if (a_out_len)
        *a_out_len = 0;

    uint64_t l_now = s_now_ms();
    char *l_reply = NULL;
    size_t l_reply_len = 0;
    dap_rpc_cache_entry_t *l_entry = NULL;

    pthread_rwlock_rdlock(&a_class->lock);
    HASH_FIND_STR(a_class->entries, a_key, l_entry);
    if (l_entry && l_entry->epoch == a_class->epoch
            && (l_now - l_entry->ts_ms) <= a_class->ttl_ms) {
        l_reply_len = l_entry->len;
        l_reply = dap_strdup(l_entry->json);
        __atomic_add_fetch(&a_class->hits, 1, __ATOMIC_RELAXED);
    }
    pthread_rwlock_unlock(&a_class->lock);
    if (l_reply) {
        if (a_out_len)
            *a_out_len = l_reply_len;
        return l_reply;
    }

    __atomic_add_fetch(&a_class->misses, 1, __ATOMIC_RELAXED);

    // Build outside any lock: the builder may take chain/ledger locks.
    char *l_built = NULL;
    size_t l_built_len = 0;
    if (a_build(a_ctx, &l_built, &l_built_len) != 0 || !l_built)
        return NULL;
    l_built_len = strlen(l_built);
    // The build may have taken a while: the TTL comparison below and the new
    // entry's timestamp must use the current time, not the pre-build one.
    l_now = s_now_ms();

    pthread_rwlock_wrlock(&a_class->lock);
    HASH_FIND_STR(a_class->entries, a_key, l_entry);
    if (l_entry) {
        // Single-flight: someone built it while we were building ours.
        if (l_entry->epoch == a_class->epoch && (l_now - l_entry->ts_ms) <= a_class->ttl_ms) {
            l_reply_len = l_entry->len;
            l_reply = dap_strdup(l_entry->json);
            DAP_DELETE(l_built);
        } else {
            a_class->cur_bytes -= l_entry->len + 1;
            a_class->cur_items--;
            HASH_DEL(a_class->entries, l_entry);
            s_entry_free(l_entry);
        }
    }
    if (!l_reply) {
        if (l_built_len > a_class->max_bytes) {
            // Too big for the class: serve it once without caching.
            l_reply = l_built;
            l_reply_len = l_built_len;
            l_built = NULL;
        } else {
            s_class_evict_lru_locked(a_class, l_built_len + 1);
            dap_rpc_cache_entry_t *l_new = DAP_NEW_Z(dap_rpc_cache_entry_t);
            char *l_new_key = dap_strdup(a_key);
            if (l_new && l_new_key) {
                l_new->key = l_new_key;
                l_new->json = l_built;
                l_new->len = l_built_len;
                l_new->ts_ms = l_now;
                l_new->epoch = a_class->epoch;
                HASH_ADD_STR(a_class->entries, key, l_new);
                a_class->cur_bytes += l_built_len + 1;
                a_class->cur_items++;
                l_reply_len = l_built_len;
                l_reply = dap_strdup(l_built);
                l_built = NULL; // owned by the entry now
            } else {
                DAP_DELETE(l_new_key);
                DAP_DELETE(l_new);
            }
        }
    }
    pthread_rwlock_unlock(&a_class->lock);

    if (l_built)
        DAP_DELETE(l_built);
    if (l_reply && a_out_len)
        *a_out_len = l_reply_len;
    return l_reply;
}

void dap_rpc_cache_invalidate(dap_rpc_cache_class_t *a_class)
{
    if (!a_class)
        return;
    pthread_rwlock_wrlock(&a_class->lock);
    a_class->epoch++;
    s_class_clear_locked(a_class);
    pthread_rwlock_unlock(&a_class->lock);
}

void dap_rpc_cache_invalidate_name(const char *a_name)
{
    if (!a_name || !s_enabled)
        return;
    pthread_rwlock_rdlock(&s_classes_lock);
    for (dap_rpc_cache_class_t *l_it = s_classes; l_it; l_it = l_it->next) {
        if (!strcmp(l_it->name, a_name)) {
            dap_rpc_cache_invalidate(l_it);
            break;
        }
    }
    pthread_rwlock_unlock(&s_classes_lock);
}

void dap_rpc_cache_invalidate_prefix(dap_rpc_cache_class_t *a_class, const char *a_prefix)
{
    if (!a_class || !a_prefix || !*a_prefix)
        return;
    size_t l_prefix_len = strlen(a_prefix);
    pthread_rwlock_wrlock(&a_class->lock);
    dap_rpc_cache_entry_t *l_entry = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_class->entries, l_entry, l_tmp) {
        if (!strncmp(l_entry->key, a_prefix, l_prefix_len)) {
            a_class->cur_bytes -= l_entry->len + 1;
            a_class->cur_items--;
            HASH_DEL(a_class->entries, l_entry);
            s_entry_free(l_entry);
        }
    }
    pthread_rwlock_unlock(&a_class->lock);
}

void dap_rpc_cache_invalidate_prefix_name(const char *a_name, const char *a_prefix)
{
    if (!s_enabled)
        return;
    dap_rpc_cache_class_t *l_class = dap_rpc_cache_class_find(a_name);
    if (l_class)
        dap_rpc_cache_invalidate_prefix(l_class, a_prefix);
}

void dap_rpc_cache_invalidate_all(void)
{
    pthread_rwlock_rdlock(&s_classes_lock);
    for (dap_rpc_cache_class_t *l_it = s_classes; l_it; l_it = l_it->next)
        dap_rpc_cache_invalidate(l_it);
    pthread_rwlock_unlock(&s_classes_lock);
}

size_t dap_rpc_cache_stats(char *a_buf, size_t a_buf_size)
{
    if (!a_buf || !a_buf_size)
        return 0;
    size_t l_off = 0;
    l_off += snprintf(a_buf + l_off, a_buf_size - l_off,
                      "rpc_cache: %s%s%s\n", s_enabled ? "enabled" : "disabled",
                      s_enabled ? "" : " - ", s_enabled ? "" : s_disabled_reason);
    pthread_rwlock_rdlock(&s_classes_lock);
    for (dap_rpc_cache_class_t *l_it = s_classes; l_it && l_off < a_buf_size; l_it = l_it->next) {
        pthread_rwlock_rdlock(&l_it->lock);
        l_off += snprintf(a_buf + l_off, a_buf_size - l_off,
                          "  %s: items %zu/%zu, bytes %zu/%zu, hits %" DAP_UINT64_FORMAT_U
                          ", misses %" DAP_UINT64_FORMAT_U ", evicts %" DAP_UINT64_FORMAT_U "\n",
                          l_it->name, l_it->cur_items, l_it->max_items,
                          l_it->cur_bytes, l_it->max_bytes,
                          l_it->hits, l_it->misses, l_it->evicts);
        pthread_rwlock_unlock(&l_it->lock);
    }
    pthread_rwlock_unlock(&s_classes_lock);
    return l_off;
}
