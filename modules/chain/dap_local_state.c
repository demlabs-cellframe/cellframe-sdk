#define LOG_TAG "dap_local_state"
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "uthash.h"
#include "dap_local_state.h"

typedef struct s_local_state_entry {
    char *name;             // group "\x1f" key
    uint8_t *value;
    size_t value_len;
    dap_nanotime_t ts;
    UT_hash_handle hh;
} s_local_state_entry_t;

static s_local_state_entry_t *s_entries = NULL;
static pthread_rwlock_t s_lock = PTHREAD_RWLOCK_INITIALIZER;

#define LOCAL_STATE_SEP '\x1f'

static char *s_make_name(const char *a_group, const char *a_key)
{
    size_t l_glen = strlen(a_group), l_klen = strlen(a_key);
    char *l_name = DAP_NEW_Z_SIZE(char, l_glen + 1 + l_klen + 1);
    if (!l_name)
        return NULL;
    memcpy(l_name, a_group, l_glen);
    l_name[l_glen] = LOCAL_STATE_SEP;
    memcpy(l_name + l_glen + 1, a_key, l_klen);
    return l_name;
}

int dap_local_state_set(const char *a_group, const char *a_key, const void *a_value, size_t a_value_len)
{
    if (!a_group || !a_key || (!a_value && a_value_len))
        return -1;
    char *l_name = s_make_name(a_group, a_key);
    if (!l_name)
        return -2;
    uint8_t *l_value = a_value_len ? DAP_DUP_SIZE((uint8_t *)a_value, a_value_len) : NULL;
    if (a_value_len && !l_value) {
        DAP_DELETE(l_name);
        return -2;
    }
    pthread_rwlock_wrlock(&s_lock);
    s_local_state_entry_t *l_entry = NULL;
    HASH_FIND_STR(s_entries, l_name, l_entry);
    if (l_entry) {
        DAP_DEL_Z(l_entry->value);
        l_entry->value = l_value;
        l_entry->value_len = a_value_len;
        l_entry->ts = dap_nanotime_now();
    } else {
        l_entry = DAP_NEW_Z(s_local_state_entry_t);
        if (!l_entry) {
            pthread_rwlock_unlock(&s_lock);
            DAP_DEL_Z(l_value);
            DAP_DELETE(l_name);
            return -2;
        }
        l_entry->name = l_name;
        l_entry->value = l_value;
        l_entry->value_len = a_value_len;
        l_entry->ts = dap_nanotime_now();
        HASH_ADD_STR(s_entries, name, l_entry);
    }
    pthread_rwlock_unlock(&s_lock);
    return 0;
}

int dap_local_state_del(const char *a_group, const char *a_key)
{
    if (!a_group || !a_key)
        return -1;
    char *l_name = s_make_name(a_group, a_key);
    if (!l_name)
        return -2;
    pthread_rwlock_wrlock(&s_lock);
    s_local_state_entry_t *l_entry = NULL;
    HASH_FIND_STR(s_entries, l_name, l_entry);
    if (l_entry) {
        HASH_DEL(s_entries, l_entry);
        DAP_DEL_Z(l_entry->value);
        DAP_DELETE(l_entry->name);
        DAP_DELETE(l_entry);
    }
    pthread_rwlock_unlock(&s_lock);
    DAP_DELETE(l_name);
    return l_entry ? 0 : -3;
}

const uint8_t *dap_local_state_get(const char *a_group, const char *a_key, size_t *a_value_len)
{
    if (!a_group || !a_key)
        return NULL;
    char *l_name = s_make_name(a_group, a_key);
    if (!l_name)
        return NULL;
    pthread_rwlock_rdlock(&s_lock);
    s_local_state_entry_t *l_entry = NULL;
    HASH_FIND_STR(s_entries, l_name, l_entry);
    if (l_entry && a_value_len)
        *a_value_len = l_entry->value_len;
    const uint8_t *l_ret = l_entry ? l_entry->value : NULL;
    pthread_rwlock_unlock(&s_lock);
    DAP_DELETE(l_name);
    return l_ret;
}

dap_global_db_obj_t *dap_local_state_get_all(const char *a_group, size_t *a_count)
{
    if (a_count)
        *a_count = 0;
    if (!a_group)
        return NULL;
    size_t l_glen = strlen(a_group);
    pthread_rwlock_rdlock(&s_lock);
    size_t l_count = 0;
    for (s_local_state_entry_t *l_it = s_entries; l_it; l_it = l_it->hh.next)
        if (!strncmp(l_it->name, a_group, l_glen) && l_it->name[l_glen] == LOCAL_STATE_SEP)
            ++l_count;
    dap_global_db_obj_t *l_objs = l_count ? DAP_NEW_Z_COUNT(dap_global_db_obj_t, l_count) : NULL;
    size_t i = 0;
    if (l_objs) {
        for (s_local_state_entry_t *l_it = s_entries; l_it && i < l_count; l_it = l_it->hh.next) {
            if (strncmp(l_it->name, a_group, l_glen) || l_it->name[l_glen] != LOCAL_STATE_SEP)
                continue;
            l_objs[i].key = dap_strdup(l_it->name + l_glen + 1);
            l_objs[i].value = l_it->value_len ? DAP_DUP_SIZE(l_it->value, l_it->value_len) : NULL;
            l_objs[i].value_len = l_it->value_len;
            l_objs[i].timestamp = l_it->ts;
            if (!l_objs[i].key || (l_it->value_len && !l_objs[i].value)) {
                DAP_DEL_Z(l_objs[i].key);
                DAP_DEL_Z(l_objs[i].value);
                break;
            }
            ++i;
        }
    }
    pthread_rwlock_unlock(&s_lock);
    if (a_count)
        *a_count = i;
    return l_objs;
}

void dap_local_state_objs_delete(dap_global_db_obj_t *a_objs, size_t a_count)
{
    for (size_t i = 0; i < a_count; ++i) {
        DAP_DEL_Z(a_objs[i].key);
        DAP_DEL_Z(a_objs[i].value);
    }
    DAP_DEL_Z(a_objs);
}

size_t dap_local_state_count(const char *a_group)
{
    if (!a_group)
        return 0;
    size_t l_glen = strlen(a_group), l_count = 0;
    pthread_rwlock_rdlock(&s_lock);
    for (s_local_state_entry_t *l_it = s_entries; l_it; l_it = l_it->hh.next)
        if (!strncmp(l_it->name, a_group, l_glen) && l_it->name[l_glen] == LOCAL_STATE_SEP)
            ++l_count;
    pthread_rwlock_unlock(&s_lock);
    return l_count;
}

int dap_local_state_clear(const char *a_group)
{
    if (!a_group)
        return -1;
    size_t l_glen = strlen(a_group), l_removed = 0;
    pthread_rwlock_wrlock(&s_lock);
    s_local_state_entry_t *l_it = s_entries, *l_tmp;
    while (l_it) {
        l_tmp = l_it->hh.next;
        if (!strncmp(l_it->name, a_group, l_glen) && l_it->name[l_glen] == LOCAL_STATE_SEP) {
            HASH_DEL(s_entries, l_it);
            DAP_DEL_Z(l_it->value);
            DAP_DELETE(l_it->name);
            DAP_DELETE(l_it);
            ++l_removed;
        }
        l_it = l_tmp;
    }
    pthread_rwlock_unlock(&s_lock);
    return (int)l_removed;
}

int dap_local_state_dump(dap_string_t *a_out)
{
    if (!a_out)
        return -1;
    pthread_rwlock_rdlock(&s_lock);
    uint32_t l_count = (uint32_t)HASH_COUNT(s_entries);
    bool l_ok = dap_string_append_len(a_out, (const char *)&l_count, sizeof(l_count)) != NULL;
    for (s_local_state_entry_t *l_it = s_entries; l_ok && l_it; l_it = l_it->hh.next) {
        uint32_t l_nlen = (uint32_t)(strlen(l_it->name) + 1);
        uint32_t l_vlen = (uint32_t)l_it->value_len;
        uint64_t l_ts = (uint64_t)l_it->ts;
        l_ok = dap_string_append_len(a_out, (const char *)&l_nlen, sizeof(l_nlen))
                && dap_string_append_len(a_out, (const char *)&l_vlen, sizeof(l_vlen))
                && dap_string_append_len(a_out, (const char *)&l_ts, sizeof(l_ts))
                && dap_string_append_len(a_out, l_it->name, l_nlen)
                && (!l_vlen || dap_string_append_len(a_out, (const char *)l_it->value, l_vlen));
    }
    pthread_rwlock_unlock(&s_lock);
    return l_ok ? 0 : -2;
}

int dap_local_state_load(const uint8_t *a_data, size_t a_size)
{
    if (!a_data || a_size < sizeof(uint32_t))
        return -1;
    uint32_t l_count = 0;
    memcpy(&l_count, a_data, sizeof(l_count));
    const uint8_t *l_ptr = a_data + sizeof(l_count), *l_end = a_data + a_size;
    size_t l_loaded = 0;
    for (uint32_t i = 0; i < l_count; ++i) {
        uint32_t l_nlen = 0, l_vlen = 0;
        uint64_t l_ts = 0;
        if ((size_t)(l_end - l_ptr) < sizeof(l_nlen) + sizeof(l_vlen) + sizeof(l_ts))
            return -2;
        memcpy(&l_nlen, l_ptr, sizeof(l_nlen)); l_ptr += sizeof(l_nlen);
        memcpy(&l_vlen, l_ptr, sizeof(l_vlen)); l_ptr += sizeof(l_vlen);
        memcpy(&l_ts, l_ptr, sizeof(l_ts)); l_ptr += sizeof(l_ts);
        if (!l_nlen || (size_t)(l_end - l_ptr) < (size_t)l_nlen + l_vlen || l_ptr[l_nlen - 1])
            return -3;
        const char *l_name = (const char *)l_ptr;
        l_ptr += l_nlen;
        const uint8_t *l_value = l_ptr;
        l_ptr += l_vlen;
        const char *l_sep = strchr(l_name, LOCAL_STATE_SEP);
        if (!l_sep)
            continue;
        char *l_group = DAP_NEW_Z_SIZE(char, (size_t)(l_sep - l_name) + 1);
        if (!l_group)
            return -4;
        memcpy(l_group, l_name, (size_t)(l_sep - l_name));
        int l_rc = dap_local_state_set(l_group, l_sep + 1, l_value, l_vlen);
        DAP_DELETE(l_group);
        if (l_rc)
            return -5;
        ++l_loaded;
    }
    log_it(L_NOTICE, "Local state: restored %zu entries", l_loaded);
    return l_ptr == l_end ? 0 : -6;
}
