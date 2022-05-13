#include <string.h>
#include <stdlib.h>

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_chain.h"
#include "dap_time.h"

#define LOG_TAG "dap_chain_global_db_remote"

// Default time of a node address expired in hours
#define NODE_TIME_EXPIRED_DEFAULT 720

/**
 * @brief Gets last id of the log.
 *
 * @param a_group_name a group name string
 * @return Returns id if succeessful.
 */
uint64_t dap_db_log_get_group_last_id(const char *a_group_name)
{
    uint64_t result = 0;
    dap_store_obj_t *l_last_obj = dap_chain_global_db_get_last(a_group_name);
    if(l_last_obj) {
        result = l_last_obj->id;
        dap_store_obj_free_one(l_last_obj);
    }
    return result;
}

/**
 * @brief A function for a thread for reading a log list
 *
 * @param arg a pointer to the log list structure
 * @return Returns NULL.
 */
static void *s_list_thread_proc(void *arg)
{
    dap_db_log_list_t *l_dap_db_log_list = (dap_db_log_list_t *)arg;
    uint32_t l_time_store_lim_hours = dap_config_get_item_uint32_default(g_config, "resources", "dap_global_db_time_store_limit", 72);
    uint64_t l_limit_time = l_time_store_lim_hours ? dap_gdb_time_now() - dap_gdb_time_from_sec(l_time_store_lim_hours * 3600) : 0;
    for (dap_list_t *l_groups = l_dap_db_log_list->groups; l_groups; l_groups = dap_list_next(l_groups)) {
        dap_db_log_list_group_t *l_group_cur = (dap_db_log_list_group_t *)l_groups->data;
        char *l_del_group_name_replace = NULL;
        char l_obj_type;
        if (!dap_fnmatch("*.del", l_group_cur->name, 0)) {
            l_obj_type = DAP_DB$K_OPTYPE_DEL;
            size_t l_del_name_len = strlen(l_group_cur->name) - 4; //strlen(".del");
            l_del_group_name_replace = DAP_NEW_SIZE(char, l_del_name_len + 1);
            memcpy(l_del_group_name_replace, l_group_cur->name, l_del_name_len);
            l_del_group_name_replace[l_del_name_len] = '\0';
        } else {
            l_obj_type = DAP_DB$K_OPTYPE_ADD;
        }
        uint64_t l_item_start = l_group_cur->last_id_synced + 1;
        dap_gdb_time_t l_time_now = dap_gdb_time_now();
        while (l_group_cur->count && l_dap_db_log_list->is_process) { // Number of records to be synchronized
            size_t l_item_count = min(64, l_group_cur->count);
            dap_store_obj_t *l_objs = dap_chain_global_db_cond_load(l_group_cur->name, l_item_start, &l_item_count);
            if (!l_dap_db_log_list->is_process)
                return NULL;
            // go to next group
            if (!l_objs)
                break;
            // set new start pos = lastitem pos + 1
            l_item_start = l_objs[l_item_count - 1].id + 1;
            l_group_cur->count -= l_item_count;
            dap_list_t *l_list = NULL;
            for (size_t i = 0; i < l_item_count; i++) {
                dap_store_obj_t *l_obj_cur = l_objs + i;
                if (!l_obj_cur)
                    continue;
                l_obj_cur->type = l_obj_type;
                if (l_obj_cur->timestamp >> 32 == 0 ||
                        l_obj_cur->timestamp > l_time_now ||
                        l_obj_cur->group == NULL) {
                    dap_chain_global_db_driver_delete(l_obj_cur, 1);
                    continue;       // the object is broken
                }
                if (l_obj_type == DAP_DB$K_OPTYPE_DEL) {
                    if (l_limit_time && l_obj_cur->timestamp < l_limit_time) {
                        dap_chain_global_db_driver_delete(l_obj_cur, 1);
                        continue;
                    }
                    DAP_DELETE((char *)l_obj_cur->group);
                    l_obj_cur->group = dap_strdup(l_del_group_name_replace);
                }
                dap_db_log_list_obj_t *l_list_obj = DAP_NEW_Z(dap_db_log_list_obj_t);
                uint64_t l_cur_id = l_obj_cur->id;
                l_obj_cur->id = 0;
                dap_store_obj_pkt_t *l_pkt = dap_store_packet_single(l_obj_cur);
                dap_hash_fast(l_pkt->data, l_pkt->data_size, &l_list_obj->hash);
                dap_store_packet_change_id(l_pkt, l_cur_id);
                l_list_obj->pkt = l_pkt;
                l_list = dap_list_append(l_list, l_list_obj);
            }
            dap_store_obj_free(l_objs, l_item_count);
            pthread_mutex_lock(&l_dap_db_log_list->list_mutex);
            // add l_list to list_write
            l_dap_db_log_list->list_write = dap_list_concat(l_dap_db_log_list->list_write, l_list);
            // init read list if it ended already
            if(!l_dap_db_log_list->list_read)
                l_dap_db_log_list->list_read = l_list;
            pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);
        }
        DAP_DEL_Z(l_del_group_name_replace);
        if (!l_dap_db_log_list->is_process)
            return NULL;
    }

    pthread_mutex_lock(&l_dap_db_log_list->list_mutex);
    l_dap_db_log_list->is_process = false;
    pthread_mutex_unlock(&l_dap_db_log_list->list_mutex);
    return NULL;
}

/**
 * @brief Starts a thread that readding a log list
 * @note instead dap_db_log_get_list()
 *
 * @param l_net net for sync
 * @param a_addr a pointer to the structure
 * @param a_flags flags
 * @return Returns a pointer to the log list structure if successful, otherwise NULL pointer.
 */
dap_db_log_list_t* dap_db_log_list_start(dap_chain_net_t *l_net, dap_chain_node_addr_t a_addr, int a_flags)
{
#ifdef GDB_SYNC_ALWAYS_FROM_ZERO
    a_flags |= F_DB_LOG_SYNC_FROM_ZERO;
#endif

    const char *l_net_name = NULL;
    if(l_net && l_net->pub.name && l_net->pub.name[0]!='\0') {
        l_net_name = l_net->pub.name;
    }

    //log_it(L_DEBUG, "Start loading db list_write...");
    dap_db_log_list_t *l_dap_db_log_list = DAP_NEW_Z(dap_db_log_list_t);
    // Add groups for the selected network only
    dap_list_t *l_groups_masks = dap_chain_db_get_sync_groups(l_net_name);
    if (a_flags & F_DB_LOG_ADD_EXTRA_GROUPS) {
        dap_list_t *l_extra_groups_masks = dap_chain_db_get_sync_extra_groups(l_net_name);
        l_groups_masks = dap_list_concat(l_groups_masks, l_extra_groups_masks);
    }
    dap_list_t *l_groups_names = NULL;
    for (dap_list_t *l_cur_mask = l_groups_masks; l_cur_mask; l_cur_mask = dap_list_next(l_cur_mask)) {
        char *l_cur_mask_data = ((dap_sync_group_item_t *)l_cur_mask->data)->group_mask;
        l_groups_names = dap_list_concat(l_groups_names, dap_chain_global_db_driver_get_groups_by_mask(l_cur_mask_data));
    }
    dap_list_free(l_groups_masks);

    static int16_t s_size_ban_list = -1;
    static char **s_ban_list = NULL;

    static int16_t s_size_white_list = -1;
    static char **s_white_list = NULL;
    static char **s_white_list_del = NULL;

    if (s_size_ban_list == -1)
        s_ban_list = dap_config_get_array_str(g_config, "stream_ch_chain", "ban_list_sync_groups", (uint16_t *)&s_size_ban_list);
    if (s_size_white_list == -1) {
        s_white_list = dap_config_get_array_str(g_config, "stream_ch_chain", "white_list_sync_groups", (uint16_t *)&s_size_white_list);
        if (s_size_white_list > 0) {
            s_white_list_del = DAP_NEW_SIZE(char *, s_size_white_list * sizeof(char *));
            for (int i = 0; i < s_size_white_list; i++) {
                s_white_list_del[i] = dap_strdup_printf("%s.del", s_white_list[i]);
            }
        }
    }

    /* delete if not condition */
    if (s_size_white_list > 0) {
        for (dap_list_t *l_group = l_groups_names; l_group; ) {
            bool l_found = false;
            for (int i = 0; i < s_size_white_list; i++) {
                if (!dap_fnmatch(s_white_list[i], l_group->data, FNM_NOESCAPE) ||
                        !dap_fnmatch(s_white_list_del[i], l_group->data, FNM_NOESCAPE)) {
                    l_found = true;
                    break;
                }
            }
            if (!l_found) {
                dap_list_t *l_tmp = l_group->next;
                l_groups_names = dap_list_delete_link(l_groups_names, l_group);
                l_group = l_tmp;
            } else
                l_group = dap_list_next(l_group);
        }
    } else if (s_size_ban_list > 0) {
        for (dap_list_t *l_group = l_groups_names; l_group; ) {
            bool l_found = false;
            for (int i = 0; i < s_size_ban_list; i++) {
                if (!dap_fnmatch(s_ban_list[i], l_group->data, FNM_NOESCAPE)) {
                    dap_list_t *l_tmp = l_group->next;
                    l_groups_names = dap_list_delete_link(l_groups_names, l_group);
                    l_group = l_tmp;
                    l_found = true;
                    break;
                }
            }
            if (l_found) continue;
            l_group = dap_list_next(l_group);
        }
    }

    l_dap_db_log_list->groups = l_groups_names; // repalce name of group with group item
    for (dap_list_t *l_group = l_dap_db_log_list->groups; l_group; l_group = dap_list_next(l_group)) {
        dap_db_log_list_group_t *l_sync_group = DAP_NEW_Z(dap_db_log_list_group_t);
        l_sync_group->name = (char *)l_group->data;
        if (a_flags & F_DB_LOG_SYNC_FROM_ZERO)
            l_sync_group->last_id_synced = 0;
        else
            l_sync_group->last_id_synced = dap_db_get_last_id_remote(a_addr.uint64, l_sync_group->name);
        l_sync_group->count = dap_chain_global_db_driver_count(l_sync_group->name, l_sync_group->last_id_synced + 1);
        l_dap_db_log_list->items_number += l_sync_group->count;
        l_group->data = (void *)l_sync_group;
    }
    l_dap_db_log_list->items_rest = l_dap_db_log_list->items_number;
    if (!l_dap_db_log_list->items_number) {
        DAP_DELETE(l_dap_db_log_list);
        return NULL;
    }
    l_dap_db_log_list->is_process = true;
    pthread_mutex_init(&l_dap_db_log_list->list_mutex, NULL);
    pthread_create(&l_dap_db_log_list->thread, NULL, s_list_thread_proc, l_dap_db_log_list);
    return l_dap_db_log_list;
}

/**
 * @brief Gets a number of objects from a log list.
 *
 * @param a_db_log_list a pointer to the log list structure
 * @return Returns the number if successful, otherwise 0.
 */
size_t dap_db_log_list_get_count(dap_db_log_list_t *a_db_log_list)
{
    if(!a_db_log_list)
        return 0;
    size_t l_items_number;
    pthread_mutex_lock(&a_db_log_list->list_mutex);
    l_items_number = a_db_log_list->items_number;
    pthread_mutex_unlock(&a_db_log_list->list_mutex);
    return l_items_number;
}

/**
 * @brief Gets a number of rest objects from a log list.
 *
 * @param a_db_log_list a pointer to the log list structure
 * @return Returns the number if successful, otherwise 0.
 */
size_t dap_db_log_list_get_count_rest(dap_db_log_list_t *a_db_log_list)
{
    if(!a_db_log_list)
        return 0;
    size_t l_items_rest;
    pthread_mutex_lock(&a_db_log_list->list_mutex);
    l_items_rest = a_db_log_list->items_rest;
    pthread_mutex_unlock(&a_db_log_list->list_mutex);
    return l_items_rest;
}

/**
 * @brief Gets an object from a list.
 *
 * @param a_db_log_list a pointer to the log list
 * @return Returns a pointer to the object.
 */
dap_db_log_list_obj_t *dap_db_log_list_get(dap_db_log_list_t *a_db_log_list)
{
    if (!a_db_log_list)
        return NULL;
    pthread_mutex_lock(&a_db_log_list->list_mutex);
    int l_is_process = a_db_log_list->is_process;
    // check next item
    dap_list_t *l_list = a_db_log_list->list_read;
    if (l_list){
        a_db_log_list->list_read = dap_list_next(a_db_log_list->list_read);
        a_db_log_list->items_rest--;
    }
    pthread_mutex_unlock(&a_db_log_list->list_mutex);
    //log_it(L_DEBUG, "get item n=%d", a_db_log_list->items_number - a_db_log_list->items_rest);
    return l_list ? (dap_db_log_list_obj_t *)l_list->data : DAP_INT_TO_POINTER(l_is_process);
}

void dap_db_log_list_rewind(dap_db_log_list_t *a_db_log_list)
{
    if (!a_db_log_list)
        return;
    a_db_log_list->list_read = a_db_log_list->list_write;
    a_db_log_list->items_rest = a_db_log_list->items_number;
}

/**
 * @brief Deallocates memory of a list item
 *
 * @param a_item a pointer to the list item
 * @returns (none)
 */
void dap_db_log_list_delete_item(void *a_item)
{
    dap_db_log_list_obj_t *l_list_item = (dap_db_log_list_obj_t *)a_item;
    DAP_DELETE(l_list_item->pkt);
    DAP_DELETE(l_list_item);
}

/**
 * @brief Deallocates memory of a log list.
 *
 * @param a_db_log_list a pointer to the log list structure
 * @returns (none)
 */
void dap_db_log_list_delete(dap_db_log_list_t *a_db_log_list)
{
    if(!a_db_log_list)
        return;
    // stop thread if it has created
    if(a_db_log_list->thread) {
        pthread_mutex_lock(&a_db_log_list->list_mutex);
        a_db_log_list->is_process = false;
        pthread_mutex_unlock(&a_db_log_list->list_mutex);
        pthread_join(a_db_log_list->thread, NULL);
    }
    dap_list_free_full(a_db_log_list->groups, free);
    dap_list_free_full(a_db_log_list->list_write, (dap_callback_destroyed_t)dap_db_log_list_delete_item);
    pthread_mutex_destroy(&a_db_log_list->list_mutex);
    DAP_DELETE(a_db_log_list);
}

/**
 * @brief Sets a current node adress.
 * @param a_address a current node adress
 * @param a_net_name a net name string
 * @return True if success, otherwise false
 */
static bool dap_db_set_cur_node_addr_common(uint64_t a_address, char *a_net_name, time_t a_expire_time)
{
char	l_key [DAP_DB_K_MAXKEYLEN];
bool	l_ret;

    if(!a_net_name)
        return false;

    dap_snprintf(l_key, sizeof(l_key) - 1, "cur_node_addr_%s", a_net_name);

    if ( !(l_ret = dap_chain_global_db_gr_set(l_key, &a_address, sizeof(a_address), GROUP_LOCAL_GENERAL)) ) {
        dap_snprintf(l_key, sizeof(l_key) - 1, "cur_node_addr_%s_time", a_net_name);
        l_ret = dap_chain_global_db_gr_set(l_key, &a_expire_time, sizeof(time_t), GROUP_LOCAL_GENERAL);
    }

    return l_ret;
}

/**
 * @brief Sets an adress of a current node and no expire time.
 *
 * @param a_address an adress of a current node
 * @param a_net_name a net name string
 * @return Returns true if siccessful, otherwise false
 */
bool dap_db_set_cur_node_addr(uint64_t a_address, char *a_net_name )
{
    return dap_db_set_cur_node_addr_common(a_address,a_net_name,0);
}

/**
 * @brief Sets an address of a current node and expire time.
 *
 * @param a_address an address of a current node
 * @param a_net_name a net name string
 * @return Returns true if successful, otherwise false
 */
bool dap_db_set_cur_node_addr_exp(uint64_t a_address, char *a_net_name )
{
    return dap_db_set_cur_node_addr_common(a_address,a_net_name, time(NULL));
}

/**
 * @brief Gets an adress of current node by a net name.
 *
 * @param a_net_name a net name string
 * @return Returns an adress if successful, otherwise 0.
 */
uint64_t dap_db_get_cur_node_addr(char *a_net_name)
{
char	l_key[DAP_DB_K_MAXKEYLEN], l_key_time[DAP_DB_K_MAXKEYLEN];
uint8_t *l_node_addr_data, *l_node_time_data;
size_t l_node_addr_len = 0, l_node_time_len = 0;
uint64_t l_node_addr_ret = 0;
time_t l_node_time = 0;

    if(!a_net_name)
        return 0;

    dap_snprintf(l_key, sizeof(l_key) - 1, "cur_node_addr_%s", a_net_name);
    dap_snprintf(l_key_time, sizeof(l_key_time) - 1, "cur_node_addr_%s_time", a_net_name);

    l_node_addr_data = dap_chain_global_db_gr_get(l_key, &l_node_addr_len, GROUP_LOCAL_GENERAL);
    l_node_time_data = dap_chain_global_db_gr_get(l_key_time, &l_node_time_len, GROUP_LOCAL_GENERAL);

    if(l_node_addr_data && (l_node_addr_len == sizeof(uint64_t)) )
        l_node_addr_ret = *( (uint64_t *) l_node_addr_data );

    if(l_node_time_data && (l_node_time_len == sizeof(time_t)) )
        l_node_time = *( (time_t *) l_node_time_data );

    DAP_DELETE(l_node_addr_data);
    DAP_DELETE(l_node_time_data);

    // time delta in seconds
    static int64_t addr_time_expired = -1;
    // read time-expired

    if(addr_time_expired == -1) {
        dap_string_t *l_cfg_path = dap_string_new("network/");
        dap_string_append(l_cfg_path, a_net_name);
        dap_config_t *l_cfg;

        if((l_cfg = dap_config_open(l_cfg_path->str)) == NULL) {
            log_it(L_ERROR, "Can't open default network config");
            addr_time_expired = 0;
        } else {
            addr_time_expired = 3600 *
                    dap_config_get_item_int64_default(l_cfg, "general", "node-addr-expired",
                    NODE_TIME_EXPIRED_DEFAULT);
        }
        dap_string_free(l_cfg_path, true);
    }

    time_t l_dt = time(NULL) - l_node_time;
    //NODE_TIME_EXPIRED
    if(l_node_time && l_dt > addr_time_expired) {
        l_node_addr_ret = 0;
    }

    return l_node_addr_ret;
}

/**
 * @brief Sets last id of a remote node.
 *
 * @param a_node_addr a node adress
 * @param a_id id
 * @param a_group a group name string
 * @return Returns true if successful, otherwise false.
 */
bool dap_db_set_last_id_remote(uint64_t a_node_addr, uint64_t a_id, char *a_group)
{
char	l_key[DAP_DB_K_MAXKEYLEN];

    dap_snprintf(l_key, sizeof(l_key) - 1, "%ju%s", a_node_addr, a_group);
    return  dap_chain_global_db_gr_set(l_key, &a_id, sizeof(uint64_t), GROUP_LOCAL_NODE_LAST_ID);
}

/**
 * @brief Gets last id of a remote node.
 *
 * @param a_node_addr a node adress
 * @param a_group a group name string
 * @return Returns id if successful, otherwise 0.
 */
uint64_t dap_db_get_last_id_remote(uint64_t a_node_addr, char *a_group)
{
    char *l_node_addr_str = dap_strdup_printf("%ju%s", a_node_addr, a_group);
    size_t l_id_len = 0;
    uint8_t *l_id = dap_chain_global_db_gr_get((const char*) l_node_addr_str, &l_id_len,
                                                GROUP_LOCAL_NODE_LAST_ID);
    uint64_t l_ret_id = 0;
    if (l_id) {
        if (l_id_len == sizeof(uint64_t))
            memcpy(&l_ret_id, l_id, l_id_len);
        DAP_DELETE(l_id);
    }
    DAP_DELETE(l_node_addr_str);
    return l_ret_id;
}

/**
 * @brief Sets the last hash of a remote node.
 *
 * @param a_node_addr a node adress
 * @param a_chain a pointer to the chain stucture
 * @param a_hash a
 * @return true
 * @return false
 */
bool dap_db_set_last_hash_remote(uint64_t a_node_addr, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_hash)
{
char	l_key[DAP_DB_K_MAXKEYLEN];

    dap_snprintf(l_key, sizeof(l_key) - 1, "%ju%s%s", a_node_addr, a_chain->net_name, a_chain->name);
    return dap_chain_global_db_gr_set(l_key, a_hash, sizeof(dap_chain_hash_fast_t), GROUP_LOCAL_NODE_LAST_ID);
}

/**
 * @brief Gets the last hash of a remote node.
 *
 * @param a_node_addr a node adress
 * @param a_chain a pointer to a chain structure
 * @return Returns a hash if successful.
 */
dap_chain_hash_fast_t *dap_db_get_last_hash_remote(uint64_t a_node_addr, dap_chain_t *a_chain)
{
    char *l_node_chain_str = dap_strdup_printf("%ju%s%s", a_node_addr, a_chain->net_name, a_chain->name);
    size_t l_hash_len = 0;
    uint8_t *l_hash = dap_chain_global_db_gr_get((const char*)l_node_chain_str, &l_hash_len,
                                                 GROUP_LOCAL_NODE_LAST_ID);
    DAP_DELETE(l_node_chain_str);
    return (dap_chain_hash_fast_t *)l_hash;
}

/**
 * @brief Gets a size of an object.
 *
 * @param store_obj a pointer to the object
 * @return Returns the size.
 */
static size_t dap_db_get_size_pdap_store_obj_t(pdap_store_obj_t store_obj)
{
    size_t size = sizeof(uint32_t) + 2 * sizeof(uint16_t) +
            3 * sizeof(uint64_t) + dap_strlen(store_obj->group) +
            dap_strlen(store_obj->key) + store_obj->value_len;
    return size;
}

/**
 * @brief Multiples data into a_old_pkt structure from a_new_pkt structure.
 * @param a_old_pkt a pointer to the old object
 * @param a_new_pkt a pointer to the new object
 * @return Returns a pointer to the multiple object
 */
dap_store_obj_pkt_t *dap_store_packet_multiple(dap_store_obj_pkt_t *a_old_pkt, dap_store_obj_pkt_t *a_new_pkt)
{
    if (!a_new_pkt)
        return a_old_pkt;
    if (a_old_pkt)
        a_old_pkt = (dap_store_obj_pkt_t *)DAP_REALLOC(a_old_pkt,
                                                       a_old_pkt->data_size + a_new_pkt->data_size + sizeof(dap_store_obj_pkt_t));
    else
        a_old_pkt = DAP_NEW_Z_SIZE(dap_store_obj_pkt_t, a_new_pkt->data_size + sizeof(dap_store_obj_pkt_t));
    memcpy(a_old_pkt->data + a_old_pkt->data_size, a_new_pkt->data, a_new_pkt->data_size);
    a_old_pkt->data_size += a_new_pkt->data_size;
    a_old_pkt->obj_count++;
    return a_old_pkt;
}

/**
 * @brief Changes id in a packed structure.
 *
 * @param a_pkt a pointer to the packed structure
 * @param a_id id
 * @return (none)
 */
void dap_store_packet_change_id(dap_store_obj_pkt_t *a_pkt, uint64_t a_id)
{
    uint16_t l_gr_len;
    memcpy(&l_gr_len, a_pkt->data + sizeof(uint32_t), sizeof(uint16_t));
    size_t l_id_offset = sizeof(uint32_t) + sizeof(uint16_t) + l_gr_len;
    memcpy(a_pkt->data + l_id_offset, &a_id, sizeof(uint64_t));
}

/**
 * @brief Serializes an object into a packed structure.
 * @param a_store_obj a pointer to the object to be serialized
 * @return Returns a pointer to the packed sructure if successful, otherwise NULL.
 */
dap_store_obj_pkt_t *dap_store_packet_single(dap_store_obj_t *a_store_obj)
{
int len;
unsigned char *pdata;

    if (!a_store_obj)
        return NULL;

    uint32_t l_data_size_out = dap_db_get_size_pdap_store_obj_t(a_store_obj);
    dap_store_obj_pkt_t *l_pkt = DAP_NEW_SIZE(dap_store_obj_pkt_t, l_data_size_out + sizeof(dap_store_obj_pkt_t));

    /* Fill packet header */
    l_pkt->data_size = l_data_size_out;
    l_pkt->obj_count = 1;
    l_pkt->timestamp = 0;

    /* Put serialized data into the payload part of the packet */
    pdata = l_pkt->data;
    *( (uint32_t *) pdata) =  a_store_obj->type;                pdata += sizeof(uint32_t);

    len = dap_strlen(a_store_obj->group);
    *( (uint16_t *) pdata) = (uint16_t) len;                    pdata += sizeof(uint16_t);
    memcpy(pdata, a_store_obj->group, len);                     pdata += len;

    *( (uint64_t *) pdata) = a_store_obj->id;                   pdata += sizeof(uint64_t);
    *( (uint64_t *) pdata) = a_store_obj->timestamp;            pdata += sizeof(uint64_t);

    len = dap_strlen(a_store_obj->key);
    *( (uint16_t *) pdata) = (uint16_t) len;                    pdata += sizeof(uint16_t);
    memcpy(pdata, a_store_obj->key, len);                       pdata += len;

    *( (uint64_t *) pdata) = a_store_obj->value_len;            pdata += sizeof(uint64_t);
    memcpy(pdata, a_store_obj->value, a_store_obj->value_len);  pdata += a_store_obj->value_len;

    assert( (pdata - l_pkt->data) == l_data_size_out);
    return l_pkt;
}

/**
 * @brief Deserializes some objects from a packed structure into an array of objects.
 * @param pkt a pointer to the serialized packed structure
 * @param store_obj_count[out] a number of deserialized objects in the array
 * @return Returns a pointer to the first object in the array, if successful; otherwise NULL.
 */
dap_store_obj_t *dap_store_unpacket_multiple(const dap_store_obj_pkt_t *a_pkt, size_t *a_store_obj_count)
{
    if(!a_pkt || a_pkt->data_size < sizeof(dap_store_obj_pkt_t))
        return NULL;
    uint64_t l_offset = 0;
    uint32_t l_count = a_pkt->obj_count, l_cur_count;
    uint64_t l_size = l_count <= UINT16_MAX ? l_count * sizeof(struct dap_store_obj) : 0;
    dap_store_obj_t *l_store_obj = DAP_NEW_Z_SIZE(dap_store_obj_t, l_size);
    if (!l_store_obj || !l_size) {
        log_it(L_ERROR, "Invalid size: can't allocate %"DAP_UINT64_FORMAT_U" bytes", l_size);
        DAP_DEL_Z(l_store_obj)
        return NULL;
    }
    for(l_cur_count = 0; l_cur_count < l_count; ++l_cur_count) {
        dap_store_obj_t *l_obj = l_store_obj + l_cur_count;
        uint16_t l_str_length;

        uint32_t l_type;
        if (l_offset+sizeof (uint32_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'type' field"); break;} // Check for buffer boundries
        memcpy(&l_type, a_pkt->data + l_offset, sizeof(uint32_t));
        l_obj->type = l_type;
        l_offset += sizeof(uint32_t);

        if (l_offset+sizeof (uint16_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'group_length' field"); break;} // Check for buffer boundries
        memcpy(&l_str_length, a_pkt->data + l_offset, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);

        if (l_offset + l_str_length > a_pkt->data_size || !l_str_length) {log_it(L_ERROR, "Broken GDB element: can't read 'group' field"); break;} // Check for buffer boundries
        l_obj->group = DAP_NEW_Z_SIZE(char, l_str_length + 1);
        memcpy(l_obj->group, a_pkt->data + l_offset, l_str_length);
        l_offset += l_str_length;

        if (l_offset+sizeof (uint64_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'id' field");
                                                           DAP_DELETE(l_obj->group); break;} // Check for buffer boundries
        memcpy(&l_obj->id, a_pkt->data + l_offset, sizeof(uint64_t));
        l_offset += sizeof(uint64_t);

        if (l_offset+sizeof (uint64_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'timestamp' field");
                                                           DAP_DELETE(l_obj->group); break;} // Check for buffer boundries
        memcpy(&l_obj->timestamp, a_pkt->data + l_offset, sizeof(uint64_t));
        l_offset += sizeof(uint64_t);

        if (l_offset+sizeof (uint16_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'key_length' field");
                                                           DAP_DELETE(l_obj->group); break;} // Check for buffer boundries
        memcpy(&l_str_length, a_pkt->data + l_offset, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);

        if (l_offset + l_str_length > a_pkt->data_size || !l_str_length) {log_it(L_ERROR, "Broken GDB element: can't read 'key' field: len %s",
                                                                                 l_str_length ? "OVER" : "NULL");
                                                                          DAP_DELETE(l_obj->group); break;} // Check for buffer boundries
        l_obj->key = DAP_NEW_Z_SIZE(char, l_str_length + 1);
        memcpy((char *)l_obj->key, a_pkt->data + l_offset, l_str_length);
        l_offset += l_str_length;

        if (l_offset+sizeof (uint64_t)> a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'value_length' field");
                                                           DAP_DELETE(l_obj->group); DAP_DELETE(l_obj->key); break;} // Check for buffer boundries
        memcpy(&l_obj->value_len, a_pkt->data + l_offset, sizeof(uint64_t));
        l_offset += sizeof(uint64_t);

        if (l_offset + l_obj->value_len > a_pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'value' field");
                                                          DAP_DELETE(l_obj->group); DAP_DELETE(l_obj->key);break;} // Check for buffer boundries
        l_obj->value = DAP_NEW_SIZE(uint8_t, l_obj->value_len);
        memcpy(l_obj->value, a_pkt->data + l_offset, l_obj->value_len);
        l_offset += l_obj->value_len;
    }
    if (a_pkt->data_size != l_offset) {
        if (l_cur_count)
            dap_store_obj_free(l_store_obj, l_cur_count);
        return NULL;
    }
    // Return the number of completely filled dap_store_obj_t structures
    // because l_cur_count may be less than l_count due to too little memory
    if(a_store_obj_count)
        *a_store_obj_count = l_cur_count;
    return l_store_obj;
}
