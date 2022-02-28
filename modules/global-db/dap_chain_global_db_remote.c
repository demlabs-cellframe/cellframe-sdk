#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <dap_common.h>
#include <dap_strfuncs.h>
#include <dap_string.h>
#include "dap_chain.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#define LOG_TAG "dap_chain_global_db_remote"

// Default time of a node address expired in hours
#define NODE_TIME_EXPIRED_DEFAULT 720

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
 * @brief Sets an adress of a current node and expire time.
 *
 * @param a_address an adress of a current node
 * @param a_net_name a net name string
 * @return Returns true if siccessful, otherwise false
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
    size_t size = sizeof(uint32_t) + 2 * sizeof(uint16_t) + sizeof(time_t)
            + 2 * sizeof(uint64_t) + dap_strlen(store_obj->group) +
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
dap_store_obj_t *dap_store_unpacket_multiple(const dap_store_obj_pkt_t *pkt, size_t *store_obj_count)
{
    if(!pkt || pkt->data_size < 1)
        return NULL;
    uint64_t offset = 0;
    uint32_t count = pkt->obj_count;
    dap_store_obj_t *store_obj = DAP_NEW_SIZE(dap_store_obj_t, count * sizeof(struct dap_store_obj));
    for(size_t q = 0; q < count; ++q) {
        dap_store_obj_t *obj = store_obj + q;
        uint16_t str_length;

        uint32_t l_type;
        if (offset+sizeof (uint32_t)> pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'type' field"); break;} // Check for buffer boundries
        memcpy(&l_type, pkt->data + offset, sizeof(uint32_t));
        obj->type = l_type;
        offset += sizeof(uint32_t);

        if (offset+sizeof (uint16_t)> pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'group_length' field"); break;} // Check for buffer boundries
        memcpy(&str_length, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        if (offset+str_length> pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'group' field"); break;} // Check for buffer boundries
        obj->group = DAP_NEW_SIZE(char, str_length + 1);
        memcpy((char *)obj->group, pkt->data + offset, str_length);
        ((char *)obj->group)[str_length] = '\0';
        offset += str_length;

        if (offset+sizeof (uint64_t)> pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'id' field"); break;} // Check for buffer boundries
        memcpy(&obj->id, pkt->data + offset, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        if (offset+sizeof (uint64_t)> pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'timestamp' field"); break;} // Check for buffer boundries
        memcpy(&obj->timestamp, pkt->data + offset, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        if (offset+sizeof (uint16_t)> pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'key_length' field"); break;} // Check for buffer boundries
        memcpy(&str_length, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        if (offset+ str_length > pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'key' field"); break;} // Check for buffer boundries
        obj->key = DAP_NEW_SIZE(char, str_length + 1);
        memcpy((char *)obj->key, pkt->data + offset, str_length);
        ((char *)obj->key)[str_length] = '\0';
        offset += str_length;

        if (offset+sizeof (uint64_t)> pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'value_length' field"); break;} // Check for buffer boundries
        memcpy(&obj->value_len, pkt->data + offset, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        if (offset+obj->value_len> pkt->data_size) {log_it(L_ERROR, "Broken GDB element: can't read 'value' field"); break;} // Check for buffer boundries
        obj->value = DAP_NEW_SIZE(uint8_t, obj->value_len);
        memcpy((char *)obj->value, pkt->data + offset, obj->value_len);
        offset += obj->value_len;
    }

    assert(pkt->data_size == offset);

    if(store_obj_count)
        *store_obj_count = count;

    return store_obj;
}
