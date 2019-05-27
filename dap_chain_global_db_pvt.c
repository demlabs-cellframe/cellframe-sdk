#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_pvt.h"
#include "dap_strfuncs.h"
#include "dap_list.h"

#define LOG_TAG "dap_global_db"
#define TDB_PREFIX_LEN 7

static struct ldb_context *s_ldb = NULL;
static TALLOC_CTX *s_mem_ctx = NULL;

//static int dap_store_len = 0; // initialized only when reading from local db
static char *dap_db_path = NULL;

#define CALL2(a, b, ...) (a), (b)
#define dap_db_add_record(...) dap_db_merge(CALL2(__VA_ARGS__, 0))

static int dap_db_add_msg(struct ldb_message *a_msg)
{
    if(ldb_msg_sanity_check(s_ldb, a_msg) != LDB_SUCCESS) {
        log_it(L_ERROR, "LDB message is inconsistent: %s", ldb_errstring(s_ldb));
        return -1;
    }
    ldb_transaction_start(s_ldb);
    int status = ldb_add(s_ldb, a_msg);
    // Delete the entry if it already exist and add again
    if(status == LDB_ERR_ENTRY_ALREADY_EXISTS) {
        ldb_delete(s_ldb, a_msg->dn);
        status = ldb_add(s_ldb, a_msg);
    }
    if(status != LDB_SUCCESS) {
        if(status == LDB_ERR_ENTRY_ALREADY_EXISTS) {
            log_it(L_INFO, "Entry %s already present, skipped", ldb_dn_get_linearized(a_msg->dn));
        }
        else {
            log_it(L_ERROR, "LDB adding error: %s", ldb_errstring(s_ldb));
        }
        ldb_transaction_cancel(s_ldb);
        return -2;
    }
    else {
        ldb_transaction_commit(s_ldb);
        //log_it(L_INFO, "Entry %s added", ldb_dn_get_linearized(a_msg->dn));
        return 0;
    }
}

/**
 * @brief dap_db_group_create
 * @param a_group
 */
void dap_db_group_create(const char * a_group)
{
    struct ldb_message *msg;

    // level 2: group record
    msg = ldb_msg_new(s_ldb);
    msg->dn = ldb_dn_new(s_mem_ctx, s_ldb, "ou=addrs_leased,dc=kelvin_nodes");
    ldb_msg_add_string(msg, "ou", a_group );
    ldb_msg_add_string(msg, "objectClass", "group");
    ldb_msg_add_string(msg, "section", "kelvin_nodes");
    ldb_msg_add_string(msg, "description", "Whitelist of Kelvin blockchain nodes");
    dap_db_add_msg(msg);
    talloc_free(msg->dn);
    talloc_free(msg);

}

/**
 * @brief dap_db_init
 * @param path
 * @return
 */
int dap_db_init(const char *path)
{
    s_mem_ctx = talloc_new(NULL);
    if(ldb_global_init() != 0) {
        log_it(L_ERROR, "Couldn't initialize LDB's global information");
        return -1;
    };
    if((s_ldb = ldb_init(s_mem_ctx, NULL)) != LDB_SUCCESS) {
        log_it(L_INFO, "ldb context initialized");
        char *l_tdb_path = DAP_NEW_Z_SIZE(char,strlen(path) + TDB_PREFIX_LEN );
        memset(l_tdb_path, '\0', strlen(path) + TDB_PREFIX_LEN);
        strcat(l_tdb_path, "tdb://"); // using tdb for simplicity, no need for separate LDAP server
        strcat(l_tdb_path, path);
        struct ldb_result *data_message;
        if(ldb_connect(s_ldb, l_tdb_path, 0, NULL) != LDB_SUCCESS) {
            log_it(L_ERROR, "Couldn't connect to database");
            DAP_DELETE(l_tdb_path);
            return 1;
        }
        dap_db_path = strdup(l_tdb_path);
        const char *query = "(dn=*)";
        if(ldb_search(s_ldb, s_mem_ctx, &data_message, NULL, LDB_SCOPE_DEFAULT, NULL, "%s", query) != LDB_SUCCESS) {
            log_it(L_ERROR, "Database querying failed");
            DAP_DELETE(l_tdb_path);
            return 2;
        }
        struct ldb_message *msg;
        if(data_message->count == 0) {
            // level 1: section record
            msg = ldb_msg_new(s_ldb);
            msg->dn = ldb_dn_new(s_mem_ctx, s_ldb, "dc=kelvin_nodes");
            ldb_msg_add_string(msg, "dc", "kelvin_nodes");
            ldb_msg_add_string(msg, "objectClass", "top");
            ldb_msg_add_string(msg, "objectClass", "section");
            dap_db_add_msg(msg);

            // level 2: groups
            dap_db_group_create( GROUP_LOCAL_HISTORY);
            dap_db_group_create( GROUP_LOCAL_GENERAL );
            dap_db_group_create( GROUP_LOCAL_NODE_LAST_TS);

        }
        talloc_free(data_message);
        DAP_DELETE(l_tdb_path);
        return 0;
    }
    else {
        log_it(L_ERROR, "Couldn't initialize LDB context");
        return -2;
    }
}

int dap_db_del_msg(struct ldb_dn *ldn)
{
    ldb_transaction_start(s_ldb);
    int status = ldb_delete(s_ldb, ldn);
    if(status != LDB_SUCCESS) {
        log_it(L_ERROR, "LDB deleting error: %s", ldb_errstring(s_ldb));
        ldb_transaction_cancel(s_ldb);
        return -2;
    }
    else {
        ldb_transaction_commit(s_ldb);
        //log_it(L_INFO, "Entry %s deleted", ldb_dn_get_linearized(ldn));
        return 0;
    }
}

static int compare_message_items(const void * l_a, const void * l_b)
{
    const struct ldb_message *l_item_a = (const struct ldb_message*) l_a;
    const struct ldb_message *l_item_b = (const struct ldb_message*) l_b;
    const struct ldb_val *l_val_a = ldb_msg_find_ldb_val(l_item_a, "time");
    const struct ldb_val *l_val_b = ldb_msg_find_ldb_val(l_item_b, "time");
    time_t timestamp_a = 0;
    time_t timestamp_b = 0;
    if(l_val_a)
        memcpy(&timestamp_a, l_val_a->data, min(sizeof(time_t), l_val_a->length));
    if(l_val_b)
        memcpy(&timestamp_b, l_val_b->data, min(sizeof(time_t), l_val_b->length));
    if(timestamp_a == timestamp_b)
        return 0;
    if(timestamp_a < timestamp_b)
        return -1;
    return 1;
}

/**
 * Get data from base
 *
 * query RFC2254 (The String Representation of LDAP Search Filters)
 * sample:
 * (uid=testuser)    Matches to all users that have exactly the value testuser for the attribute uid.
 * (uid=test*)    Matches to all users that have values for the attribute uid that start with test.
 * (!(uid=test*))    Matches to all users that have values for the attribute uid that do not start with test.
 * (&(department=1234)(city=Paris)) Matches to all users that have exactly the value 1234 for the attribute department and exactly the value Paris for the attribute city .
 *
 */
pdap_store_obj_t dap_db_read_data_ldb(const char *a_query, size_t *a_count)
{
    struct ldb_result *data_message;
    /*
     CN      commonName (2.5.4.3)
     L       localityName (2.5.4.7)
     ST      stateOrProvinceName (2.5.4.8)
     O       organizationName (2.5.4.10)
     OU      organizationalUnitName (2.5.4.11)
     C       countryName (2.5.4.6)
     STREET  streetAddress (2.5.4.9)
     DC      domainComponent (0.9.2342.19200300.100.1.25)
     UID     userId (0.9.2342.19200300.100.1.1)
     */
    if(ldb_connect(s_ldb, dap_db_path, LDB_FLG_RDONLY, NULL) != LDB_SUCCESS) {
        log_it(L_ERROR, "Couldn't connect to database");
        return NULL;
    }
    //sample: query = "(objectClass=addr_leased)";
    if(ldb_search(s_ldb, NULL, &data_message, NULL, LDB_SCOPE_DEFAULT, NULL, a_query) != LDB_SUCCESS) {
        log_it(L_ERROR, "Database querying failed");
        return NULL;
    }
    //log_it(L_INFO, "Obtained binary data, %d entries", data_message->count);

    // not found data
    if(!data_message->count ) {
        talloc_free(data_message);
        return NULL;
    }

    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, data_message->count * sizeof(struct dap_store_obj));
    if(!store_data) {
        log_it(L_ERROR, "Couldn't allocate memory, store objects unobtained");
        talloc_free(data_message);
        return NULL;
    }

    dap_list_t *l_list_items = NULL;
    // fill list
    for(size_t i = 0; i < data_message->count; i++) {
        l_list_items = dap_list_prepend(l_list_items, data_message->msgs[i]);
    }
    // sort list by time
    l_list_items = dap_list_sort(l_list_items, (dap_callback_compare_t) compare_message_items);

    dap_list_t *l_list = l_list_items;
    size_t q = 0;
    while(l_list) {
        const struct ldb_message *l_msgs = l_list->data;
        store_data[q].section = strdup(ldb_msg_find_attr_as_string(l_msgs, "section", "")); //strdup("kelvin_nodes");
        store_data[q].group = strdup(ldb_msg_find_attr_as_string(l_msgs, "objectClass", "")); //strdup(group);
        store_data[q].type = 1;
        store_data[q].key = strdup(ldb_msg_find_attr_as_string(l_msgs, "cn", ""));
        // get timestamp
        const struct ldb_val *l_val = ldb_msg_find_ldb_val(l_msgs, "time");
        if(l_val) {
            memcpy(&store_data[q].timestamp, l_val->data, min(sizeof(time_t), l_val->length));
        }
        // get value
        l_val = ldb_msg_find_ldb_val(l_msgs, "val");
        if(l_val) {
            store_data[q].value_len = l_val->length;
            store_data[q].value = DAP_NEW_SIZE(uint8_t, l_val->length);
            memcpy(store_data[q].value, l_val->data, l_val->length);
        }
        q++;
        l_list = dap_list_next(l_list);
        //log_it(L_INFO, "Record %s read successfully", ldb_dn_get_linearized(data_message->msgs[q]->dn));
    }
    size_t dap_store_len = data_message->count;
    /*for(size_t q = 0; q < dap_store_len; ++q) {
        store_data[q].section = strdup(ldb_msg_find_attr_as_string(data_message->msgs[q], "section", "")); //strdup("kelvin_nodes");
        store_data[q].group = strdup(ldb_msg_find_attr_as_string(data_message->msgs[q], "objectClass", "")); //strdup(group);
        store_data[q].type = 1;
        store_data[q].key = strdup(ldb_msg_find_attr_as_string(data_message->msgs[q], "cn", ""));
        // get timestamp
        const struct ldb_val *l_val = ldb_msg_find_ldb_val(data_message->msgs[q], "time");
        if(l_val) {
            memcpy(&store_data[q].timestamp, l_val->data, min(sizeof(time_t), l_val->length));
        }
        // get value
        l_val = ldb_msg_find_ldb_val(data_message->msgs[q], "val");
        if(l_val) {
            store_data[q].value_len = l_val->length;
            store_data[q].value = DAP_NEW_SIZE(uint8_t, l_val->length);
            memcpy(store_data[q].value, l_val->data, l_val->length);
        }
        //log_it(L_INFO, "Record %s read successfully", ldb_dn_get_linearized(data_message->msgs[q]->dn));
    }*/
    talloc_free(data_message);
    dap_list_free(l_list_items);
    if(a_count)
        *a_count = dap_store_len;
    return store_data;
}

/**
 * clean memory
 */
void dab_db_free_pdap_store_obj_t(pdap_store_obj_t store_data, size_t count)
{
    if(!store_data)
        return;
    for(size_t i = 0; i < count; i++) {
        pdap_store_obj_t store_one = store_data + i;
        DAP_DELETE(store_one->section);
        DAP_DELETE(store_one->group);
        DAP_DELETE(store_one->key);
        DAP_DELETE(store_one->value);
    }
    DAP_DELETE(store_data);
}

/* Get the entire content without using query expression
 * This function is highly dissuaded from being used
 * */
pdap_store_obj_t dap_db_read_file_data(const char *path, const char *group)
{
    struct ldb_ldif *ldif_msg;
    FILE *fs = fopen(path, "r");
    if(!fs) {
        log_it(L_ERROR, "Can't open file %s", path);
        return NULL;
    }
    pdap_store_obj_t store_data = (pdap_store_obj_t) malloc(256 * sizeof(dap_store_obj_t));
    if(store_data != NULL) {
        log_it(L_INFO, "We're about to put entries in store objects");
    }
    else {
        log_it(L_ERROR, "Couldn't allocate memory, store objects unobtained");
        fclose(fs);
        return NULL;
    }

    size_t q = 0;
    for(ldif_msg = ldb_ldif_read_file(s_ldb, fs); ldif_msg; ldif_msg = ldb_ldif_read_file(s_ldb, fs), q++) {
        if(q % 256 == 0) {
            store_data = (pdap_store_obj_t) realloc(store_data, (q + 256) * sizeof(dap_store_obj_t));
        }
        /* if (ldif_msg->changetype == LDB_CHANGETYPE_ADD) {
         / ... /
         } */ // in case we gonna use extra LDIF functionality
        const char *key = ldb_msg_find_attr_as_string(ldif_msg->msg, "cn", NULL);
        if(key != NULL) {
            store_data[q].section = strdup("kelvin-testnet");
            store_data[q].group = strdup(group);
            store_data[q].type = 1;
            store_data[q].key = strdup(key);
            store_data[q].value =(uint8_t*) strdup( ldb_msg_find_attr_as_string(ldif_msg->msg, "time", NULL));
            store_data[q].value_len = strlen ( (char*) store_data[q].value) +1;
            log_it(L_INFO, "Record %s stored successfully", ldb_dn_get_linearized(ldif_msg->msg->dn));
        }
        ldb_ldif_read_free(s_ldb, ldif_msg);
    }
    fclose(fs);
    return store_data;
}

/*
 * Add multiple entries received from remote node to local database.
 * Since we don't know the size, it must be supplied too
 *
 * dap_store_size the count records
 * return 0 if Ok, <0 if errors
 */
int dap_db_add_ldb(pdap_store_obj_t a_store_obj, size_t a_store_count)
{
    int l_ret = 0;
    if(a_store_obj == NULL) {
        log_it(L_ERROR, "Invalid Dap store objects passed");
        return -1;
    }
    if(ldb_connect(s_ldb, dap_db_path, 0, NULL) != LDB_SUCCESS) {
        log_it(L_ERROR, "Couldn't connect to database");
        return -2;
    }
    //log_it(L_INFO, "We're about to put %d records into database", a_store_count);
    struct ldb_message *l_msg;
    if(a_store_count == 0) {
        a_store_count = 1;
    }
    for(size_t q = 0; q < a_store_count; q++) {
        // level 3: leased address, single whitelist entity

        // if it is marked, don't save
        if(a_store_obj[q].timestamp == (time_t) -1)
            continue;

        l_msg = ldb_msg_new(s_ldb);
        char dn[256];
        memset(dn, '\0', 256);
        strcat(dn, "cn=");
        strcat(dn, a_store_obj[q].key);
        //strcat(dn, ",ou=addrs_leased,dc=kelvin_nodes");
        strcat(dn, ",ou=");
        strcat(dn, a_store_obj[q].group);
        strcat(dn, ",dc=kelvin_nodes");
        l_msg->dn = ldb_dn_new(s_mem_ctx, s_ldb, dn);
        int l_res = ldb_msg_add_string(l_msg, "cn", a_store_obj[q].key);
        ldb_msg_add_string(l_msg, "objectClass", a_store_obj[q].group);
        ldb_msg_add_string(l_msg, "section", "kelvin_nodes");
        ldb_msg_add_string(l_msg, "description", "Approved Kelvin node");

        struct ldb_val l_val;
        struct ldb_message_element *return_el;
        l_val.data = (uint8_t*) &a_store_obj[q].timestamp;
        l_val.length = sizeof(time_t);
        l_res = ldb_msg_add_value(l_msg, "time", &l_val, &return_el);

        l_val.data = a_store_obj[q].value;
        l_val.length = a_store_obj[q].value_len;
        l_res = ldb_msg_add_value(l_msg, "val", &l_val, &return_el);

        l_ret += dap_db_add_msg(l_msg); // accumulation error codes
        talloc_free(l_msg->dn);
        talloc_free(l_msg);
    }
    return l_ret;
}

/*
 * Delete multiple entries from local database.
 *
 * dap_store_size the count records
 * return 0 if Ok, <0 if errors
 */
int dap_db_delete_ldb(pdap_store_obj_t store_obj, size_t a_store_count)
{
    int ret = 0;
    if(store_obj == NULL) {
        log_it(L_ERROR, "Invalid Dap store objects passed");
        return -1;
    }
    if(ldb_connect(s_ldb, dap_db_path, 0, NULL) != LDB_SUCCESS) {
        log_it(L_ERROR, "Couldn't connect to database");
        return -2;
    }
    //log_it(L_INFO, "We're delete %d records from database", a_store_count);
    if(a_store_count == 0) {
        a_store_count = 1;
    }
    for(size_t q = 0; q < a_store_count; q++) {
        char dn[128];
        memset(dn, '\0', 128);
        strcat(dn, "cn=");
        strcat(dn, store_obj[q].key);
        //strcat(dn, ",ou=addrs_leased,dc=kelvin_nodes");
        strcat(dn, ",ou=");
        strcat(dn, store_obj[q].group);
        strcat(dn, ",dc=kelvin_nodes");
        struct ldb_dn *ldn = ldb_dn_new(s_mem_ctx, s_ldb, dn);
        ret += dap_db_del_msg(ldn); // accumulation error codes
        talloc_free(ldn);
    }
    return ret;

}

/* serialization */
/*dap_store_obj_pkt_t *dap_store_packet_single(pdap_store_obj_t store_obj)
 {
 dap_store_obj_pkt_t *pkt = DAP_NEW_Z_SIZE(dap_store_obj_pkt_t,
 sizeof(int) + 4 + strlen(store_obj->group) + strlen(store_obj->key) + strlen(store_obj->section)
 + strlen(store_obj->value));
 pkt->grp_size = strlen(store_obj->group) + 1;
 pkt->name_size = strlen(store_obj->key) + 1;
 pkt->sec_size = strlen(store_obj->section) + 1;
 pkt->type = store_obj->type;
 memcpy(pkt->data, &store_obj->section, pkt->sec_size);
 memcpy(pkt->data + pkt->sec_size, &store_obj->group, pkt->grp_size);
 memcpy(pkt->data + pkt->sec_size + pkt->grp_size, &store_obj->key, pkt->name_size);
 memcpy(pkt->data + pkt->sec_size + pkt->grp_size + pkt->name_size, &store_obj->value, strlen(store_obj->value) + 1);
 return pkt;
 }*/

static size_t dap_db_get_size_pdap_store_obj_t(pdap_store_obj_t store_obj)
{
    size_t size = sizeof(uint32_t) + 3 * sizeof(uint16_t) + sizeof(size_t) + sizeof(time_t) + dap_strlen(store_obj->group) +
            dap_strlen(store_obj->key) + dap_strlen(store_obj->section) + store_obj->value_len;
    return size;
}

/**
 * serialization
 * @param a_store_obj_count count of structures store_obj
 * @param a_timestamp create data time
 * @param a_size_out[out] size of output structure
 * @return NULL in case of an error
 */
dap_store_obj_pkt_t *dap_store_packet_multiple(pdap_store_obj_t a_store_obj, time_t a_timestamp, size_t a_store_obj_count)
{
    if(!a_store_obj || a_store_obj_count < 1)
        return NULL;
    size_t l_data_size_out = sizeof(uint32_t); // size of output data
    // calculate output structure size
    for(size_t l_q = 0; l_q < a_store_obj_count; ++l_q)
        l_data_size_out += dap_db_get_size_pdap_store_obj_t(&a_store_obj[l_q]);

    dap_store_obj_pkt_t *l_pkt = DAP_NEW_Z_SIZE(dap_store_obj_pkt_t, sizeof(dap_store_obj_pkt_t) + l_data_size_out);
    l_pkt->data_size = l_data_size_out;
    l_pkt->timestamp = a_timestamp;
    uint64_t l_offset = 0;
    uint32_t l_count = (uint32_t) a_store_obj_count;
    memcpy(l_pkt->data + l_offset, &l_count, sizeof(uint32_t));
    l_offset += sizeof(uint32_t);
    for( size_t l_q = 0; l_q < a_store_obj_count; ++l_q) {
        dap_store_obj_t obj = a_store_obj[l_q];
        uint16_t section_size = (uint16_t) dap_strlen(obj.section);
        uint16_t group_size = (uint16_t) dap_strlen(obj.group);
        uint16_t key_size = (uint16_t) dap_strlen(obj.key);
        memcpy(l_pkt->data + l_offset, &obj.type, sizeof(int));
        l_offset += sizeof(int);
        memcpy(l_pkt->data + l_offset, &section_size, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);
        memcpy(l_pkt->data + l_offset, obj.section, section_size);
        l_offset += section_size;
        memcpy(l_pkt->data + l_offset, &group_size, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);
        memcpy(l_pkt->data + l_offset, obj.group, group_size);
        l_offset += group_size;
        memcpy(l_pkt->data + l_offset, &obj.timestamp, sizeof(time_t));
        l_offset += sizeof(time_t);
        memcpy(l_pkt->data + l_offset, &key_size, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);
        memcpy(l_pkt->data + l_offset, obj.key, key_size);
        l_offset += key_size;
        memcpy(l_pkt->data + l_offset, &obj.value_len, sizeof(size_t));
        l_offset += sizeof(size_t);
        memcpy(l_pkt->data + l_offset, obj.value, obj.value_len);
        l_offset += obj.value_len;
    }
    assert(l_data_size_out == l_offset);
    return l_pkt;
}
/**
 * deserialization
 * @param store_obj_count[out] count of the output structures store_obj
 * @return NULL in case of an error*
 */

dap_store_obj_t *dap_store_unpacket(const dap_store_obj_pkt_t *pkt, size_t *store_obj_count)
{
    if(!pkt || pkt->data_size < 1)
        return NULL;
    uint64_t offset = 0;
    uint32_t count;
    memcpy(&count, pkt->data, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    dap_store_obj_t *store_obj = DAP_NEW_Z_SIZE(dap_store_obj_t, count * sizeof(struct dap_store_obj));
    for(size_t q = 0; q < count; ++q) {
        dap_store_obj_t *obj = store_obj + q;
        uint16_t str_size;
        memcpy(&obj->type, pkt->data + offset, sizeof(int));
        offset += sizeof(int);

        memcpy(&str_size, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        obj->section = DAP_NEW_Z_SIZE(char, str_size + 1);
        memcpy(obj->section, pkt->data + offset, str_size);
        offset += str_size;

        memcpy(&str_size, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        obj->group = DAP_NEW_Z_SIZE(char, str_size + 1);
        memcpy(obj->group, pkt->data + offset, str_size);
        offset += str_size;

        memcpy(&obj->timestamp, pkt->data + offset, sizeof(time_t));
        offset += sizeof(time_t);

        memcpy(&str_size, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        obj->key = DAP_NEW_Z_SIZE(char, str_size + 1);
        memcpy(obj->key, pkt->data + offset, str_size);
        offset += str_size;

        memcpy(&obj->value_len, pkt->data + offset, sizeof(size_t));
        offset += sizeof(size_t);

        obj->value = DAP_NEW_Z_SIZE(uint8_t, obj->value_len + 1);
        memcpy(obj->value, pkt->data + offset, obj->value_len);
        offset += obj->value_len;
    }
    assert(pkt->data_size == offset);
    if(store_obj_count)
        *store_obj_count = count;
    return store_obj;
}

void dap_db_deinit()
{
    talloc_free(s_ldb);
    talloc_free(s_mem_ctx);
    free(dap_db_path);
    s_ldb = NULL;
    s_mem_ctx = NULL;
    dap_db_path = NULL;
}
