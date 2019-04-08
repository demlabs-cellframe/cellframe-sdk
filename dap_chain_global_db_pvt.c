#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

//#include "talloc.h"
#include "dap_chain_global_db_pvt.h"

#define LOG_TAG "dap_global_db"
#define TDB_PREFIX_LEN 7

static struct ldb_context *ldb = NULL;
static TALLOC_CTX *mem_ctx = NULL;

//static int dap_store_len = 0; // initialized only when reading from local db
static char *dap_db_path = NULL;

#define CALL2(a, b, ...) (a), (b)
#define dap_db_add_record(...) dap_db_merge(CALL2(__VA_ARGS__, 0))

static int dap_db_add_msg(struct ldb_message *a_msg)
{
    if(ldb_msg_sanity_check(ldb, a_msg) != LDB_SUCCESS) {
        log_it(L_ERROR, "LDB message is inconsistent: %s", ldb_errstring(ldb));
        return -1;
    }
    ldb_transaction_start(ldb);
    int status = ldb_add(ldb, a_msg);
    // Delete the entry if it already exist and add again
    if(status == LDB_ERR_ENTRY_ALREADY_EXISTS) {
        ldb_delete(ldb, a_msg->dn);
        status = ldb_add(ldb, a_msg);
    }
    if(status != LDB_SUCCESS) {
        if(status == LDB_ERR_ENTRY_ALREADY_EXISTS) {
            log_it(L_INFO, "Entry %s already present, skipped", ldb_dn_get_linearized(a_msg->dn));
        }
        else {
            log_it(L_ERROR, "LDB adding error: %s", ldb_errstring(ldb));
        }
        ldb_transaction_cancel(ldb);
        return -2;
    }
    else {
        ldb_transaction_commit(ldb);
        log_it(L_INFO, "Entry %s added", ldb_dn_get_linearized(a_msg->dn));
        return 0;
    }
    return -1;
}

int dap_db_init(const char *path)
{
    mem_ctx = talloc_new(NULL);
    if(ldb_global_init() != 0) {
        log_it(L_ERROR, "Couldn't initialize LDB's global information");
        return -1;
    };
    if((ldb = ldb_init(mem_ctx, NULL)) != LDB_SUCCESS) {
        log_it(L_INFO, "ldb context initialized");
        char tdb_path[strlen(path) + TDB_PREFIX_LEN];
        memset(tdb_path, '\0', strlen(path) + TDB_PREFIX_LEN);
        strcat(tdb_path, "tdb://"); // using tdb for simplicity, no need for separate LDAP server
        strcat(tdb_path, path);
        struct ldb_result *data_message;
        if(ldb_connect(ldb, tdb_path, 0, NULL) != LDB_SUCCESS) {
            log_it(L_ERROR, "Couldn't connect to database");
            return 1;
        }
        dap_db_path = strdup(tdb_path);
        const char *query = "(dn=*)";
        if(ldb_search(ldb, mem_ctx, &data_message, NULL, LDB_SCOPE_DEFAULT, NULL, query) != LDB_SUCCESS) {
            log_it(L_ERROR, "Database querying failed");
            return 2;
        }
        struct ldb_message *msg;
        if(data_message->count == 0) {
            // level 1: section record
            msg = ldb_msg_new(ldb);
            msg->dn = ldb_dn_new(mem_ctx, ldb, "dc=kelvin_nodes");
            ldb_msg_add_string(msg, "dc", "kelvin_nodes");
            ldb_msg_add_string(msg, "objectClass", "top");
            ldb_msg_add_string(msg, "objectClass", "section");
            dap_db_add_msg(msg);
            talloc_free(msg->dn);
            talloc_free(msg);

            // level 2: group record
            msg = ldb_msg_new(ldb);
            msg->dn = ldb_dn_new(mem_ctx, ldb, "ou=addrs_leased,dc=kelvin_nodes");
            ldb_msg_add_string(msg, "ou", "addrs_leased");
            ldb_msg_add_string(msg, "objectClass", "group");
            ldb_msg_add_string(msg, "section", "kelvin_nodes");
            ldb_msg_add_string(msg, "description", "Whitelist of Kelvin blockchain nodes");
            dap_db_add_msg(msg);
            talloc_free(msg->dn);
            talloc_free(msg);

            // level 2: group record
            msg = ldb_msg_new(ldb);
            msg->dn = ldb_dn_new(mem_ctx, ldb, "ou=aliases_leased,dc=kelvin_nodes");
            ldb_msg_add_string(msg, "ou", "aliases_leased");
            ldb_msg_add_string(msg, "objectClass", "group");
            ldb_msg_add_string(msg, "section", "kelvin_nodes");
            ldb_msg_add_string(msg, "description", "Aliases of Kelvin blockchain nodes");
            dap_db_add_msg(msg);
            talloc_free(msg->dn);
            talloc_free(msg);

            // level 2: group record
            msg = ldb_msg_new(ldb);
            msg->dn = ldb_dn_new(mem_ctx, ldb, "ou=datums,dc=kelvin_nodes");
            ldb_msg_add_string(msg, "ou", "datums");
            ldb_msg_add_string(msg, "objectClass", "group");
            ldb_msg_add_string(msg, "section", "kelvin_nodes");
            ldb_msg_add_string(msg, "description", "List of Datums");
            dap_db_add_msg(msg);
            talloc_free(msg->dn);
            talloc_free(msg);
        }
        talloc_free(data_message);
        return 0;
    }
    else {
        log_it(L_ERROR, "Couldn't initialize LDB context");
        return -2;
    }
    return -1;
}

int dap_db_del_msg(struct ldb_dn *ldn)
{
    ldb_transaction_start(ldb);
    int status = ldb_delete(ldb, ldn);
    if(status != LDB_SUCCESS) {
        log_it(L_ERROR, "LDB deleting error: %s", ldb_errstring(ldb));
        ldb_transaction_cancel(ldb);
        return -2;
    }
    else {
        ldb_transaction_commit(ldb);
        log_it(L_INFO, "Entry %s deleted", ldb_dn_get_linearized(ldn));
        return 0;
    }
    return -1;
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
pdap_store_obj_t dap_db_read_data(const char *query, int *count, const char *group)
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
    if(ldb_connect(ldb, dap_db_path, LDB_FLG_RDONLY, NULL) != LDB_SUCCESS) {
        log_it(L_ERROR, "Couldn't connect to database");
        return NULL;
    }
    //sample: query = "(objectClass=addr_leased)";
    if(ldb_search(ldb, NULL, &data_message, NULL, LDB_SCOPE_DEFAULT, NULL, query) != LDB_SUCCESS) {
        log_it(L_ERROR, "Database querying failed");
        return NULL;
    }
    log_it(L_INFO, "Obtained binary data, %d entries", data_message->count);

    pdap_store_obj_t store_data = DAP_NEW_Z_SIZE(dap_store_obj_t, data_message->count * sizeof(struct dap_store_obj));
    if(!store_data) {
        log_it(L_ERROR, "Couldn't allocate memory, store objects unobtained");
        talloc_free(data_message);
        return NULL;
    }
    int dap_store_len = data_message->count;
    int q;
    for(q = 0; q < dap_store_len; ++q) {
        unsigned int num_elements;
        struct ldb_message_element *elements;
        store_data[q].section = strdup(ldb_msg_find_attr_as_string(data_message->msgs[q], "section", "")); //strdup("kelvin_nodes");
        store_data[q].group = strdup(ldb_msg_find_attr_as_string(data_message->msgs[q], "objectClass", "")); //strdup(group);
        store_data[q].type = 1;
        store_data[q].key = strdup(ldb_msg_find_attr_as_string(data_message->msgs[q], "cn", ""));
        store_data[q].timestamp = ldb_msg_find_attr_as_uint64(data_message->msgs[q], "time", 5);
        const struct ldb_val *l_val = ldb_msg_find_ldb_val(data_message->msgs[q], "time");

        l_val = ldb_msg_find_ldb_val(data_message->msgs[q], "val");
        if(l_val) {
            store_data[q].value_len = l_val->length;
            store_data[q].value = DAP_NEW_SIZE(uint8_t, l_val->length);
            memcpy(store_data[q].value, l_val->data, l_val->length);
        }
        log_it(L_INFO, "Record %s read successfully", ldb_dn_get_linearized(data_message->msgs[q]->dn));
    }
    talloc_free(data_message);
    if(count)
        *count = dap_store_len;
    return store_data;
}

/**
 * clean memory
 */
void dab_db_free_pdap_store_obj_t(pdap_store_obj_t store_data, int count)
{
    if(!store_data)
        return;
    for(int i = 0; i < count; i++) {
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

    int q = 0;
    for(ldif_msg = ldb_ldif_read_file(ldb, fs); ldif_msg; ldif_msg = ldb_ldif_read_file(ldb, fs), q++) {
        if(q % 256 == 0) {
            store_data = (pdap_store_obj_t) realloc(store_data, (q + 256) * sizeof(dap_store_obj_t));
        }
        /* if (ldif_msg->changetype == LDB_CHANGETYPE_ADD) {
         / ... /
         } */ // in case we gonna use extra LDIF functionality
        const char *key = ldb_msg_find_attr_as_string(ldif_msg->msg, "cn", NULL);
        if(key != NULL) {
            store_data[q].section = strdup("kelvin_nodes");
            store_data[q].group = strdup(group);
            store_data[q].type = 1;
            store_data[q].key = strdup(key);
            store_data[q].value = strdup(ldb_msg_find_attr_as_string(ldif_msg->msg, "time", NULL));
            log_it(L_INFO, "Record %s stored successfully", ldb_dn_get_linearized(ldif_msg->msg->dn));
        }
        ldb_ldif_read_free(ldb, ldif_msg);
    }
    fclose(fs);
    return store_data;
}

/*
 * Add multiple entries received from remote node to local database.
 * Since we don't know the size, it must be supplied too
 *
 * dap_store_size the count records
 */
int dap_db_add(pdap_store_obj_t a_store_obj, int a_store_count)
{
    int l_ret = 0;
    if(a_store_obj == NULL) {
        log_it(L_ERROR, "Invalid Dap store objects passed");
        return -1;
    }
    if(ldb_connect(ldb, dap_db_path, 0, NULL) != LDB_SUCCESS) {
        log_it(L_ERROR, "Couldn't connect to database");
        return -2;
    }
    //log_it(L_INFO, "We're about to put %d records into database", a_store_count);
    struct ldb_message *l_msg;
    int q;
    if(a_store_count == 0) {
        a_store_count = 1;
    }
    for(q = 0; q < a_store_count; q++) {
        // level 3: leased address, single whitelist entity

        // if it is marked, don't save
        if(a_store_obj[q].timestamp == (time_t) -1)
            continue;

        l_msg = ldb_msg_new(ldb);
        char dn[256];
        memset(dn, '\0', 256);
        strcat(dn, "cn=");
        strcat(dn, a_store_obj[q].key);
        //strcat(dn, ",ou=addrs_leased,dc=kelvin_nodes");
        strcat(dn, ",ou=");
        strcat(dn, a_store_obj[q].group);
        strcat(dn, ",dc=kelvin_nodes");
        l_msg->dn = ldb_dn_new(mem_ctx, ldb, dn);
        int l_res = ldb_msg_add_string(l_msg, "cn", a_store_obj[q].key);
        ldb_msg_add_string(l_msg, "objectClass", a_store_obj[q].group);
        ldb_msg_add_string(l_msg, "section", "kelvin_nodes");
        ldb_msg_add_string(l_msg, "description", "Approved Kelvin node");

        struct ldb_val l_val;
        struct ldb_message_element *return_el;
        l_val.data = (uint8_t*) &a_store_obj[q].timestamp;
        l_val.length = sizeof(time_t);
        l_res = ldb_msg_add_value(l_msg, "time", &l_val, &return_el);
        ldb_msg_remove_element(l_msg, return_el);

        l_val.data = a_store_obj[q].value;
        l_val.length = a_store_obj[q].value_len;
        l_res = ldb_msg_add_steal_value(l_msg, "val", &l_val);

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
 */
int dap_db_delete(pdap_store_obj_t store_obj, int a_store_count)
{
    int ret = 0;
    if(store_obj == NULL) {
        log_it(L_ERROR, "Invalid Dap store objects passed");
        return -1;
    }
    if(ldb_connect(ldb, dap_db_path, 0, NULL) != LDB_SUCCESS) {
        log_it(L_ERROR, "Couldn't connect to database");
        return -2;
    }
    //log_it(L_INFO, "We're delete %d records from database", a_store_count);
    struct ldb_message *msg;
    int q;
    if(a_store_count == 0) {
        a_store_count = 1;
    }
    for(q = 0; q < a_store_count; q++) {
        char dn[128];
        memset(dn, '\0', 128);
        strcat(dn, "cn=");
        strcat(dn, store_obj[q].key);
        //strcat(dn, ",ou=addrs_leased,dc=kelvin_nodes");
        strcat(dn, ",ou=");
        strcat(dn, store_obj[q].group);
        strcat(dn, ",dc=kelvin_nodes");
        struct ldb_dn *ldn = ldb_dn_new(mem_ctx, ldb, dn);
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
    size_t size = sizeof(uint32_t) + 4 * sizeof(uint16_t) + strlen(store_obj->group) +
            strlen(store_obj->key) + strlen(store_obj->section) + strlen(store_obj->value);
    return size;
}

/**
 * serialization
 * @param a_store_obj_count count of structures store_obj
 * @param a_timestamp create data time
 * @param a_size_out[out] size of output structure
 * @return NULL in case of an error
 */
dap_store_obj_pkt_t *dap_store_packet_multiple(pdap_store_obj_t a_store_obj, time_t a_timestamp, int a_store_obj_count)
{
    if(!a_store_obj || a_store_obj_count < 1)
        return NULL;
    size_t l_data_size_out = sizeof(uint32_t); // size of output data
    int l_q;
    // calculate output structure size
    for(l_q = 0; l_q < a_store_obj_count; ++l_q)
        l_data_size_out += dap_db_get_size_pdap_store_obj_t(&a_store_obj[l_q]);

    dap_store_obj_pkt_t *l_pkt = DAP_NEW_Z_SIZE(dap_store_obj_pkt_t, sizeof(dap_store_obj_pkt_t) + l_data_size_out);
    l_pkt->data_size = l_data_size_out;
    l_pkt->timestamp = a_timestamp;
    uint64_t l_offset = 0;
    uint32_t l_count = (uint32_t) a_store_obj_count;
    memcpy(l_pkt->data + l_offset, &l_count, sizeof(uint32_t));
    l_offset += sizeof(uint32_t);
    for(l_q = 0; l_q < a_store_obj_count; ++l_q) {
        dap_store_obj_t obj = a_store_obj[l_q];
        uint16_t section_size = (uint16_t) strlen(obj.section);
        uint16_t group_size = (uint16_t) strlen(obj.group);
        uint16_t key_size = (uint16_t) strlen(obj.key);
        uint16_t value_size = (uint16_t) strlen(obj.value);
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
        memcpy(l_pkt->data + l_offset, &key_size, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);
        memcpy(l_pkt->data + l_offset, obj.key, key_size);
        l_offset += key_size;
        memcpy(l_pkt->data + l_offset, &value_size, sizeof(uint16_t));
        l_offset += sizeof(uint16_t);
        memcpy(l_pkt->data + l_offset, obj.value, value_size);
        l_offset += value_size;
    }
    assert(l_data_size_out == l_offset);
    return l_pkt;
}
/**
 * deserialization
 * @param store_obj_count[out] count of the output structures store_obj
 * @return NULL in case of an error*
 */

dap_store_obj_t *dap_store_unpacket(dap_store_obj_pkt_t *pkt, int *store_obj_count)
{
    if(!pkt || pkt->data_size < 1)
        return NULL;
    int q;
    uint64_t offset = 0;
    uint32_t count;
    memcpy(&count, pkt->data, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    dap_store_obj_t *store_obj = DAP_NEW_Z_SIZE(dap_store_obj_t, count * sizeof(struct dap_store_obj));
    for(q = 0; q < count; ++q) {
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

        memcpy(&str_size, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        obj->key = DAP_NEW_Z_SIZE(char, str_size + 1);
        memcpy(obj->key, pkt->data + offset, str_size);
        offset += str_size;

        memcpy(&str_size, pkt->data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        obj->value = DAP_NEW_Z_SIZE(char, str_size + 1);
        memcpy(obj->value, pkt->data + offset, str_size);
        offset += str_size;
    }
    assert(pkt->data_size == offset);
    if(store_obj_count)
        *store_obj_count = count;
    return store_obj;
}

void dap_db_deinit()
{
    talloc_free(ldb);
    talloc_free(mem_ctx);
    free(dap_db_path);
    ldb = NULL;
    mem_ctx = NULL;
    dap_db_path = NULL;
}
