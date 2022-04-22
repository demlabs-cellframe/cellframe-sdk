#pragma once

#include <stdbool.h>
#include <time.h>
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_global_db_driver.h"

#define F_DB_LOG_ADD_EXTRA_GROUPS   1
#define F_DB_LOG_SYNC_FROM_ZERO     2

#define GDB_SYNC_ALWAYS_FROM_ZERO       // For debug purposes
// for dap_db_log_list_xxx()

typedef struct dap_db_log_list_group {
    char *name;
    uint64_t last_id_synced;
    uint64_t count;
} dap_db_log_list_group_t;

typedef struct dap_db_log_list_obj {
    dap_store_obj_pkt_t *pkt;
    dap_hash_fast_t hash;
} dap_db_log_list_obj_t;

typedef struct dap_db_log_list {
    dap_list_t *list_write; // writed list
    dap_list_t *list_read; // readed list (inside list_write)
    bool is_process;
    size_t items_rest; // rest items to read from list_read
    size_t items_number; // total items in list_write after reading from db
    dap_list_t *groups;
    pthread_t thread;
    pthread_mutex_t list_mutex;
} dap_db_log_list_t;

// Set addr for current node
bool dap_db_set_cur_node_addr(uint64_t a_address, char *a_net_name);
bool dap_db_set_cur_node_addr_exp(uint64_t a_address, char *a_net_name );
uint64_t dap_db_get_cur_node_addr(char *a_net_name);

// Set last id for remote node
bool dap_db_set_last_id_remote(uint64_t a_node_addr, uint64_t a_id, char *a_group);
// Get last id for remote node
uint64_t dap_db_get_last_id_remote(uint64_t a_node_addr, char *a_group);
// Set last hash for chain for remote node
bool dap_db_set_last_hash_remote(uint64_t a_node_addr, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_hash);
// Get last hash for chain for remote node
dap_chain_hash_fast_t *dap_db_get_last_hash_remote(uint64_t a_node_addr, dap_chain_t *a_chain);

dap_store_obj_pkt_t *dap_store_packet_single(dap_store_obj_t *a_store_obj);
dap_store_obj_pkt_t *dap_store_packet_multiple(dap_store_obj_pkt_t *a_old_pkt, dap_store_obj_pkt_t *a_new_pkt);
dap_store_obj_t *dap_store_unpacket_multiple(const dap_store_obj_pkt_t *a_pkt, size_t *a_store_obj_count);
char *dap_store_packet_get_group(dap_store_obj_pkt_t *a_pkt);
uint64_t dap_store_packet_get_id(dap_store_obj_pkt_t *a_pkt);
void dap_store_packet_change_id(dap_store_obj_pkt_t *a_pkt, uint64_t a_id);

dap_db_log_list_t* dap_db_log_list_start(dap_chain_net_t *l_net, dap_chain_node_addr_t a_addr, int a_flags);
size_t dap_db_log_list_get_count(dap_db_log_list_t *a_db_log_list);
size_t dap_db_log_list_get_count_rest(dap_db_log_list_t *a_db_log_list);
dap_db_log_list_obj_t *dap_db_log_list_get(dap_db_log_list_t *a_db_log_list);
void dap_db_log_list_delete(dap_db_log_list_t *a_db_log_list);
// Get last id in log
uint64_t dap_db_log_get_group_last_id(const char *a_group_name);
uint64_t dap_db_log_get_last_id(void);
void dap_db_log_list_rewind(dap_db_log_list_t *a_db_log_list);
