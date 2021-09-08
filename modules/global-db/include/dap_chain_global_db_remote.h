#pragma once

#include <stdbool.h>
#include <time.h>
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_global_db_driver.h"
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

dap_store_obj_pkt_t *dap_store_packet_single(pdap_store_obj_t a_store_obj);
dap_store_obj_pkt_t *dap_store_packet_multiple(dap_store_obj_pkt_t *a_old_pkt, dap_store_obj_pkt_t *a_new_pkt);
dap_store_obj_t *dap_store_unpacket_multiple(const dap_store_obj_pkt_t *a_pkt, size_t *a_store_obj_count);
char *dap_store_packet_get_group(dap_store_obj_pkt_t *a_pkt);
uint64_t dap_store_packet_get_id(dap_store_obj_pkt_t *a_pkt);
void dap_store_packet_change_id(dap_store_obj_pkt_t *a_pkt, uint64_t a_id);
