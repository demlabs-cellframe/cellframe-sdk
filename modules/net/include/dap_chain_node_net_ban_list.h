#pragma once

#include "uthash.h"
#ifdef WIN32
#include <winsock2.h>
#endif
#ifdef DAP_OS_UNIX
#include <arpa/inet.h>
#endif
#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_enc_http_ban_list_client.h"
#include "dap_chain_net.h"
#include "uthash.h"

typedef struct dap_chain_node_ban_list_record{
    dap_chain_node_addr_t node_addr;
    dap_hash_fast_t decree_hash;
    dap_time_t ts_created_decree;
    UT_hash_handle hh;
}dap_chain_node_ban_list_record_t;

bool dap_chain_node_net_ban_list_check_node_addr(dap_chain_node_addr_t node_addr);

bool dap_chain_node_net_ban_list_add_node_addr(dap_chain_node_addr_t node_addr, dap_hash_fast_t a_decree_hash, dap_time_t a_time_created, dap_chain_net_t *a_net);
void dap_chain_node_net_ban_list_remove_node_addr(dap_chain_net_t *a_net, dap_chain_node_addr_t node_addr);
void dap_chain_node_net_ban_list_print(dap_string_t *a_str_out);

int dap_chain_node_net_ban_list_init();
void dap_chain_node_net_ban_list_deinit();
