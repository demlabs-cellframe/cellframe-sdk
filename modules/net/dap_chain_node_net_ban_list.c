#include "dap_chain_node_net_ban_list.h"
#include "dap_list.h"
#include "dap_cli_server.h"
#include "dap_chain_node.h"

#undef LOG_TAG
#define LOG_TAG "dap_chain_node_net_ban_list"

static dap_chain_node_ban_list_record_t *s_ban_addr_list = NULL;
static pthread_rwlock_t s_ban_addr_list_rwlock;

bool s_chain_node_net_ban_list_addr_resolve_ip_v4(dap_chain_net_t  *a_net, dap_chain_node_addr_t a_node_addr, struct in_addr *a_out_ip) {
    char *l_key = dap_chain_node_addr_to_hash_str(&a_node_addr);
    if (!l_key)
        return false;
    size_t l_node_info_size = 0;
    dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t*) dap_global_db_get_sync(a_net->pub.gdb_nodes, l_key, &l_node_info_size, NULL, NULL);
    if (!l_node_info) {
        log_it(L_ERROR, "Unable to add node address to ban list: Node address could not be resolved to IP address, no information in GDB.");
        return false;
    }
    size_t node_info_size_must_be = dap_chain_node_info_get_size(l_node_info);
    if(node_info_size_must_be != l_node_info_size) {
        DAP_DELETE(l_node_info);
        DAP_DELETE(l_key);
        return false;
    }
    DAP_DELETE(l_key);
    *a_out_ip = l_node_info->hdr.ext_addr_v4;
    return true;
}

bool dap_chain_node_net_ban_list_check_node_addr(dap_chain_node_addr_t node_addr){
    pthread_rwlock_rdlock(&s_ban_addr_list_rwlock);
    dap_chain_node_ban_list_record_t *l_record = NULL;
    HASH_FIND(hh, s_ban_addr_list, &node_addr, sizeof(dap_chain_node_addr_t), l_record);
    pthread_rwlock_unlock(&s_ban_addr_list_rwlock);
    return l_record ? true : false;
}

bool dap_chain_node_net_ban_list_add_node_addr(dap_chain_node_addr_t node_addr, dap_hash_fast_t a_decree_hash, dap_time_t a_time_created, dap_chain_net_t *a_net){
    dap_chain_node_ban_list_record_t *l_record = DAP_NEW(dap_chain_node_ban_list_record_t);
    //Resolve addr to ip
    struct in_addr l_in;
    if (s_chain_node_net_ban_list_addr_resolve_ip_v4(a_net, node_addr, &l_in)) {
        dap_enc_http_ban_list_client_add_ipv4(l_in, a_decree_hash, a_time_created);
        l_record->node_addr = node_addr;
        l_record->decree_hash = a_decree_hash;
        l_record->ts_created_decree = a_time_created;
        pthread_rwlock_wrlock(&s_ban_addr_list_rwlock);
        HASH_ADD(hh, s_ban_addr_list, node_addr, sizeof(dap_chain_node_addr_t), l_record);
        pthread_rwlock_unlock(&s_ban_addr_list_rwlock);
        return true;
    } else {
        DAP_DELETE(l_record);
        return false;
    }
}

void dap_chain_node_net_ban_list_print(dap_string_t *a_str_out) {
    int number = 1;
    a_str_out = dap_string_append(a_str_out, "\t Address node.\n");
    pthread_rwlock_rdlock(&s_ban_addr_list_rwlock);
    if (!s_ban_addr_list) {
        a_str_out = dap_string_append(a_str_out, "\t\t Not found.\n\n");
        return;
    }
    dap_chain_node_ban_list_record_t *l_record = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_ban_addr_list, l_record, l_tmp) {
        number++;
        char *l_decree_hash_str = dap_hash_fast_to_str_new(&l_record->decree_hash);
        char l_time_out[65] = {'\0'};
        dap_time_to_str_rfc822(l_time_out, 65, l_record->ts_created_decree);
        dap_string_append_printf(a_str_out, "\t\t%d) %s\n"
                                        "\t\t\tAddress: "NODE_ADDR_FP_STR"\n"
                                        "\t\t\tCreated: %s\n", number, l_decree_hash_str,
                                        NODE_ADDR_FP_ARGS_S(l_record->node_addr), l_time_out);
        DAP_DELETE(l_decree_hash_str);
    }
    pthread_rwlock_unlock(&s_ban_addr_list_rwlock);
}

void dap_chain_node_net_ban_list_remove_node_addr(dap_chain_net_t *a_net, dap_chain_node_addr_t node_addr) {
    pthread_rwlock_wrlock(&s_ban_addr_list_rwlock);
    dap_chain_node_ban_list_record_t *l_record = NULL;
    HASH_FIND(hh, s_ban_addr_list, &node_addr, sizeof(dap_chain_node_addr_t), l_record);
    if (l_record) {
        if (l_record->node_addr.uint64 == node_addr.uint64) {
            struct in_addr l_in;
            if (s_chain_node_net_ban_list_addr_resolve_ip_v4(a_net, l_record->node_addr, &l_in)) {
                dap_enc_http_ban_list_client_remove_ipv4(l_in);
            } else {
                log_it(L_WARNING, "Can't resolve node address "NODE_ADDR_FP_STR" to ip at remove node addr from ban list",
                       NODE_ADDR_FP_ARGS_S(l_record->node_addr));
            }
            DAP_DELETE(l_record);
        }
    }
    pthread_rwlock_unlock(&s_ban_addr_list_rwlock);
}

int dap_chain_node_net_ban_list_init() {
    s_ban_addr_list = NULL;
    pthread_rwlock_init(&s_ban_addr_list_rwlock, NULL);
    return 0;
}
void dap_chain_node_net_ban_list_deinit() {
    pthread_rwlock_destroy(&s_ban_addr_list_rwlock);
}
