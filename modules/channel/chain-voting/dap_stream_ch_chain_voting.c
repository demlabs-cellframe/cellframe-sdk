#include "dap_stream.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch_chain_voting.h"
#include "dap_chain_net.h"
#include "dap_client_pvt.h"

#include "dap_chain_node_cli.h"

#define LOG_TAG "dap_stream_ch_chain_voting"

struct voting_pkt_in_callback {
    void * arg;
    dap_chain_voting_ch_callback_t packet_in_callback;
};

struct voting_node_client_list {
    dap_chain_node_addr_t node_addr;    // HT key
    dap_chain_node_info_t *node_info;
    dap_chain_node_client_t *node_client;
    UT_hash_handle hh;
};

static struct voting_node_client_list *s_node_client_list = NULL;

static size_t s_pkt_in_callback_count = 0;
static struct voting_pkt_in_callback s_pkt_in_callback[16] = {};

static void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_packet_in(dap_stream_ch_t *a_ch, void *a_arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg);

int dap_stream_ch_chain_voting_init()
{
    log_it(L_NOTICE, "Chains voting channel initialized");

    dap_stream_ch_proc_add(dap_stream_ch_chain_voting_get_id(),
                           s_stream_ch_new,
                           s_stream_ch_delete,
                           s_stream_ch_packet_in,
                           NULL);

    return 0;
}

void dap_stream_ch_chain_voting_in_callback_add(void* a_arg, dap_chain_voting_ch_callback_t packet_in_callback)
{
    size_t i = s_pkt_in_callback_count;
    s_pkt_in_callback[i].arg = a_arg;
    s_pkt_in_callback[i].packet_in_callback = packet_in_callback;
    s_pkt_in_callback_count++;
}

static void s_callback_pkt_in_call_all(dap_stream_ch_chain_voting_pkt_t *a_voting_pkt)
{
    for (size_t i = 0; i < s_pkt_in_callback_count; i++) {
        struct voting_pkt_in_callback *l_callback = s_pkt_in_callback + i;
        if (l_callback->packet_in_callback) {
            l_callback->packet_in_callback(l_callback->arg, &a_voting_pkt->hdr.sender_node_addr,
                                           &a_voting_pkt->hdr.data_hash, a_voting_pkt->data, a_voting_pkt->hdr.data_size);
        }
    }
}

void dap_stream_ch_chain_voting_message_write(dap_chain_net_t * a_net, dap_list_t *a_sendto_nodes,
                                              const void * a_data, size_t a_data_size)
{
    dap_stream_ch_chain_voting_pkt_t *l_voting_pkt = dap_stream_ch_chain_voting_pkt_new(a_net->pub.id.uint64, a_data, a_data_size);
    for (dap_list_t *it = a_sendto_nodes; it; it = it->next) {
        dap_chain_node_addr_t *l_remote_node_addr = (dap_chain_node_addr_t *)it->data;
        struct voting_node_client_list *l_node_client_item = NULL;
        if (l_remote_node_addr->uint64 != dap_chain_net_get_cur_addr_int(a_net)) {
            HASH_FIND(hh, s_node_client_list, l_remote_node_addr, sizeof(dap_chain_node_addr_t), l_node_client_item);
            if (!l_node_client_item) {
                size_t node_info_size = 0;
                char *l_key = dap_chain_node_addr_to_hash_str(l_remote_node_addr);
                dap_chain_node_info_t *l_node_info =
                        (dap_chain_node_info_t *)dap_global_db_get_sync(a_net->pub.gdb_nodes, l_key,
                                                                            &node_info_size, NULL, NULL);
                DAP_DELETE(l_key);
                if (!l_node_info) {
                    log_it(L_WARNING, "Can't find validator's addr "NODE_ADDR_FP_STR" in database", NODE_ADDR_FP_ARGS(l_remote_node_addr));
                    continue;
                }
                char l_channels[] = {dap_stream_ch_chain_voting_get_id(),0};
                dap_chain_node_client_t *l_node_client = dap_chain_node_client_connect_channels(a_net, l_node_info, l_channels);
                if (!l_node_client || !l_node_client->client) {
                    log_it(L_ERROR, "Can't connect to remote node "NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(l_remote_node_addr));
                    continue;
                }
                l_node_client->client->connect_on_demand = true;

                l_node_client_item = DAP_NEW_Z(struct voting_node_client_list);
                l_node_client_item->node_addr = *l_remote_node_addr;
                l_node_client_item->node_info = l_node_info;
                l_node_client_item->node_client = l_node_client;
                HASH_ADD(hh, s_node_client_list, node_addr, sizeof(dap_chain_node_addr_t), l_node_client_item);
            }
            if (!l_node_client_item->node_client) {
                log_it(L_ERROR, "NULL node_client in item of voting channel");
                continue;
            }
            dap_chain_node_client_write_mt(l_node_client_item->node_client, dap_stream_ch_chain_voting_get_id(),
                                           DAP_STREAM_CH_CHAIN_VOTING_PKT_TYPE_DATA, l_voting_pkt,
                                           sizeof(l_voting_pkt) + a_data_size);
        } else
            s_callback_pkt_in_call_all(l_voting_pkt);
    }
}

void dap_stream_ch_chain_voting_deinit() {
    struct voting_node_client_list *l_node_info_item, *l_node_info_tmp;
    HASH_ITER(hh, s_node_client_list, l_node_info_item, l_node_info_tmp) {
        // Clang bug at this, l_node_info_item should change at every loop cycle
        HASH_DEL(s_node_client_list, l_node_info_item);
        dap_chain_node_client_close_mt(l_node_info_item->node_client);
        DAP_DELETE(l_node_info_item);
    }
}

static void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg) {
    UNUSED(a_arg);
    a_ch->internal = DAP_NEW_Z(dap_stream_ch_chain_voting_t);
    dap_stream_ch_chain_voting_t *l_ch_chain_voting = DAP_STREAM_CH_CHAIN_VOTING(a_ch);
    l_ch_chain_voting->_inheritor = a_ch;
}

static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg)
{
    DAP_DEL_Z(a_ch->internal);
}

static void s_stream_ch_packet_in(dap_stream_ch_t *a_ch, void *a_arg)
{
    dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
    if (!l_ch_pkt)
        return;

    size_t l_voting_pkt_size = l_ch_pkt->hdr.data_size;
    if (!l_voting_pkt_size || l_voting_pkt_size > UINT16_MAX)
        return;

    dap_stream_ch_chain_voting_pkt_t *l_voting_pkt = (dap_stream_ch_chain_voting_pkt_t *)l_ch_pkt->data;
    s_callback_pkt_in_call_all(l_voting_pkt);
    dap_stream_ch_chain_voting_t *l_ch_chain_voting = DAP_STREAM_CH_CHAIN_VOTING(a_ch);
    if (l_ch_chain_voting->callback_notify)
        l_ch_chain_voting->callback_notify(l_ch_chain_voting, l_ch_pkt->hdr.type, l_voting_pkt,
                                           l_voting_pkt->hdr.data_size, l_ch_chain_voting->callback_notify_arg);
}

dap_stream_ch_chain_voting_pkt_t *dap_stream_ch_chain_voting_pkt_new(uint64_t a_net_id, const void *a_data, size_t a_data_size)
{
    dap_stream_ch_chain_voting_pkt_t *l_voting_pkt = DAP_NEW_Z_SIZE(dap_stream_ch_chain_voting_pkt_t,
                                                                   sizeof(dap_stream_ch_chain_voting_pkt_t) + a_data_size);
    l_voting_pkt->hdr.data_size = a_data_size;
    l_voting_pkt->hdr.version = 1;
    l_voting_pkt->hdr.net_id.uint64 = a_net_id;
    dap_hash_fast(a_data, a_data_size, &l_voting_pkt->hdr.data_hash);
    if (a_data_size && a_data)
        memcpy(l_voting_pkt->data, a_data, a_data_size);
    return l_voting_pkt;
}

size_t dap_stream_ch_chain_voting_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                                   const void * a_data, size_t a_data_size)
{

    dap_stream_ch_chain_voting_pkt_t *l_voting_pkt = dap_stream_ch_chain_voting_pkt_new(a_net_id, a_data, a_data_size);
    size_t l_ret  = dap_stream_ch_pkt_write_unsafe(a_ch, a_type, l_voting_pkt, sizeof(l_voting_pkt) + a_data_size);
    DAP_DELETE(l_voting_pkt);
    return l_ret;
}
