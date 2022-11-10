

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

typedef struct voting_pkt_in_callback{
	void * arg;
    voting_ch_callback_t packet_in_callback;
} voting_pkt_in_callback_t;

typedef struct voting_pkt_addr
{
	dap_chain_node_addr_t node_addr;
	dap_stream_ch_chain_voting_pkt_t *voting_pkt;
} voting_pkt_addr_t;

typedef struct voting_pkt_items
{
	pthread_rwlock_t rwlock_out;
	pthread_rwlock_t rwlock_in;
	dap_list_t * pkts_out; // voting_pkt_addr_t
	dap_list_t * pkts_in; // dap_stream_ch_chain_voting_pkt_t
} voting_pkt_items_t;

typedef struct voting_node_client_list {
    dap_chain_node_info_t *node_info;
    dap_chain_node_client_t *node_client;
    dap_events_socket_uuid_t uuid;
    dap_chain_node_addr_t node_addr;
    UT_hash_handle hh;
} voting_node_client_list_t;

static size_t s_pkt_in_callback_count = 0;
static voting_pkt_in_callback_t s_pkt_in_callback[256]={{0}};
static voting_pkt_items_t *s_pkt_items = NULL;
static voting_node_client_list_t *s_node_client_list = NULL;

static void s_callback_send_all_loopback(uint64_t a_node_addr);
static void s_callback_send_all_unsafe(dap_client_t *a_client, void *a_arg);

static void s_callback_send_all_unsafe(dap_client_t *a_client, void *a_arg);
static void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg);

static bool s_packet_in_callback_handler(void * a_arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg);

static dap_timerfd_t * s_packet_in_callback_timer = NULL; 
static bool s_is_inited = false;

//static int s_cli_voting(int argc, char ** argv, char **a_str_reply);

int dap_stream_ch_chain_voting_init() {
	log_it(L_NOTICE, "Chains voting channel initialized");
	if (s_is_inited) {
		return 0;
	}

    if (!s_pkt_items) {
		s_pkt_items = DAP_NEW_Z(voting_pkt_items_t);
		s_pkt_items->pkts_out = NULL;
		s_pkt_items->pkts_in = NULL;
		pthread_rwlock_init(&s_pkt_items->rwlock_out, NULL);
		pthread_rwlock_init(&s_pkt_items->rwlock_in, NULL);
    }

    dap_stream_ch_proc_add(dap_stream_ch_chain_voting_get_id(), 
    		s_stream_ch_new, 
    		s_stream_ch_delete,
    		s_stream_ch_packet_in,
            s_stream_ch_packet_out);

	if (!s_packet_in_callback_timer) {
		s_packet_in_callback_timer = dap_timerfd_start(1*1000, 
                        (dap_timerfd_callback_t)s_packet_in_callback_handler, 
                        NULL);
	}
	s_is_inited = true;
	// s_packet_in_callback_handler();
	return 0;
}

void dap_stream_ch_chain_voting_in_callback_add(void* a_arg, voting_ch_callback_t packet_in_callback) {
	size_t i = s_pkt_in_callback_count;
	s_pkt_in_callback[i].arg = a_arg;
	s_pkt_in_callback[i].packet_in_callback = packet_in_callback;
	s_pkt_in_callback_count++;
}

void dap_stream_ch_chain_voting_message_write(dap_chain_net_t * a_net, dap_list_t *a_sendto_nodes, 
												dap_chain_hash_fast_t * a_data_hash,
                                                    const void * a_data, size_t a_data_size)
{
    dap_stream_ch_chain_voting_pkt_t * l_voting_pkt;
    size_t l_voting_pkt_size = sizeof(l_voting_pkt->hdr) + a_data_size;
    l_voting_pkt = DAP_NEW_SIZE(dap_stream_ch_chain_voting_pkt_t, l_voting_pkt_size );
    l_voting_pkt->hdr.data_size = a_data_size;
    memcpy( &l_voting_pkt->hdr.data_hash, a_data_hash, sizeof(dap_chain_hash_fast_t));
    l_voting_pkt->hdr.pkt_type = DAP_STREAM_CH_CHAIN_VOTING_PKT_TYPE_TEST;
    l_voting_pkt->hdr.version = 1;
    l_voting_pkt->hdr.net_id.uint64 = a_net->pub.id.uint64;
    if (a_data_size && a_data) {
        memcpy( l_voting_pkt->data, a_data, a_data_size);
    }
    voting_pkt_addr_t * l_pkt_addr = DAP_NEW_Z(voting_pkt_addr_t);
    l_pkt_addr->node_addr.uint64 = 0;
    l_pkt_addr->voting_pkt = l_voting_pkt;
    pthread_rwlock_wrlock(&s_pkt_items->rwlock_out);
    s_pkt_items->pkts_out = dap_list_append(s_pkt_items->pkts_out, l_pkt_addr);
    pthread_rwlock_unlock(&s_pkt_items->rwlock_out);
    
    dap_stream_ch_chain_voting_pkt_broadcast(a_net, a_sendto_nodes);
}

static void s_callback_send_all_unsafe_on_worker(dap_worker_t *a_worker, void *a_arg)
{
    UNUSED(a_worker);
    s_callback_send_all_unsafe((dap_client_t *)a_arg, NULL);
}

void dap_stream_ch_chain_voting_pkt_broadcast(dap_chain_net_t *a_net, dap_list_t *a_sendto_nodes)
{
    bool l_send_loop = false;
    dap_list_t *l_nodes_list_temp = dap_list_first(a_sendto_nodes);
    while(l_nodes_list_temp) {
        dap_list_t *l_nodes_list = l_nodes_list_temp;
        l_nodes_list_temp = l_nodes_list_temp->next;
        dap_chain_node_addr_t *l_remote_node_addr = (dap_chain_node_addr_t *)l_nodes_list->data;

        voting_node_client_list_t *l_node_item = NULL;
        if ( l_remote_node_addr->uint64 != dap_chain_net_get_cur_addr_int(a_net) ) {
            HASH_FIND(hh, s_node_client_list, l_remote_node_addr, sizeof(dap_chain_node_addr_t), l_node_item);
            if (l_node_item) {
                dap_chain_node_client_t *l_usable = dap_chain_node_client_find(l_node_item->uuid);
                if (l_usable && !dap_client_get_stream(l_usable->client)) {
                        dap_chain_node_client_close(l_node_item->uuid);
                        l_usable = NULL;
                }
                if (!l_usable) {
                    char l_channels[] = {dap_stream_ch_chain_voting_get_id(),0};
                    l_node_item->node_client = dap_chain_node_client_connect_channels(a_net, l_node_item->node_info, l_channels);
                    l_node_item->uuid = l_node_item->node_client->uuid;
                }
            } else {
                size_t node_info_size = 0;
                char *l_key = dap_chain_node_addr_to_hash_str(l_remote_node_addr);
                dap_chain_node_info_t *l_node_info =
                        (dap_chain_node_info_t *)dap_chain_global_db_gr_get(l_key,
                                                        &node_info_size, a_net->pub.gdb_nodes);
                DAP_DELETE(l_key);
                if (!l_node_info) {
                    continue;
                }
                char l_channels[] = {dap_stream_ch_chain_voting_get_id(),0};
                dap_chain_node_client_t *l_node_client = dap_chain_node_client_connect_channels(a_net, l_node_info, l_channels);
                if (!l_node_client) {
                    continue;
                }
                voting_node_client_list_t *l_node_client_item = DAP_NEW_Z(voting_node_client_list_t);
                l_node_client_item->node_addr = *l_remote_node_addr;
                l_node_client_item->node_info = l_node_info;
                l_node_client_item->node_client = l_node_client;
                l_node_client_item->uuid = l_node_client->uuid;
                HASH_ADD(hh, s_node_client_list, node_addr, sizeof(dap_chain_node_addr_t), l_node_client_item);
                l_node_item = l_node_client_item;
            }
            if ( !l_node_item || !l_node_item->node_client ) {
                continue;
            }
            dap_client_pvt_t * l_client_pvt = dap_client_pvt_find(l_node_item->node_client->client->pvt_uuid);
            if (NULL == l_client_pvt) {
                continue;
            }
            pthread_rwlock_wrlock(&s_pkt_items->rwlock_out);
            dap_list_t* l_pkts_list_temp = s_pkt_items->pkts_out;
            while(l_pkts_list_temp) {
                dap_list_t *l_pkts_list = l_pkts_list_temp;
                l_pkts_list_temp = l_pkts_list_temp->next;
                voting_pkt_addr_t * l_pkt_addr = (voting_pkt_addr_t *)l_pkts_list->data;
                if (!l_pkt_addr->node_addr.uint64) {
                    voting_pkt_addr_t * l_pkt_addr_new = DAP_NEW(voting_pkt_addr_t);
                    l_pkt_addr_new->node_addr.uint64 = l_remote_node_addr->uint64;
                    l_pkt_addr_new->voting_pkt = DAP_DUP_SIZE(l_pkt_addr->voting_pkt,
                                                            l_pkt_addr->voting_pkt->hdr.data_size+sizeof(dap_stream_ch_chain_voting_pkt_hdr_t));
                    l_pkt_addr_new->voting_pkt->hdr.sender_node_addr.uint64 = dap_chain_net_get_cur_addr_int(a_net);
                    l_pkt_addr_new->voting_pkt->hdr.recipient_node_addr.uint64 = l_remote_node_addr->uint64;
                    s_pkt_items->pkts_out = dap_list_append(s_pkt_items->pkts_out, l_pkt_addr_new);
                }
            }
            pthread_rwlock_unlock(&s_pkt_items->rwlock_out);

            if (dap_client_get_stage(l_node_item->node_client->client) != STAGE_STREAM_STREAMING)
                dap_client_go_stage(l_node_item->node_client->client, STAGE_STREAM_STREAMING, s_callback_send_all_unsafe);
            else {
                dap_stream_t *l_stream = dap_client_get_stream(l_node_item->node_client->client);
                dap_worker_exec_callback_on(l_stream->stream_worker->worker, s_callback_send_all_unsafe_on_worker,
                                            l_node_item->node_client->client);
            }
        } else
            l_send_loop = true;
    }
    s_callback_send_all_loopback(l_send_loop ? dap_chain_net_get_cur_addr_int(a_net) : 0);
}

static void s_callback_send_all_loopback(uint64_t a_node_addr)
{
    pthread_rwlock_wrlock(&s_pkt_items->rwlock_out);
    dap_list_t* l_pkts_list = s_pkt_items->pkts_out;
    while (l_pkts_list) {
		dap_list_t *l_pkts_list_next = l_pkts_list->next;
		voting_pkt_addr_t *l_pkt_addr = (voting_pkt_addr_t *)l_pkts_list->data;
        if (l_pkt_addr->node_addr.uint64 == 0) {
            if (a_node_addr) {
                l_pkt_addr->voting_pkt->hdr.sender_node_addr.uint64 =
                l_pkt_addr->voting_pkt->hdr.recipient_node_addr.uint64 =
                            a_node_addr;
                pthread_rwlock_wrlock(&s_pkt_items->rwlock_in);
                s_pkt_items->pkts_in = dap_list_append(s_pkt_items->pkts_in, l_pkt_addr->voting_pkt);
                pthread_rwlock_unlock(&s_pkt_items->rwlock_in);
            } else
                DAP_DELETE(l_pkt_addr->voting_pkt);
            DAP_DELETE(l_pkt_addr);
            s_pkt_items->pkts_out = dap_list_delete_link(s_pkt_items->pkts_out, l_pkts_list);
        }
        l_pkts_list = l_pkts_list_next;
    }
    pthread_rwlock_unlock(&s_pkt_items->rwlock_out);
}

static void s_callback_send_all_unsafe(dap_client_t *a_client, void *a_arg)
{
	UNUSED(a_arg);
    pthread_rwlock_wrlock(&s_pkt_items->rwlock_out);
    dap_chain_node_client_t *l_node_client = DAP_CHAIN_NODE_CLIENT(a_client);
    if (l_node_client) {
        dap_stream_ch_t * l_ch = dap_client_get_stream_ch_unsafe(a_client, dap_stream_ch_chain_voting_get_id() );
        if (l_ch) {
            dap_list_t* l_pkts_list = s_pkt_items->pkts_out;
			while(l_pkts_list) {
				dap_list_t *l_pkts_list_next = l_pkts_list->next;
				voting_pkt_addr_t *l_pkt_addr = (voting_pkt_addr_t *)l_pkts_list->data;
				dap_stream_ch_chain_voting_pkt_t * l_voting_pkt = l_pkt_addr->voting_pkt;
			    size_t l_voting_pkt_size = sizeof(l_voting_pkt->hdr) + l_voting_pkt->hdr.data_size;
				if ( l_pkt_addr->node_addr.uint64 == l_node_client->remote_node_addr.uint64 ) {
                    if (l_ch) {
                        dap_stream_ch_pkt_write_unsafe(l_ch,
			    						l_voting_pkt->hdr.pkt_type, l_voting_pkt, l_voting_pkt_size);
                        log_it(L_DEBUG, "Sent pkt size %zu to addr "NODE_ADDR_FP_STR, l_voting_pkt_size,
                                                                    NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr));
			    	}
                    DAP_DELETE(l_voting_pkt);
                    DAP_DELETE(l_pkt_addr);
                    s_pkt_items->pkts_out = dap_list_delete_link(s_pkt_items->pkts_out, l_pkts_list);
                }
		    	l_pkts_list = l_pkts_list_next;
		    }
	    }
	}
    pthread_rwlock_unlock(&s_pkt_items->rwlock_out);
}


void dap_stream_ch_chain_voting_deinit() {
	voting_node_client_list_t *l_node_info_item=NULL, *l_node_info_tmp=NULL;
    HASH_ITER(hh, s_node_client_list, l_node_info_item, l_node_info_tmp) {
        // Clang bug at this, l_node_info_item should change at every loop cycle
        HASH_DEL(s_node_client_list, l_node_info_item);
        DAP_DELETE(l_node_info_item->node_client);
        DAP_DELETE(l_node_info_item);
    }
}

static void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg) {
    UNUSED(a_arg);
    a_ch->internal = DAP_NEW_Z(dap_stream_ch_chain_voting_t);
    dap_stream_ch_chain_voting_t * l_ch_chain_voting = DAP_STREAM_CH_CHAIN_VOTING(a_ch);
    l_ch_chain_voting->ch = a_ch;
}

static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg) {
    a_ch->internal = NULL; // To prevent its cleaning in worker
}

static bool s_packet_in_callback_handler(void *a_arg)
{
    UNUSED(a_arg);
    pthread_rwlock_wrlock(&s_pkt_items->rwlock_in);
    if (s_pkt_items->pkts_in) {
		dap_list_t* l_list_pkts = dap_list_copy(s_pkt_items->pkts_in);
	    dap_list_free(s_pkt_items->pkts_in);
	    s_pkt_items->pkts_in = NULL;
        pthread_rwlock_unlock(&s_pkt_items->rwlock_in);
        while(l_list_pkts) {
            dap_stream_ch_chain_voting_pkt_t * l_voting_pkt = (dap_stream_ch_chain_voting_pkt_t *)l_list_pkts->data;
            for (size_t i=0; i<s_pkt_in_callback_count; i++) {
				voting_pkt_in_callback_t * l_callback = s_pkt_in_callback+i;
				if (l_callback->packet_in_callback) {
                    l_callback->packet_in_callback(l_callback->arg, &l_voting_pkt->hdr.sender_node_addr,
                                        &l_voting_pkt->hdr.data_hash, l_voting_pkt->data, l_voting_pkt->hdr.data_size);
				}
			}
			DAP_DELETE(l_voting_pkt);
            l_list_pkts = l_list_pkts->next;
		}
		dap_list_free(l_list_pkts);
    } else {
        pthread_rwlock_unlock(&s_pkt_items->rwlock_in);
    }
	return true;
}


static void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg) {
	dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
    if (!l_ch_pkt)
        return;
    pthread_rwlock_wrlock(&s_pkt_items->rwlock_in);
    size_t l_voting_pkt_size = l_ch_pkt->hdr.size;
    if (!l_voting_pkt_size || l_voting_pkt_size > UINT16_MAX) {
        return;
    }
    dap_stream_ch_chain_voting_pkt_t *l_voting_pkt = DAP_DUP_SIZE(&l_ch_pkt->data, l_voting_pkt_size);
	s_pkt_items->pkts_in = dap_list_append(s_pkt_items->pkts_in, l_voting_pkt);
	pthread_rwlock_unlock(&s_pkt_items->rwlock_in);
}

static void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg) {
	UNUSED(a_arg);
}


size_t dap_stream_ch_chain_voting_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                            const void * a_data, size_t a_data_size)
{
    dap_stream_ch_chain_voting_pkt_t * l_chain_pkt;
    size_t l_chain_pkt_size = sizeof (l_chain_pkt->hdr) + a_data_size;
    l_chain_pkt = DAP_NEW_Z_SIZE(dap_stream_ch_chain_voting_pkt_t, l_chain_pkt_size );
    l_chain_pkt->hdr.data_size = a_data_size;
    l_chain_pkt->hdr.pkt_type = a_type;
    l_chain_pkt->hdr.version = 1;
    l_chain_pkt->hdr.net_id.uint64 = a_net_id;

    if (a_data_size && a_data)
        memcpy( &l_chain_pkt->data, a_data, a_data_size);

    size_t l_ret  = dap_stream_ch_pkt_write_unsafe(a_ch, a_type , l_chain_pkt, l_chain_pkt_size);
    DAP_DELETE(l_chain_pkt);
    return l_ret;
}
