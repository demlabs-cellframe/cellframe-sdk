/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"

#include "dap_events_socket.h"
#include "dap_http_client.h"

#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"

#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_client.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_vpn_cdb.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_chain_net_vpn_client.h"
#include "dap_chain_net_vpn_client_tun.h"
#include "dap_chain_ledger.h"
#include "dap_events.h"

#define LOG_TAG "dap_chain_net_srv_vpn"

#define SF_MAX_EVENTS 256

typedef struct usage_client {
    pthread_rwlock_t rwlock;
    dap_chain_net_srv_ch_vpn_t * ch_vpn;
    dap_chain_net_srv_client_t *net_srv_client;
    dap_chain_datum_tx_receipt_t * receipt;
    size_t receipt_size;
    uint32_t usage_id;
    dap_chain_net_srv_t * srv;
    UT_hash_handle hh;
} usage_client_t;


typedef struct vpn_local_network {
    struct in_addr ipv4_lease_last;
    struct in_addr ipv4_network_mask;
    struct in_addr ipv4_host;
    struct in_addr ipv4_network_addr;
    int tun_ctl_fd;
    int tun_fd;
    struct ifreq ifr;

#ifdef DAP_TUN_IN_WORKER
    dap_events_socket_t * tun_events_socket;
#endif
    ch_vpn_pkt_t * pkt_out[400];
    size_t pkt_out_size;
    size_t pkt_out_rindex;
    size_t pkt_out_windex;
    pthread_mutex_t pkt_out_mutex;

} vpn_local_network_t;

static usage_client_t * s_clients;
static dap_chain_net_srv_ch_vpn_t * s_ch_vpn_addrs ;
static pthread_rwlock_t s_clients_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static ch_vpn_socket_proxy_t * sf_socks = NULL;
static ch_vpn_socket_proxy_t * sf_socks_client = NULL;
static pthread_mutex_t s_sf_socks_mutex;
static pthread_cond_t s_sf_socks_cond;
static int sf_socks_epoll_fd;
static pthread_t srv_sf_socks_pid;
static pthread_t srv_sf_socks_raw_pid;
static vpn_local_network_t *s_raw_server;
static pthread_rwlock_t s_raw_server_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static const char *s_addr;

// Service callbacks
static int s_callback_requested(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size );
static int s_callback_response_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size );
static int s_callback_response_error(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size );

static int s_callback_receipt_next_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client,
                    const void * a_receipt_next, size_t a_receipt_next_size);


// Tunnel threads
static void *srv_ch_sf_thread(void * a_arg);
static void *srv_ch_sf_thread_raw(void *arg);
static void s_tun_create(void);
static void s_tun_destroy(void);


// Stream callbacks
static void s_new(dap_stream_ch_t* ch, void* arg);
static void srv_ch_vpn_delete(dap_stream_ch_t* ch, void* arg);
static void s_ch_packet_in(dap_stream_ch_t* ch, void* a_arg);
static void s_ch_packet_out(dap_stream_ch_t* ch, void* arg);

//static int srv_ch_sf_raw_write(uint8_t op_code, const void * data, size_t data_size);
//static void srv_stream_sf_disconnect(ch_vpn_socket_proxy_t * sf_sock);

static char *s_srv_vpn_addr = NULL, *s_srv_vpn_mask = NULL;

static void s_update_limits(dap_stream_ch_t * a_ch ,
                           dap_chain_net_srv_stream_session_t * a_srv_session,
                           dap_chain_net_srv_usage_t * a_usage, size_t a_bytes);

#ifdef DAP_TUN_IN_WORKER
static void m_es_tun_delete(dap_events_socket_t * a_es, void * arg);
static void m_es_tun_read(dap_events_socket_t * a_es, void * arg);
static void m_es_tun_error(dap_events_socket_t * a_es, void * arg);

bool is_dap_tun_in_worker(void)
{
#ifdef DAP_TUN_IN_WORKER
    return true;
#else
    return false;
#endif
}

static void s_es_tun_new(dap_events_socket_t * a_es, void * arg);
static void s_es_tun_delete(dap_events_socket_t * a_es, void * arg);
static void s_es_tun_read(dap_events_socket_t * a_es, void * arg);
static void s_es_tun_error(dap_events_socket_t * a_es, void * arg);

pthread_rwlock_t s_tun_sockets_rwlock = PTHREAD_RWLOCK_INITIALIZER;
ch_sf_tun_socket_t * s_tun_sockets = NULL;

//TODO: create .new_callback for event sockets
int s_tun_event_stream_create()
{
  static dap_events_socket_callbacks_t l_s_callbacks = {
          .read_callback = m_es_tun_read,// for server
          .write_callback = NULL,// for client
          .error_callback = m_es_tun_error,
          .delete_callback = m_es_tun_delete
  };

  s_raw_server->tun_events_socket = dap_events_socket_wrap_no_add(NULL,
                                                                  s_raw_server->tun_fd, &l_s_callbacks);
  s_raw_server->tun_events_socket->type = DESCRIPTOR_TYPE_FILE;
  dap_events_socket_create_after(s_raw_server->tun_events_socket);
  s_raw_server->tun_events_socket->_inheritor = s_raw_server;

  return 0;
}
#endif

static int s_callback_client_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client,
                    const void * a_success, size_t a_success_size)
{
    if(!a_srv || !a_srv_client || !a_srv_client->ch || !a_success || a_success_size < sizeof(dap_stream_ch_chain_net_srv_pkt_success_t))
        return -1;
    dap_stream_ch_chain_net_srv_pkt_success_t * l_success = (dap_stream_ch_chain_net_srv_pkt_success_t*) a_success;

    dap_chain_net_srv_stream_session_t * l_srv_session =
            (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_vpn_t* l_srv_vpn = (dap_chain_net_srv_vpn_t*) a_srv->_inhertor;
    //a_srv_client->ch->
    dap_chain_net_t * l_net = dap_chain_net_by_id(l_success->hdr.net_id);
    dap_chain_net_srv_usage_t *l_usage = dap_chain_net_srv_usage_add(l_srv_session, l_net, a_srv);
    if(!l_usage)
        return -2;

    dap_chain_net_srv_ch_vpn_t * l_srv_ch_vpn =
            (dap_chain_net_srv_ch_vpn_t*) a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID] ?
                    a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID]->internal : NULL;
    if ( ! l_srv_ch_vpn ){
        log_it(L_ERROR, "No VPN service stream channel, its closed?");
        return -3;
    }
    l_srv_ch_vpn->usage_id = l_usage->id;
    l_usage->is_active = true;
    l_usage->is_free = true;

    dap_stream_ch_t *l_ch = dap_chain_net_vpn_client_get_stream_ch();

    int remote_sock_id = 0;//l_vpn_pkt->header.sock_id;
    ch_vpn_socket_proxy_t * sf_sock = NULL;
    sf_sock = DAP_NEW_Z(ch_vpn_socket_proxy_t);
    sf_sock->id = remote_sock_id;
    sf_sock->sock = l_ch->stream->esocket->socket;
    sf_sock->ch = l_ch;
    pthread_mutex_init(&sf_sock->mutex, NULL);
    dap_chain_net_srv_ch_vpn_t *f = CH_VPN(a_srv_client->ch);
    //pthread_mutex_lock(&s_sf_socks_mutex);
    pthread_mutex_lock(&l_srv_ch_vpn->mutex);
    HASH_ADD_INT(l_srv_ch_vpn->socks, id, sf_sock);
    pthread_mutex_unlock(&l_srv_ch_vpn->mutex);
    //HASH_ADD_INT(CH_VPN(a_srv_client->ch)->socks, id, sf_sock);
    log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id, sf_sock->sock);

    //!!!//l_usage->receipt = ;

    /*
     dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION( a_ch->stream->session );
     dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(a_ch);
     dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find(l_srv_session,  l_ch_vpn->usage_id);
     if ( ! l_usage->is_active
     */

    if(l_ch) { // Is present in hash table such destination address
        size_t l_ipv4_str_len = 0; //dap_strlen(a_ipv4_str);
        ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + l_ipv4_str_len);

        pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST;
        //pkt_out->header.sock_id = l_stream->stream->events_socket->socket;
        //pkt_out->header.op_connect.addr_size = l_ipv4_str_len; //remoteAddrBA.length();
        //pkt_out->header.op_connect.port = a_port;
        //memcpy(pkt_out->data, a_ipv4_str, l_ipv4_str_len);
        sf_sock->pkt_out[sf_sock->pkt_out_size] = pkt_out;
        sf_sock->pkt_out_size++;

        dap_stream_ch_pkt_write(l_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
        dap_stream_ch_set_ready_to_write(l_ch, true);
        //DAP_DELETE(pkt_out);
    }




    // usage is present, we've accepted packets
    dap_stream_ch_set_ready_to_read( l_srv_ch_vpn->ch , true );
    return 0;
}

static int callback_client_sign_request(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client,
                    const void **a_receipt, size_t a_receipt_size)
{
    dap_chain_datum_tx_receipt_t *l_receipt = (dap_chain_datum_tx_receipt_t*)*a_receipt;
    char *l_gdb_group = dap_strdup_printf("local.%s", DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX);
    char *l_wallet_name = dap_chain_global_db_gr_get(dap_strdup("wallet_name"), NULL, l_gdb_group);

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, dap_chain_wallet_get_path(g_config));
    if(l_wallet) {
        dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
        dap_chain_datum_tx_receipt_sign_add(&l_receipt, dap_chain_datum_tx_receipt_get_size(l_receipt), l_enc_key);
        dap_chain_wallet_close(l_wallet);
        *a_receipt = l_receipt;
    }
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_wallet_name);
    return 0;
}


/*
 * Client VPN init (after dap_chain_net_srv_vpn_init!)
 */
int dap_chain_net_srv_client_vpn_init(dap_config_t * l_config) {
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    dap_chain_net_srv_t *l_srv = dap_chain_net_srv_get(l_uid);
    dap_chain_net_srv_vpn_t* l_srv_vpn = l_srv ? (dap_chain_net_srv_vpn_t*) l_srv->_inhertor : NULL;
    // if vpn server disabled
    if(!l_srv_vpn) {
        l_srv_vpn = DAP_NEW_Z(dap_chain_net_srv_vpn_t);
        if(l_srv)
            l_srv->_inhertor = l_srv_vpn;
        dap_stream_ch_proc_add(DAP_STREAM_CH_ID_NET_SRV_VPN, s_new, srv_ch_vpn_delete, s_ch_packet_in, s_ch_packet_out);
        pthread_mutex_init(&s_sf_socks_mutex, NULL);
        pthread_cond_init(&s_sf_socks_cond, NULL);
    }
    if(!dap_chain_net_srv_client_init(l_uid, s_callback_requested,
            s_callback_response_success, s_callback_response_error,
            s_callback_receipt_next_success,
            s_callback_client_success,
            callback_client_sign_request,
            l_srv_vpn)) {
        l_srv = dap_chain_net_srv_get(l_uid);
        //l_srv_vpn = l_srv ? (dap_chain_net_srv_vpn_t*)l_srv->_inhertor : NULL;
        //l_srv_vpn->parent = l_srv;
        l_srv->_inhertor = l_srv_vpn;
    }
    l_srv_vpn->parent = (dap_chain_net_srv_t*) l_srv;

    return 0;
}


ch_sf_tun_server_t * m_tun_server = NULL;

int s_tun_attach_queue(int fd)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_ATTACH_QUEUE;
    return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
}

int s_tun_deattach_queue(int fd)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_DETACH_QUEUE;
    return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
}


/**
 * @brief s_tun_es_create
 * @param a_worker
 * @return
 */
dap_events_socket_t * s_tun_es_create(dap_worker_t * a_worker, int a_tun_fd)
{
    assert(a_worker);
    static dap_events_socket_callbacks_t l_s_callbacks = {{ 0 }};
    l_s_callbacks.new_callback = s_es_tun_new;
    l_s_callbacks.read_callback = s_es_tun_read;
    l_s_callbacks.error_callback = s_es_tun_error;
    l_s_callbacks.delete_callback = s_es_tun_delete;

    s_tun_deattach_queue(a_tun_fd);

    dap_events_socket_t * l_es = dap_events_socket_wrap_no_add(a_worker->events ,
                                          a_tun_fd, &l_s_callbacks);
    l_es->type = DESCRIPTOR_TYPE_FILE;
    dap_events_socket_assign_on_worker_mt(l_es, a_worker);

    return l_es;
}

int s_vpn_tun_create(dap_config_t * g_config)
{
    const char *c_addr = dap_config_get_item_str(g_config, "srv_vpn", "network_address");
    const char *c_mask = dap_config_get_item_str(g_config, "srv_vpn", "network_mask");
    if(!c_addr || !c_mask){
        log_it(L_ERROR, "%s: error while reading network parameters from config (network_address and network_mask)", __PRETTY_FUNCTION__);
        DAP_DELETE((void*)c_addr);
        DAP_DELETE((void*)c_mask);
        return -1;
    }

    inet_aton(c_addr, &m_tun_server->int_network );
    inet_aton(c_mask, &m_tun_server->int_network_mask );
    m_tun_server->int_network_addr.s_addr= (m_tun_server->int_network.s_addr | 0x01000000); // grow up some shit here!
    m_tun_server->client_addr_last.s_addr = m_tun_server->int_network_addr.s_addr;

    memset(&m_tun_server->ifr, 0, sizeof(m_tun_server->ifr));
    m_tun_server->ifr.ifr_flags = IFF_TUN | IFF_MULTI_QUEUE| IFF_NO_PI;

    uint32_t l_cpu_count = dap_get_cpu_count(); // maybe replace with getting s_threads_count directly
    log_it(L_NOTICE,"%s: trying to initialize multiqueue for %u workers", __PRETTY_FUNCTION__, l_cpu_count);

    int err = -1;
    for( uint8_t i =0; i< l_cpu_count; i++){
        dap_worker_t * l_worker = dap_events_worker_get(i);
        assert( l_worker );
        int l_tun_fd;
        if( (l_tun_fd = open("/dev/net/tun", O_RDWR| O_NONBLOCK)) < 0 ) {
            log_it(L_ERROR,"Opening /dev/net/tun error: '%s'", strerror(errno));
            err = -100;
            break;
        }
        log_it(L_DEBUG,"Opening /dev/net/tun:%u", i);
        if( (err = ioctl(l_tun_fd, TUNSETIFF, (void *)& m_tun_server->ifr)) < 0 ) {
            log_it(L_CRITICAL, "ioctl(TUNSETIFF) error: '%s' ",strerror(errno));
            close(l_tun_fd);
            break;
        }
        s_tun_deattach_queue(l_tun_fd);
        s_tun_es_create(l_worker, l_tun_fd);
    }

    if (! err ){
        char buf[256];
        log_it(L_NOTICE,"Bringed up %s virtual network interface (%s/%s)", m_tun_server->ifr.ifr_name,inet_ntoa(m_tun_server->int_network_addr),c_mask);
        snprintf(buf,sizeof(buf),"ip link set %s up",m_tun_server->ifr.ifr_name);
        system(buf);
        snprintf(buf,sizeof(buf),"ip addr add %s/%s dev %s ",inet_ntoa(m_tun_server->int_network_addr),c_mask, m_tun_server->ifr.ifr_name );
        system(buf);
    }

    return err;
}

/**
* @brief ch_sf_tun_init
* @return
*/
int s_vpn_tun_init()
{
    m_tun_server=DAP_NEW_Z(ch_sf_tun_server_t);
    pthread_rwlock_init(&m_tun_server->rwlock, NULL);

    pthread_mutex_init(&m_tun_server->external_route_operations,NULL);
    pthread_mutex_init(&m_tun_server->pkt_out_mutex,NULL);

    return 0;
}

int dap_chain_net_srv_vpn_init(dap_config_t * g_config) {
    s_vpn_tun_init();

    log_it(L_DEBUG,"Initializing TUN driver...");
    s_vpn_tun_create(g_config);
    log_it(L_INFO,"TUN driver configured successfuly");

    //TODO: initialize dap_chain_net_srv_vpn_t* here,
    //take it from previous version of dap_chain_net_srv_vpn_init() (below)
    return 0;
}

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
/*
int dap_chain_net_srv_vpn_init(dap_config_t * g_config) {
    const char *c_addr = dap_config_get_item_str(g_config, "srv_vpn", "network_address");
    const char *c_mask = dap_config_get_item_str(g_config, "srv_vpn", "network_mask");
    if(c_addr && c_mask) {
        s_srv_vpn_addr = strdup(c_addr);
        s_srv_vpn_mask = strdup(c_mask);

        s_raw_server = DAP_NEW_Z(vpn_local_network_t);
        pthread_mutex_init(&s_raw_server->pkt_out_mutex, NULL);
        pthread_mutex_init(&s_sf_socks_mutex, NULL);
        pthread_cond_init(&s_sf_socks_cond, NULL);

#ifdef DAP_TUN_IN_WORKER
        s_tun_create();

        if(s_raw_server->tun_fd == -1){
          log_it(L_CRITICAL,"Error creating file descriptor for /dev/net/tun device");
          return -2;
        }

        s_tun_event_stream_create();
#else
        pthread_create(&srv_sf_socks_raw_pid, NULL, srv_ch_sf_thread_raw, NULL);
#endif

        pthread_create(&srv_sf_socks_pid, NULL, srv_ch_sf_thread, NULL);
        dap_stream_ch_proc_add(DAP_STREAM_CH_ID_NET_SRV_VPN, s_new, srv_ch_vpn_delete, s_ch_packet_in,
                s_ch_packet_out);

        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
        dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add( l_uid, s_callback_requested,
                                                            s_callback_response_success, s_callback_response_error,
                                                            s_callback_receipt_next_success);
        dap_chain_net_srv_vpn_t* l_srv_vpn  = DAP_NEW_Z( dap_chain_net_srv_vpn_t);
        l_srv->_inhertor = l_srv_vpn;
        l_srv_vpn->parent = l_srv;

        uint16_t l_pricelist_count = 0;

        //! IMPORTANT ! This fetch is single-action and cannot be further reused, since it modifies the stored config data
        //! it also must NOT be freed within this module !
        char **l_pricelist = dap_config_get_array_str(g_config, "srv_vpn", "pricelist", &l_pricelist_count); // must not be freed!
        for (uint16_t i = 0; i < l_pricelist_count; i++) {
            dap_chain_net_srv_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_price_t);
            short l_iter = 0;
            char *l_ctx;
            for (char *l_price_token = strtok_r(l_pricelist[i], ":", &l_ctx); l_price_token || l_iter == 6; l_price_token = strtok_r(NULL, ":", &l_ctx), ++l_iter) {
                //log_it(L_DEBUG, "Tokenizer: %s", l_price_token);
                switch (l_iter) {
                case 0:
                    l_price->net_name = l_price_token;
                    if (!(l_price->net = dap_chain_net_by_name(l_price->net_name))) {
                        log_it(L_ERROR, "Error parsing pricelist: can't find network \"%s\"", l_price_token);
                        DAP_DELETE(l_price);
                        break;
                    }
                    continue;
                case 1:
                    l_price->value_coins = atof(l_price_token);
                    if (!(l_price->value_datoshi = (uint64_t)dap_chain_coins_to_balance((long double)l_price->value_coins))) {
                        log_it(L_ERROR, "Error parsing pricelist: text on 2nd position \"%s\" is not floating number", l_price_token);
                        l_iter = 0;
                        DAP_DELETE(l_price);
                        break;
                    }
                    continue;
                case 2:
                    dap_stpcpy(l_price->token, l_price_token);
                    continue;
                case 3:
                    l_price->units = strtoul(l_price_token, NULL, 10);
                    if (!l_price->units) {
                        log_it(L_ERROR, "Error parsing pricelist: text on 4th position \"%s\" is not unsigned integer", l_price_token);
                        l_iter = 0;
                        DAP_DELETE(l_price);
                        break;
                    }
                    continue;
                case 4:
                    if (!strcmp(l_price_token,      "SEC"))
                        l_price->units_uid.enm = SERV_UNIT_SEC;
                    else if (!strcmp(l_price_token, "DAY"))
                        l_price->units_uid.enm = SERV_UNIT_DAY;
                    else if (!strcmp(l_price_token, "MB"))
                        l_price->units_uid.enm = SERV_UNIT_MB;
                    else {
                        log_it(L_ERROR, "Error parsing pricelist: wrong unit type \"%s\"", l_price_token);
                        l_iter = 0;
                        DAP_DELETE(l_price);
                        break;
                    }
                    continue;
                case 5:
                    if (!(l_price->wallet = dap_chain_wallet_open(l_price_token, dap_config_get_item_str_default(g_config, "resources", "wallets_path", NULL)))) {
                        log_it(L_ERROR, "Error parsing pricelist: can't open wallet \"%s\"", l_price_token);
                        l_iter = 0;
                        DAP_DELETE(l_price);
                        break;
                    }
                    continue;
                case 6:
                    log_it(L_INFO, "Price item correct, added to service");
                    DL_APPEND(l_srv->pricelist, l_price);
                    break;
                default:
                    break;
                }
                log_it(L_DEBUG, "Done with price item %d", i);
                break; // double break exits tokenizer loop and steps to next price item
            }
        }

        return 0;
        //int retVal = dap_chain_net_srv_vpn_cmd_init();
        //return retVal;
    }
    return -1;
}
*/

/**
 * @brief ch_sf_deinit
 */
void dap_chain_net_srv_vpn_deinit(void)
{
    pthread_mutex_destroy(&s_sf_socks_mutex);
    pthread_cond_destroy(&s_sf_socks_cond);
    DAP_DELETE(s_srv_vpn_addr);
    DAP_DELETE(s_srv_vpn_mask);
    if(s_raw_server)
        DAP_DELETE(s_raw_server);
}

/**
 * Callback calls after successful request for service
 */
static int s_callback_requested(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size )
{

    // TODO parse custom data like JSON or smth like this
    (void) a_custom_data;
    (void) a_custom_data_size;
    (void) a_srv;
    return 0; // aways allow to use it for now
}

/**
 * Called if responses success with all signature checks
 */
static int s_callback_response_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client
                                    , const void * a_request, size_t a_request_size )
{
    int l_ret = 0;
    const dap_chain_datum_tx_receipt_t * l_receipt = (const dap_chain_datum_tx_receipt_t *) a_request;
    size_t l_receipt_size = a_request_size;


//    dap_stream_ch_chain_net_srv_pkt_request_t * l_request =  (dap_stream_ch_chain_net_srv_pkt_request_t *) a_request;
//    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_usage_t * l_usage_active= dap_chain_net_srv_usage_find(l_srv_session,a_usage_id);
    dap_chain_net_srv_ch_vpn_t * l_srv_ch_vpn =(dap_chain_net_srv_ch_vpn_t*) a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID] ?
            a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID]->internal : NULL;

    if ( !l_usage_active){
        log_it( L_ERROR, "No active service usage, can't success");
        return -1;
    }

    usage_client_t * l_usage_client = NULL;

    l_usage_client = DAP_NEW_Z(usage_client_t);
    l_usage_client->usage_id = a_usage_id;
    l_usage_client->net_srv_client = a_srv_client;
    l_usage_client->receipt = DAP_NEW_SIZE(dap_chain_datum_tx_receipt_t,l_receipt_size);
    pthread_rwlock_init(&l_usage_client->rwlock,NULL);

    memcpy(l_usage_client->receipt, l_receipt, l_receipt_size);
    pthread_rwlock_wrlock(&s_clients_rwlock);
    HASH_ADD(hh, s_clients,usage_id,sizeof(a_usage_id),l_usage_client);

    l_srv_session->usage_active = l_usage_active;
    l_srv_session->usage_active->is_active = true;
    log_it(L_NOTICE,"Enable VPN service");

    if ( l_srv_ch_vpn ){ // If channel is already opened

        dap_stream_ch_set_ready_to_read( l_srv_ch_vpn->ch , true );

        l_srv_ch_vpn->usage_id = a_usage_id;
        // So complicated to update usage client to be sure that nothing breaks it
        l_usage_client->ch_vpn = l_srv_ch_vpn;
    } else{
        log_it(L_WARNING, "VPN channel is not open, will be no data transmission");
        l_ret = -2;
    }
    pthread_rwlock_unlock(&s_clients_rwlock);
    return l_ret;
}



static int s_callback_receipt_next_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client,
                    const void * a_receipt_next, size_t a_receipt_next_size)
{
    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_ch_vpn_t * l_srv_ch_vpn =(dap_chain_net_srv_ch_vpn_t*) a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID] ?
            a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID]->internal : NULL;

    if ( ! l_srv_ch_vpn ){
        log_it(L_ERROR, "No VPN service stream channel, its closed?");
        return -3;
    }

    const dap_chain_datum_tx_receipt_t * l_receipt_next = (const dap_chain_datum_tx_receipt_t *) a_receipt_next;
    size_t l_receipt_next_size = a_receipt_next_size;

    log_it(L_INFO, "Next receipt successfuly accepted");
    // usage is present, we've accepted packets
    dap_stream_ch_set_ready_to_read( l_srv_ch_vpn->ch , true );
    return 0;
}

/**
 * If error
 */
static int s_callback_response_error(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size )
{
    if (a_custom_data_size != sizeof (dap_stream_ch_chain_net_srv_pkt_error_t)){
        log_it(L_ERROR, "Wrong custom data size, must be %zd", sizeof(dap_stream_ch_chain_net_srv_pkt_error_t) );
        return -1;
    }
    dap_stream_ch_chain_net_srv_pkt_error_t * l_err = (dap_stream_ch_chain_net_srv_pkt_error_t *)a_custom_data;
    log_it(L_WARNING,"Response error code 0x%08X", l_err->code);
    return 0;
}


/**
 * @brief s_tun_create
 */
static void s_tun_create(void)
{
    pthread_rwlock_wrlock(& s_raw_server_rwlock);
    inet_aton(s_srv_vpn_addr, &s_raw_server->ipv4_network_addr);
    inet_aton(s_srv_vpn_mask, &s_raw_server->ipv4_network_mask);
    s_raw_server->ipv4_host.s_addr = (s_raw_server->ipv4_network_addr.s_addr | 0x01000000); // grow up some shit here!
    s_raw_server->ipv4_lease_last.s_addr = s_raw_server->ipv4_host.s_addr;

    if((s_raw_server->tun_ctl_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        log_it(L_ERROR, "Opening /dev/net/tun error: '%s'", strerror(errno));
    } else {
        int err;
        memset(&s_raw_server->ifr, 0, sizeof(s_raw_server->ifr));
        s_raw_server->ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if((err = ioctl(s_raw_server->tun_ctl_fd, TUNSETIFF, (void *) &s_raw_server->ifr)) < 0) {
            log_it(L_CRITICAL, "ioctl(TUNSETIFF) error: '%s' ", strerror(errno));
            close(s_raw_server->tun_ctl_fd);
            s_raw_server->tun_ctl_fd = -1;
            s_raw_server->tun_fd = -1;
        } else {
            char buf[256];
            log_it(L_NOTICE, "Bringed up %s virtual network interface (%s/%s)", s_raw_server->ifr.ifr_name,
                    inet_ntoa(s_raw_server->ipv4_host), s_srv_vpn_mask);
            s_raw_server->tun_fd = s_raw_server->tun_ctl_fd; // Looks yes, its so
            snprintf(buf, sizeof(buf), "ip link set %s up", s_raw_server->ifr.ifr_name);
            int res = system(buf);
            snprintf(buf, sizeof(buf), "ip addr add %s/%s dev %s ", inet_ntoa(s_raw_server->ipv4_host),
                    s_srv_vpn_mask,
                    s_raw_server->ifr.ifr_name);
            res = system(buf);
            res = 0;
        }
    }
    pthread_rwlock_unlock(& s_raw_server_rwlock);

}

/**
 * @brief s_tun_destroy
 */
static void s_tun_destroy(void)
{
    pthread_rwlock_wrlock(& s_raw_server_rwlock);
    dap_events_socket_remove_and_delete_mt(s_raw_server->tun_events_socket);
    close(s_raw_server->tun_fd);
    s_raw_server->tun_fd = -1;
    pthread_rwlock_unlock(& s_raw_server_rwlock);
}


/**
 * @brief ch_sf_socket_delete
 * @param sf
 */
static void ch_sf_socket_delete(ch_vpn_socket_proxy_t * a_vpn_socket_proxy)
{
    close(a_vpn_socket_proxy->sock);
    pthread_mutex_destroy(& (a_vpn_socket_proxy->mutex) );
    if (a_vpn_socket_proxy)
        DAP_DELETE(a_vpn_socket_proxy);
}


/**
 * @brief s_new Callback to constructor of object of Ch
 * @param ch
 * @param arg
 */
void s_new(dap_stream_ch_t* a_stream_ch, void* a_arg)
{
    (void) a_arg;

    a_stream_ch->internal = DAP_NEW_Z(dap_chain_net_srv_ch_vpn_t);
    dap_chain_net_srv_ch_vpn_t * l_srv_vpn = CH_VPN(a_stream_ch);

    if(a_stream_ch->stream->session->_inheritor == NULL && a_stream_ch->stream->session != NULL)
        dap_chain_net_srv_stream_session_create(a_stream_ch->stream->session);
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    l_srv_vpn->net_srv = dap_chain_net_srv_get(l_uid);
    l_srv_vpn->ch = a_stream_ch;

    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_stream_ch->stream->session->_inheritor;
    pthread_mutex_init(&l_srv_vpn->mutex, NULL);
    l_srv_vpn->raw_l3_sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

    l_srv_vpn->usage_id = l_srv_session->usage_active?  l_srv_session->usage_active->id : 0;

    if( l_srv_vpn->usage_id) {
        // So complicated to update usage client to be sure that nothing breaks it
        usage_client_t * l_usage_client = NULL;
        pthread_rwlock_rdlock(&s_clients_rwlock);
        HASH_FIND(hh,s_clients, &l_srv_vpn->usage_id,sizeof(l_srv_vpn->usage_id),l_usage_client );
        if (l_usage_client){
            pthread_rwlock_wrlock(&l_usage_client->rwlock);
            l_usage_client->ch_vpn = l_srv_vpn;
            pthread_rwlock_unlock(&l_usage_client->rwlock);
        }
        pthread_rwlock_unlock(&s_clients_rwlock);
    }

}

/**
 * @brief stream_sf_delete
 * @param ch
 * @param arg
 */
void srv_ch_vpn_delete(dap_stream_ch_t* ch, void* arg)
{
    log_it(L_DEBUG, "ch_sf_delete() for %s", ch->stream->esocket->hostaddr);
    dap_chain_net_srv_ch_vpn_t * l_ch_vpn = CH_VPN(ch);
    dap_chain_net_srv_vpn_t * l_srv_vpn =(dap_chain_net_srv_vpn_t *) l_ch_vpn->net_srv->_inhertor;
    pthread_mutex_lock(&(l_ch_vpn->mutex));
    // So complicated to update usage client to be sure that nothing breaks it
    usage_client_t * l_usage_client = NULL;

    bool l_is_unleased = false;
    if ( l_ch_vpn->addr_ipv4.s_addr ){ // if leased address
        pthread_rwlock_wrlock(& s_raw_server_rwlock);
        if ( s_raw_server->ipv4_lease_last.s_addr == l_ch_vpn->addr_ipv4.s_addr ){
            s_raw_server->ipv4_lease_last.s_addr = ntohl( ntohl(s_raw_server->ipv4_lease_last.s_addr)-1 );
        }
        else
            l_is_unleased = true;
        pthread_rwlock_unlock(& s_raw_server_rwlock);
    }
    pthread_rwlock_wrlock(&s_clients_rwlock);
    if(s_ch_vpn_addrs) {
        HASH_DEL(s_ch_vpn_addrs, l_ch_vpn);
    }

    if ( l_is_unleased ){ // If unleased
        log_it(L_DEBUG, "Unlease address %s and store in treshold", inet_ntoa(l_ch_vpn->addr_ipv4));
        dap_chain_net_srv_vpn_item_ipv4_t * l_item_unleased = DAP_NEW_Z(dap_chain_net_srv_vpn_item_ipv4_t);
        l_item_unleased->addr.s_addr = l_ch_vpn->addr_ipv4.s_addr;
        l_item_unleased->next = l_srv_vpn->ipv4_unleased;
        l_srv_vpn->ipv4_unleased = l_item_unleased;
    }

    HASH_FIND(hh,s_clients, &l_ch_vpn->usage_id,sizeof(l_ch_vpn->usage_id),l_usage_client );
    if (l_usage_client){
        pthread_rwlock_wrlock(&l_usage_client->rwlock);
        l_usage_client->ch_vpn = NULL; // NULL the channel, nobody uses that indicates
        pthread_rwlock_unlock(&l_usage_client->rwlock);
    }

    pthread_rwlock_unlock(&s_clients_rwlock);

    ch_vpn_socket_proxy_t * cur, *tmp;
    // in_addr_t raw_client_addr = CH_SF(ch)->tun_client_addr.s_addr;
    HASH_ITER(hh, l_ch_vpn->socks , cur, tmp)
    {
        log_it(L_DEBUG, "delete socket: %i", cur->sock);
        if(l_ch_vpn->socks){
            HASH_DEL(l_ch_vpn->socks, cur);
        }
        if(cur)
            free(cur);
    }

    if(l_ch_vpn->raw_l3_sock)
        close(l_ch_vpn->raw_l3_sock);
    l_ch_vpn->ch = NULL;
    l_ch_vpn->net_srv = NULL;
    l_ch_vpn->is_allowed =false;
    pthread_mutex_unlock(&(l_ch_vpn->mutex));
    pthread_mutex_destroy(& l_ch_vpn->mutex);
}

static void s_ch_proxy_delete(ch_vpn_socket_proxy_t * a_sock_proxy)
{
    if( !a_sock_proxy)
        return;

    if(a_sock_proxy->sock > 0)
        close(a_sock_proxy->sock);
    // wait while mutex will be released if it be locked
    pthread_mutex_lock(&a_sock_proxy->mutex);
    pthread_mutex_unlock(&a_sock_proxy->mutex);

    pthread_mutex_destroy(&(a_sock_proxy->mutex));
    DAP_DELETE(a_sock_proxy);
}

static ch_vpn_pkt_t* srv_ch_sf_raw_read()
{
    ch_vpn_pkt_t*ret = NULL;
    pthread_mutex_lock(&s_raw_server->pkt_out_mutex);
    if(s_raw_server->pkt_out_rindex == (sizeof(s_raw_server->pkt_out) / sizeof(s_raw_server->pkt_out[0]))) {
        s_raw_server->pkt_out_rindex = 0; // ring the buffer!
    }
    if((s_raw_server->pkt_out_rindex != s_raw_server->pkt_out_windex) || (s_raw_server->pkt_out_size == 0)) {
        ret = s_raw_server->pkt_out[s_raw_server->pkt_out_rindex];
        s_raw_server->pkt_out_rindex++;
        s_raw_server->pkt_out_size--;
    } //else
      //  log_it(L_WARNING, "Packet drop on raw_read() operation, ring buffer is full");
    pthread_mutex_unlock(&s_raw_server->pkt_out_mutex);
    return ret;
}

/**
 * @brief s_check_limits
 * @param a_ch
 * @param a_srv_session
 * @param a_usage
 * @param a_bytes
 */
static void s_update_limits(dap_stream_ch_t * a_ch ,
                           dap_chain_net_srv_stream_session_t * a_srv_session,
                           dap_chain_net_srv_usage_t * a_usage, size_t a_bytes)
{
    bool l_issue_new_receipt = false;
    // Check if there are time limits
    if( a_srv_session->limits_ts ){
        if( a_srv_session->limits_ts  < time(NULL) ){ // Limits out
            a_srv_session->limits_ts = 0;
            log_it(L_INFO, "Limits by timestamp are over. Switch to the next receipt");
            DAP_DELETE(a_usage->receipt);
            a_usage->receipt = a_usage->receipt_next;
            a_usage->receipt_next = NULL;
            l_issue_new_receipt = true;
            if ( a_usage->receipt){ // If there is next receipt add the time and request the next receipt
                a_srv_session->limits_units_type.uint32 = a_usage->receipt->receipt_info.units_type.uint32;
                switch( a_usage->receipt->receipt_info.units_type.enm){
                    case SERV_UNIT_DAY:{
                        a_srv_session->limits_ts = time(NULL) + (time_t)  a_usage->receipt->receipt_info.units*24*3600;
                        log_it(L_INFO,"%llu days more for VPN usage", a_usage->receipt->receipt_info.units);
                    } break;
                    case SERV_UNIT_SEC:{
                        a_srv_session->limits_ts = time(NULL) + (time_t)  a_usage->receipt->receipt_info.units;
                        log_it(L_INFO,"%llu seconds more for VPN usage", a_usage->receipt->receipt_info.units);
                    } break;
                    default: {
                        log_it(L_WARNING, "VPN doesnt accept serv unit type 0x%08X for limits_ts", a_usage->receipt->receipt_info.units_type.uint32 );
                        dap_stream_ch_set_ready_to_write(a_ch,false);
                        dap_stream_ch_set_ready_to_read(a_ch,false);
                        dap_stream_ch_pkt_write( a_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
                    }
                }

                //l_ch_vpn->limits_ts = time(NULL) + l_usage->receipt->receipt
            }else {
                log_it( L_NOTICE, "No activate receipt in usage, switch off write callback for channel");
                dap_stream_ch_set_ready_to_write(a_ch,false);
                dap_stream_ch_set_ready_to_read(a_ch,false);
                dap_stream_ch_pkt_write( a_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
            }
        }
    }else if ( a_srv_session->limits_bytes ){
        if ( a_srv_session->limits_bytes >(uint128_t) a_bytes ){
            // Update limits
            a_srv_session->limits_bytes -= (uint128_t) a_bytes;
        }else{ // traffic out
            log_it(L_INFO, "Limits by traffic is over. Switch to the next receipt");
            DAP_DELETE(a_usage->receipt);
            a_usage->receipt = a_usage->receipt_next;
            a_usage->receipt_next = NULL;
            l_issue_new_receipt = true;
            if ( a_usage->receipt){ // If there is next receipt add the time and request the next receipt
                a_srv_session->limits_units_type.uint32 = a_usage->receipt->receipt_info.units_type.uint32;
                switch( a_usage->receipt->receipt_info.units_type.enm){
                    case SERV_UNIT_B:{
                        a_srv_session->limits_bytes +=  (uint128_t) a_usage->receipt->receipt_info.units;
                        log_it(L_INFO,"%llu bytes more for VPN usage", a_usage->receipt->receipt_info.units);
                    } break;
                    case SERV_UNIT_KB:{
                        a_srv_session->limits_bytes += 1000ull * ( (uint128_t) a_usage->receipt->receipt_info.units);
                        log_it(L_INFO,"%llu bytes more for VPN usage", a_usage->receipt->receipt_info.units);
                    } break;
                    case SERV_UNIT_MB:{
                        a_srv_session->limits_bytes += 1000000ull * ( (uint128_t) a_usage->receipt->receipt_info.units);
                        log_it(L_INFO,"%llu bytes more for VPN usage", a_usage->receipt->receipt_info.units);
                    } break;
                    default: {
                        log_it(L_WARNING, "VPN doesnt accept serv unit type 0x%08X for limits_bytes", a_usage->receipt->receipt_info.units_type.uint32 );
                        dap_stream_ch_set_ready_to_write(a_ch,false);
                        dap_stream_ch_set_ready_to_read(a_ch,false);
                        dap_stream_ch_pkt_write( a_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
                    }
                }


            }else {
                log_it( L_NOTICE, "No activate receipt in usage, switch off write callback for channel");
                dap_stream_ch_set_ready_to_write(a_ch,false);
                dap_stream_ch_set_ready_to_read(a_ch,false);
                dap_stream_ch_pkt_write( a_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );

            }

        }
    }

    // If issue new receipt
    if ( l_issue_new_receipt ) {
        if ( a_usage->receipt){
            dap_chain_datum_tx_receipt_t * l_receipt =dap_chain_net_srv_issue_receipt(a_usage->service, a_usage,a_usage->price,NULL,0 );
            a_usage->receipt_next = l_receipt;
            dap_stream_ch_pkt_write( a_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST ,
                                     l_receipt, l_receipt->size);
        }
    }

}


static void send_pong_pkt(dap_stream_ch_t* a_ch)
{
//    log_it(L_DEBUG,"---------------------------------- PONG!");
    ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
    pkt_out->header.op_code = VPN_PACKET_OP_CODE_PONG;

    dap_stream_ch_pkt_write(a_ch, 'd', pkt_out,
            pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
    dap_stream_ch_set_ready_to_write(a_ch, true);
    free(pkt_out);
}

/**
 * @brief stream_sf_packet_in
 * @param ch
 * @param arg
 */
void s_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_stream_ch_pkt_t * l_pkt = (dap_stream_ch_pkt_t *) a_arg;
    dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION (a_ch->stream->session );
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(a_ch);
    dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find(l_srv_session,  l_ch_vpn->usage_id);

    if ( ! l_usage){
        log_it(L_NOTICE, "No active usage in list, possible disconnected. Send nothin on this channel");
        dap_stream_ch_set_ready_to_write(a_ch,false);
        dap_stream_ch_set_ready_to_read(a_ch,false);
        return;
    }

    if ( ! l_usage->is_active ){
        log_it(L_INFO, "Usage inactivation: switch off packet input channel");
        dap_stream_ch_set_ready_to_write(a_ch,false);
        dap_stream_ch_set_ready_to_read(a_ch,false);
        return;
    }

    // TODO move address leasing to this structure
    dap_chain_net_srv_vpn_t * l_srv_vpn =(dap_chain_net_srv_vpn_t *) l_usage->service->_inhertor;

    //if ( pkt->hdr.type == DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_CLIENT )
    //    dap_chain_net_vpn_client_pkt_in( a_ch, l_pkt);
    if(l_pkt->hdr.type != DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_CLIENT) {
        static bool client_connected = false;
        ch_vpn_pkt_t * l_vpn_pkt = (ch_vpn_pkt_t *) l_pkt->data;
        size_t l_vpn_pkt_size = l_pkt->hdr.size - sizeof (l_vpn_pkt->header);

        int remote_sock_id = l_vpn_pkt->header.sock_id;

        //log_it(L_DEBUG, "Got SF packet with id %d op_code 0x%02x", remote_sock_id, sf_pkt->header.op_code);
        if(l_vpn_pkt->header.op_code >= 0xb0) { // Raw packets
            switch (l_vpn_pkt->header.op_code) {
            case VPN_PACKET_OP_CODE_PING:
                a_ch->stream->esocket->last_ping_request = time(NULL);
                send_pong_pkt(a_ch);
                break;
            case VPN_PACKET_OP_CODE_PONG:
                a_ch->stream->esocket->last_ping_request = time(NULL);
                break;
            // for client
            case VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: { // Assigned address for peer
                if(ch_sf_tun_addr_leased(CH_VPN(a_ch), l_vpn_pkt, l_vpn_pkt_size) < 0) {
                    log_it(L_ERROR, "Can't create tun");
                }
            }
            break;
            // for server
            case VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST: { // Client request after L3 connection the new IP address
                log_it(L_INFO, "Received address request  ");
                if ( l_ch_vpn->addr_ipv4.s_addr ){
                    log_it(L_WARNING,"We already have ip address leased to us");
                    ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
                    pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
                    pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_ALREADY_ASSIGNED_ADDR;
                    pkt_out->header.sock_id = s_raw_server->tun_fd;
                    pkt_out->header.usage_id = l_usage->id;
                    dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                            pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                    dap_stream_ch_set_ready_to_write(a_ch, true);
                    break;
                }
                dap_chain_net_srv_vpn_item_ipv4_t * l_item_ipv4 = l_srv_vpn->ipv4_unleased;
                if ( l_item_ipv4){
                    log_it(L_WARNING,"We have unleased ip address");
                    l_ch_vpn->addr_ipv4.s_addr = l_item_ipv4->addr.s_addr;

                    pthread_rwlock_wrlock( &s_clients_rwlock );
                    HASH_ADD(hh, s_ch_vpn_addrs, addr_ipv4, sizeof (l_ch_vpn->addr_ipv4), l_ch_vpn);
                    pthread_rwlock_unlock( &s_clients_rwlock );

                    ch_vpn_pkt_t *l_pkt_out = DAP_NEW_Z_SIZE(ch_vpn_pkt_t,
                            sizeof(l_pkt_out->header) + sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_host));
                    l_pkt_out->header.sock_id = s_raw_server->tun_fd;
                    l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
                    l_pkt_out->header.op_data.data_size = sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_host);
                    l_pkt_out->header.usage_id = l_usage->id;

                    memcpy(l_pkt_out->data, &l_ch_vpn->addr_ipv4, sizeof(l_ch_vpn->addr_ipv4));
                    memcpy(l_pkt_out->data + sizeof(l_ch_vpn->addr_ipv4), &s_raw_server->ipv4_host,
                            sizeof(s_raw_server->ipv4_host));
                    dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA , l_pkt_out,
                            l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                    log_it(L_NOTICE, "VPN client address %s leased", inet_ntoa(l_ch_vpn->addr_ipv4));
                    log_it(L_INFO, "\tgateway %s", inet_ntoa(s_raw_server->ipv4_host));
                    log_it(L_INFO, "\tmask %s", inet_ntoa(s_raw_server->ipv4_network_mask));
                    log_it(L_INFO, "\taddr %s", inet_ntoa(s_raw_server->ipv4_network_addr));
                    log_it(L_INFO, "\tlast_addr %s", inet_ntoa(s_raw_server->ipv4_lease_last));
                    //dap_stream_ch_set_ready_to_write(a_ch, true);
                    l_srv_vpn->ipv4_unleased = l_item_ipv4->next;
                    DAP_DELETE(l_item_ipv4);
                }else{
                    struct in_addr n_addr = { 0 }, n_addr_max;
                    n_addr.s_addr = ntohl(s_raw_server->ipv4_lease_last.s_addr);
                    n_addr.s_addr++;
                    n_addr_max.s_addr = (ntohl(s_raw_server->ipv4_network_addr.s_addr)
                                         | ~ntohl(s_raw_server->ipv4_network_mask.s_addr));

                    //  Just for log output we revert it back and forward
                    n_addr.s_addr = htonl(n_addr.s_addr);
                    n_addr_max.s_addr = htonl(n_addr_max.s_addr);
                    log_it(L_DEBUG, "Check if is address is lesser than");
                    log_it(L_DEBUG,"    new_address     = %s", inet_ntoa(n_addr));
                    log_it(L_DEBUG,"    new_address_max = %s", inet_ntoa(n_addr_max));
                    n_addr.s_addr = ntohl(n_addr.s_addr);
                    n_addr_max.s_addr = ntohl(n_addr_max.s_addr);
                    if(n_addr.s_addr <= n_addr_max.s_addr ) {
                        n_addr.s_addr = htonl(n_addr.s_addr);
                        n_addr_max.s_addr = htonl(n_addr_max.s_addr);

                        s_raw_server->ipv4_lease_last.s_addr =n_addr.s_addr;
                        a_ch->stream->session->tun_client_addr.s_addr = n_addr.s_addr;
                        l_ch_vpn->addr_ipv4.s_addr = n_addr.s_addr;

                        log_it(L_NOTICE, "VPN client address %s leased", inet_ntoa(n_addr));
                        log_it(L_INFO, "\tgateway %s", inet_ntoa(s_raw_server->ipv4_host));
                        log_it(L_INFO, "\tmask %s", inet_ntoa(s_raw_server->ipv4_network_mask));
                        log_it(L_INFO, "\taddr %s", inet_ntoa(s_raw_server->ipv4_network_addr));
                        log_it(L_INFO, "\tlast_addr %s", inet_ntoa(s_raw_server->ipv4_lease_last));
                        pthread_rwlock_wrlock( &s_clients_rwlock );
                        HASH_ADD(hh, s_ch_vpn_addrs, addr_ipv4, sizeof (l_ch_vpn->addr_ipv4), l_ch_vpn);
                        pthread_rwlock_unlock( &s_clients_rwlock );

                        ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1,
                                sizeof(pkt_out->header) + sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_host));
                        pkt_out->header.sock_id = s_raw_server->tun_fd;
                        pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
                        pkt_out->header.op_data.data_size = sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_host);
                        pkt_out->header.usage_id = l_usage->id;

                        memcpy(pkt_out->data, &l_ch_vpn->addr_ipv4, sizeof(l_ch_vpn->addr_ipv4));
                        memcpy(pkt_out->data + sizeof(l_ch_vpn->addr_ipv4), &s_raw_server->ipv4_host,
                                sizeof(s_raw_server->ipv4_host));

                        if(dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                                                   pkt_out->header.op_data.data_size + sizeof(pkt_out->header))) {
                            dap_stream_ch_set_ready_to_write(a_ch, true);
                        }

                        //ch_sf_raw_write(n_addr.s_addr,STREAM_SF_PACKET_OP_CODE_RAW_L3_ADDR_REPLY,&n_addr,sizeof(n_addr));
                    } else { // All the network is filled with clients, can't lease a new address
                        log_it(L_WARNING, "All the network is filled with clients, can't lease a new address");
                        ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
                        pkt_out->header.sock_id = s_raw_server->tun_fd;
                        pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
                        pkt_out->header.usage_id = l_usage->id;
                        pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_NO_FREE_ADDR;
                        dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                                pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                        dap_stream_ch_set_ready_to_write(a_ch, true);
                    }
                }
            }
                break;
            // for client only
            case VPN_PACKET_OP_CODE_VPN_RECV:{
                a_ch->stream->esocket->last_ping_request = time(NULL); // not ping, but better  ;-)
                            ch_sf_tun_send(CH_VPN(a_ch), l_vpn_pkt->data, l_vpn_pkt->header.op_data.data_size);
            }
            break;

            // for servier only
            case VPN_PACKET_OP_CODE_VPN_SEND: {
                struct in_addr in_saddr, in_daddr;
                in_saddr.s_addr = ((struct iphdr*) l_vpn_pkt->data)->saddr;
                in_daddr.s_addr = ((struct iphdr*) l_vpn_pkt->data)->daddr;

                char str_daddr[43], str_saddr[43];
                strncpy(str_saddr, inet_ntoa(in_saddr), sizeof(str_saddr)-1);
                strncpy(str_daddr, inet_ntoa(in_daddr), sizeof(str_daddr)-1);

                // The packet can't be written, errno == EINVAL !!!
                //log_it(L_DEBUG, "VPN packet, source: %s; dest: %s", inet_ntoa(in_saddr), inet_ntoa(in_daddr));
                int ret;
                //if( ch_sf_raw_write(STREAM_SF_PACKET_OP_CODE_RAW_SEND, sf_pkt->data, sf_pkt->op_data.data_size)<0){
                /*struct sockaddr_in sin = { 0 };
                sin.sin_family = AF_INET;
                sin.sin_port = 0;
                sin.sin_addr.s_addr = in_daddr.s_addr;*/


                //if((ret=sendto(CH_SF(ch)->raw_l3_sock , sf_pkt->data,sf_pkt->header.op_data.data_size,0,(struct sockaddr *) &sin, sizeof (sin)))<0){
                if((ret = write(s_raw_server->tun_fd, l_vpn_pkt->data, l_vpn_pkt->header.op_data.data_size)) < 0) {
                    log_it(L_ERROR, "write() returned error %d : '%s'", ret, strerror(errno));
                    //log_it(L_ERROR,"raw socket ring buffer overflowed");
                    ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
                    pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
                    pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_PACKET_LOST;
                    pkt_out->header.sock_id = s_raw_server->tun_fd;
                    dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                            pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                    dap_stream_ch_set_ready_to_write(a_ch, true);
                } else {
                    s_update_limits (a_ch, l_srv_session, l_usage,(size_t) ret );
                    //log_it(L_DEBUG, "Raw IP packet daddr:%s saddr:%s  %u from %d bytes sent to tun/tap interface",
                    //        str_saddr, str_daddr, sf_pkt->header.op_data.data_size, ret);
                    //log_it(L_DEBUG, "Raw IP sent %u bytes ", ret);
                }
                //}
            }
                break;
            default:
                log_it(L_WARNING, "Can't process SF type 0x%02x", l_vpn_pkt->header.op_code);
            }
        } else { // All except CONNECT
            ch_vpn_socket_proxy_t * sf_sock = NULL;
            if(l_vpn_pkt->header.op_code != VPN_PACKET_OP_CODE_CONNECT) {

                pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                //      log_it(L_DEBUG,"Looking in hash table with %d",remote_sock_id);
                HASH_FIND_INT((CH_VPN(a_ch)->socks), &remote_sock_id, sf_sock);
                pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

                if(sf_sock != NULL) {
                    pthread_mutex_lock(&sf_sock->mutex); // Unlock it in your case as soon as possible to reduce lock time
                    sf_sock->time_lastused = time(NULL);
                    switch (l_vpn_pkt->header.op_code) {
                    case VPN_PACKET_OP_CODE_SEND: {
                        if(client_connected == false)
                        {
                            log_it(L_WARNING, "Drop Packet! User not connected!"); // Client need send
                            pthread_mutex_unlock(&s_sf_socks_mutex);
                            break;
                        }
                        int ret;
                        if((ret = send(sf_sock->sock, l_vpn_pkt->data, l_vpn_pkt->header.op_data.data_size, 0)) < 0) {
                            log_it(L_INFO, "Disconnected from the remote host");
                            pthread_mutex_unlock(&sf_sock->mutex);
                            pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                            HASH_DEL(CH_VPN(a_ch)->socks, sf_sock);
                            pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

                            pthread_mutex_lock(&s_sf_socks_mutex);
                            HASH_DELETE(hh2, sf_socks, sf_sock);
                            HASH_DELETE(hh_sock, sf_socks_client, sf_sock);

                            struct epoll_event ev = {0, {0}};
                            ev.data.fd = sf_sock->sock;
                            ev.events = EPOLLIN;
                            if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, sf_sock->sock, &ev) < 0) {
                                log_it(L_ERROR, "Can't remove sock_id %d from the epoll fd", remote_sock_id);
                                //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=0x%02x result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                            } else {
                                log_it(L_NOTICE, "Removed sock_id %d from the the epoll fd", remote_sock_id);
                                //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=0x%02x result=0",sf_pkt->sock_id, sf_pkt->op_code);
                            }
                            pthread_mutex_unlock(&s_sf_socks_mutex);

                            s_ch_proxy_delete(sf_sock);
                        } else {
                            sf_sock->bytes_sent += ret;
                            pthread_mutex_unlock(&sf_sock->mutex);
                        }
                        //log_it(L_INFO, "Send action from %d sock_id (sf_packet size %lu,  ch packet size %lu, have sent %d)"
                        //        , sf_sock->id, sf_pkt->header.op_data.data_size, l_pkt->hdr.size, ret);
                    }
                        break;
                    case VPN_PACKET_OP_CODE_DISCONNECT: {
                        log_it(L_INFO, "Disconnect action from %d sock_id", sf_sock->id);

                        pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                        HASH_DEL(CH_VPN(a_ch)->socks, sf_sock);
                        pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

                        pthread_mutex_lock(&s_sf_socks_mutex);
                        HASH_DELETE(hh2, sf_socks, sf_sock);
                        HASH_DELETE(hh_sock, sf_socks_client, sf_sock);
                        struct epoll_event ev  = {0, {0}};;
                        ev.data.fd = sf_sock->sock;
                        ev.events = EPOLLIN;
                        if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, sf_sock->sock, &ev) < 0) {
                            log_it(L_ERROR, "Can't remove sock_id %d to the epoll fd", remote_sock_id);
                            //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                        } else {
                            log_it(L_NOTICE, "Removed sock_id %d from the epoll fd", remote_sock_id);
                            //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=0",sf_pkt->sock_id, sf_pkt->op_code);
                        }
                        pthread_mutex_unlock(&s_sf_socks_mutex);

                        pthread_mutex_unlock(&sf_sock->mutex);
                        s_ch_proxy_delete(sf_sock);
                    }
                        break;
                    default: {
                        log_it(L_WARNING, "Unprocessed op code 0x%02x", l_vpn_pkt->header.op_code);
                        pthread_mutex_unlock(&sf_sock->mutex);
                    }
                    }
                } //else
                  //  log_it(L_WARNING, "Packet input: packet with sock_id %d thats not present in current stream channel",
                  //          remote_sock_id);
            } else {
                HASH_FIND_INT(CH_VPN(a_ch)->socks, &remote_sock_id, sf_sock);
                if(sf_sock) {
                    log_it(L_WARNING, "Socket id %d is already used, take another number for socket id", remote_sock_id);
                } else { // Connect action
                    struct sockaddr_in remote_addr;
                    char addr_str[1024];
                    size_t addr_str_size =
                            (l_vpn_pkt->header.op_connect.addr_size > (sizeof(addr_str) - 1)) ?
                                    (sizeof(addr_str) - 1) :
                                    l_vpn_pkt->header.op_connect.addr_size;
                    memset(&remote_addr, 0, sizeof(remote_addr));
                    remote_addr.sin_family = AF_INET;
                    remote_addr.sin_port = htons(l_vpn_pkt->header.op_connect.port);

                    memcpy(addr_str, l_vpn_pkt->data, addr_str_size);
                    addr_str[addr_str_size] = 0;

                    log_it(L_DEBUG, "Connect action to %s:%u (addr_size %lu)", addr_str, l_vpn_pkt->header.op_connect.port,
                            l_vpn_pkt->header.op_connect.addr_size);
                    if(inet_pton(AF_INET, addr_str, &(remote_addr.sin_addr)) < 0) {
                        log_it(L_ERROR, "Wrong remote address '%s:%u'", addr_str, l_vpn_pkt->header.op_connect.port);
                    } else {
                        int s;
                        if((s = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
                            log_it(L_DEBUG, "Socket is created (%d)", s);
                            if(connect(s, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) >= 0) {
                                fcntl(s, F_SETFL, O_NONBLOCK);
                                log_it(L_INFO, "Remote address connected (%s:%u) with sock_id %d", addr_str,
                                        l_vpn_pkt->header.op_connect.port, remote_sock_id);
                                ch_vpn_socket_proxy_t * sf_sock = NULL;
                                sf_sock = DAP_NEW_Z(ch_vpn_socket_proxy_t);
                                sf_sock->id = remote_sock_id;
                                sf_sock->sock = s;
                                sf_sock->ch = a_ch;
                                pthread_mutex_init(&sf_sock->mutex, NULL);

                                pthread_mutex_lock(&s_sf_socks_mutex);
                                pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                                HASH_ADD_INT(CH_VPN(a_ch)->socks, id, sf_sock);
                                log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id,
                                        sf_sock->sock);
                                HASH_ADD(hh2, sf_socks, id, sizeof(sf_sock->id), sf_sock);
                                log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id,
                                        sf_sock->sock);
                                HASH_ADD(hh_sock, sf_socks_client, sock, sizeof(int), sf_sock);
                                //log_it(L_DEBUG,"Added %d sock_id with sock %d to the socks hash table",sf->id,sf->sock);
                                pthread_mutex_unlock(&s_sf_socks_mutex);
                                pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

                                struct epoll_event ev = {0, {0}};
                                ev.data.fd = s;
                                ev.events = EPOLLIN | EPOLLERR;

                                if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_ADD, s, &ev) == -1) {
                                    log_it(L_ERROR, "Can't add sock_id %d to the epoll fd", remote_sock_id);
                                    //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                                } else {
                                    log_it(L_NOTICE, "Added sock_id %d  with sock %d to the epoll fd", remote_sock_id, s);
                                    log_it(L_NOTICE, "Send Connected packet to User");
                                    ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
                                    pkt_out->header.sock_id = remote_sock_id;
                                    pkt_out->header.op_code = VPN_PACKET_OP_CODE_CONNECTED;
                                    dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_CLIENT, pkt_out,
                                            pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                                    free(pkt_out);
                                    client_connected = true;
                                }
                                dap_stream_ch_set_ready_to_write(a_ch, true);
                            } else {
                                log_it(L_INFO, "Can't connect to the remote server %s", addr_str);
                                dap_stream_ch_pkt_write_f(a_ch, 'i', "sock_id=%d op_code=%c result=-1",
                                        l_vpn_pkt->header.sock_id, l_vpn_pkt->header.op_code);
                                dap_stream_ch_set_ready_to_write(a_ch, true);
                            }
                        } else {
                            log_it(L_ERROR, "Can't create the socket");
                        }
                    }
                }
            }
        }
    }
}

/**
 * @brief stream_sf_packet_out Packet Out Ch callback
 * @param ch
 * @param arg
 */
static void s_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;
    ch_vpn_socket_proxy_t * cur, *tmp;
    dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION( a_ch->stream->session );
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(a_ch);

    dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find(l_srv_session,  l_ch_vpn->usage_id);
    if ( ! l_usage){
        log_it(L_NOTICE, "No active usage in list, possible disconnected. Send nothin on this channel");
        dap_stream_ch_set_ready_to_write(a_ch,false);
        dap_stream_ch_set_ready_to_read(a_ch,false);
        return;
    }

    if ( ! l_usage->is_active ){
        log_it(L_INFO, "Usage inactivation: switch off packet output channel");
        dap_stream_ch_set_ready_to_write(a_ch,false);
        dap_stream_ch_set_ready_to_read(a_ch,false);
        if (l_usage->clients)
            dap_stream_ch_pkt_write( l_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
        return;
    }
    if ( (! l_usage->is_free) && (! l_usage->receipt) ){
        log_it(L_WARNING, "No active receipt, switching off");
        dap_stream_ch_set_ready_to_write(a_ch,false);
        dap_stream_ch_set_ready_to_read(a_ch,false);
        if (l_usage->clients)
            dap_stream_ch_pkt_write( l_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
        return;
    }

    bool l_is_smth_out = false;
//    log_it(L_DEBUG,"Socket forwarding packet out callback: %u sockets in hashtable", HASH_COUNT(CH_SF(ch)->socks) );
    HASH_ITER(hh, l_ch_vpn->socks , cur, tmp)
    {
        bool l_signal_to_break = false;
        pthread_mutex_lock(&(cur->mutex));
        size_t i;
        //log_it(L_DEBUG, "Socket with id %d has %u packets in output buffer", cur->id, cur->pkt_out_size);
        if(cur->pkt_out_size) {
            for(i = 0; i < cur->pkt_out_size; i++) {
                ch_vpn_pkt_t * pout = cur->pkt_out[i];
                if(pout) {
                    size_t l_wrote_size;
                    if((l_wrote_size = dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pout,
                            pout->header.op_data.data_size + sizeof(pout->header)))>0 ) {
                        l_is_smth_out = true;
                        DAP_DELETE(pout);
                        cur->pkt_out[i] = NULL;
                    } else {
                        log_it(L_WARNING, "Buffer is overflowed, breaking cycle to let the upper level cycle drop data to the output socket");
                        l_is_smth_out = true;
                        l_signal_to_break = true;
                        break;
                    }
                    s_update_limits (a_ch, l_srv_session, l_usage,l_wrote_size );
                }
            }
        }

        if(l_signal_to_break) {
            pthread_mutex_unlock(&(cur->mutex));
            break;
        }
        cur->pkt_out_size = 0;
        if(cur->signal_to_delete) {
            log_it(L_NOTICE, "Socket id %d got signal to be deleted", cur->id);
            pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
            HASH_DEL(l_ch_vpn->socks, cur);
            pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

            pthread_mutex_lock(&(s_sf_socks_mutex));
            HASH_DELETE(hh2, sf_socks, cur);
            HASH_DELETE(hh_sock, sf_socks_client, cur);
            pthread_mutex_unlock(&(s_sf_socks_mutex));

            pthread_mutex_unlock(&(cur->mutex));
            s_ch_proxy_delete(cur);
        } else
            pthread_mutex_unlock(&(cur->mutex));
    }
    if(l_is_smth_out) {
        if(a_ch->stream->conn_http)
            a_ch->stream->conn_http->state_write = DAP_HTTP_CLIENT_STATE_DATA;
    }

    dap_stream_ch_set_ready_to_write(a_ch, l_is_smth_out);
}

/**
 * @brief stream_sf_disconnect
 * @param sf
 */
void srv_stream_sf_disconnect(ch_vpn_socket_proxy_t * sf_sock)
{
    struct epoll_event ev = {0, {0}};
    ev.data.fd = sf_sock->sock;
    ev.events = EPOLLIN | EPOLLERR;
    if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, sf_sock->sock, &ev) == -1) {
        log_it(L_ERROR, "Can't del sock_id %d from the epoll fd", sf_sock->id);
        //stream_ch_pkt_write_f(sf->ch,'i',"sock_id=%d op_code=%uc result=-1",sf->id, STREAM_SF_PACKET_OP_CODE_RECV);
    } else {
        log_it(L_ERROR, "Removed sock_id %d from the epoll fd", sf_sock->id);
        //stream_ch_pkt_write_f(sf->ch,'i',"sock_id=%d op_code=%uc result=0",sf->id, STREAM_SF_PACKET_OP_CODE_RECV);
    }

    // Compise signal to disconnect to another side, with special opcode STREAM_SF_PACKET_OP_CODE_DISCONNECT
    ch_vpn_pkt_t * pkt_out;
    pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + 1);
    pkt_out->header.op_code = VPN_PACKET_OP_CODE_DISCONNECT;
    pkt_out->header.sock_id = sf_sock->id;
    sf_sock->pkt_out[sf_sock->pkt_out_size] = pkt_out;
    sf_sock->pkt_out_size++;
    sf_sock->signal_to_delete = true;
}

/**

 Socket forward
 **/

void * srv_ch_sf_thread(void * a_arg)
{
    UNUSED(a_arg);
    struct epoll_event ev = {0, {0}}, events[SF_MAX_EVENTS] = { {0, {0}} };
    //pthread_mutex_lock(&sf_socks_mutex);
    sf_socks_epoll_fd = epoll_create(SF_MAX_EVENTS);
    sigset_t sf_sigmask;
    sigemptyset(&sf_sigmask);
    sigaddset(&sf_sigmask, SIGUSR2);

    while(1) {
        int nfds = epoll_pwait(sf_socks_epoll_fd, events, SF_MAX_EVENTS, 10000, &sf_sigmask);
        if(nfds < 0) {
            //log_it(L_CRITICAL,"Can't run epoll_wait: %s",strerror(errno));
            continue;
        }
        if(nfds > 0)
            log_it(L_DEBUG, "Epolled %d fd", nfds);
        else
            continue;
        int n;
        for(n = 0; n < nfds; ++n) {
            int s = events[n].data.fd;

            ch_vpn_socket_proxy_t * l_socket_proxy = NULL;
            pthread_mutex_lock(&s_sf_socks_mutex);
            HASH_FIND(hh_sock, sf_socks_client, &s, sizeof(s), l_socket_proxy);
            pthread_mutex_unlock(&s_sf_socks_mutex);
            if( l_socket_proxy ) {
                dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION (l_socket_proxy->ch->stream->session );
                dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(l_socket_proxy->ch);
                dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find(l_srv_session,  l_ch_vpn->usage_id);

                if(events[n].events & EPOLLERR) {
                    log_it(L_NOTICE, "Socket id %d has EPOLLERR flag on", s);
                    pthread_mutex_lock(&(l_socket_proxy->mutex));
                    srv_stream_sf_disconnect(l_socket_proxy);
                    pthread_mutex_unlock(&(l_socket_proxy->mutex));
                } else if(events[n].events & EPOLLIN) {
                    char buf[1000000];
                    ssize_t ret;
                    pthread_mutex_lock(&(l_socket_proxy->mutex));
                    if(l_socket_proxy->pkt_out_size < ((sizeof(l_socket_proxy->pkt_out) / sizeof(l_socket_proxy->pkt_out[0])) - 1)) {
                        ret = recv(l_socket_proxy->sock, buf, sizeof(buf), 0);
                        //log_it(L_DEBUG,"recv() returned %d",ret);
                        if(ret > 0) {
                            size_t buf_size = ret;
                            s_update_limits(l_socket_proxy->ch,l_srv_session,l_usage,buf_size);
                            if ( dap_stream_ch_get_ready_to_read(l_socket_proxy->ch) ){
                                ch_vpn_pkt_t * pout;
                                pout = l_socket_proxy->pkt_out[l_socket_proxy->pkt_out_size] = (ch_vpn_pkt_t *) calloc(1,
                                        buf_size + sizeof(pout->header));
                                pout->header.op_code = VPN_PACKET_OP_CODE_RECV;
                                pout->header.sock_id = l_socket_proxy->id;
                                pout->header.usage_id = l_usage->id;
                                pout->header.op_data.data_size = buf_size;
                                memcpy(pout->data, buf, buf_size);
                                l_socket_proxy->pkt_out_size++;
                                pthread_mutex_unlock(&(l_socket_proxy->mutex));
                                dap_stream_ch_set_ready_to_write(l_socket_proxy->ch, true);
                            }else{
                                pthread_mutex_unlock(&(l_socket_proxy->mutex));
                            }

                        } else {
                            log_it(L_NOTICE,
                                    "Socket id %d returned error on recv() function - may be host has disconnected", s);
                            pthread_mutex_unlock(&(l_socket_proxy->mutex));
                            dap_stream_ch_set_ready_to_write(l_socket_proxy->ch, true);
                            srv_stream_sf_disconnect(l_socket_proxy);
                        }
                    } else {
                        log_it(L_WARNING, "Can't receive data, full of stack");
                        pthread_mutex_unlock(&(l_socket_proxy->mutex));
                    }
                } else {
                    log_it(L_WARNING, "Unprocessed flags 0x%08X", events[n].events);
                }
            } else {
                if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, s, &ev) < 0) {
                    log_it(L_ERROR, "Can't remove sock_id %d to the epoll fd", s);
                } else {
                    log_it(L_NOTICE, "Socket id %d is removed from the list", s);
                }
            }
        }
        //pthread_mutex_unlock(&sf_socks_mutex);
    }
    return NULL;
}

static volatile bool s_srv_ch_sf_thread_raw_is_exit = false;

/* Signal handler. */
static void s_sig_handle (int sig)
{
    UNUSED(sig);
    s_srv_ch_sf_thread_raw_is_exit = true;
}

/**
 *
 *
 **/
void* srv_ch_sf_thread_raw(void *arg)
{
    UNUSED(arg);
    s_tun_create();

    if(s_raw_server->tun_fd <= 0) {
        log_it(L_CRITICAL, "Tun/tap file descriptor is not initialized");
        return NULL;
    }
    /*    if (fcntl(raw_server->tun_fd, F_SETFL, O_NONBLOCK) < 0){ ;
     log_it(L_CRITICAL,"Can't switch tun/tap socket into the non-block mode");
     return NULL;
     }
     if (fcntl(raw_server->tun_fd, F_SETFD, FD_CLOEXEC) < 0){;
     log_it(L_CRITICAL,"Can't switch tun/tap socket to not be passed across execs");
     return NULL;
     }
     */
    uint8_t *l_tmp_buf;
    ssize_t tmp_buf_size;
    static int tun_MTU = 100000; /// TODO Replace with detection of MTU size

    l_tmp_buf = (uint8_t *) alloca(tun_MTU);
    if ( !l_tmp_buf){ // Can't allocate on stack
        log_it(L_ERROR,"Can't allocate read buffer on stack, trying to get one from heap");
        l_tmp_buf = DAP_NEW_SIZE(uint8_t, tun_MTU);
    }
    tmp_buf_size = 0;
    log_it(L_INFO, "Tun/tap thread starts with MTU = %d", tun_MTU);

    fd_set fds_read, fds_read_active;
    sigset_t l_sig_mask_proc;
    sigset_t l_sig_mask_orig;
    sigemptyset (&l_sig_mask_proc);
    sigaddset (&l_sig_mask_proc, SIGTERM);


    FD_ZERO(&fds_read);
    FD_SET(s_raw_server->tun_fd, &fds_read);
    FD_SET(get_select_breaker(), &fds_read);
    /// Main cycle
    do {
        fds_read_active = fds_read;
        int ret = select(FD_SETSIZE, &fds_read_active, NULL, NULL, NULL);
        //
        if(ret > 0) {
            if(FD_ISSET(get_select_breaker(), &fds_read_active)) { // Smth to send
                ch_vpn_pkt_t* pkt = srv_ch_sf_raw_read();
                if(pkt) {
                    int write_ret = write(s_raw_server->tun_fd, pkt->data, pkt->header.op_data.data_size);
                    if(write_ret > 0) {
                        //log_it(L_DEBUG, "Wrote out %d bytes to the tun/tap interface", write_ret);
                    } else {
                        log_it(L_ERROR, "Tun/tap write %u bytes returned '%s' error, code (%d)",
                                pkt->header.op_data.data_size, strerror(errno), write_ret);
                    }
                }
            }

            if(FD_ISSET(s_raw_server->tun_fd, &fds_read_active)) {
                int l_read_ret = read(s_raw_server->tun_fd, l_tmp_buf, tun_MTU);
                if(l_read_ret < 0) {
                    log_it(L_CRITICAL, "Tun/tap read returned '%s' error, code (%d)", strerror(errno), l_read_ret);
                    break;
                } else {
                    struct iphdr *iph = (struct iphdr*) l_tmp_buf;
                    struct in_addr in_daddr, in_saddr;
                    in_daddr.s_addr = iph->daddr;
                    in_saddr.s_addr = iph->saddr;
                    char str_daddr[42], str_saddr[42];
                    dap_snprintf(str_saddr, sizeof(str_saddr), "%s",inet_ntoa(in_saddr) );
                    dap_snprintf(str_daddr, sizeof(str_daddr), "%s",inet_ntoa(in_daddr) );

                    //log_it(L_DEBUG, "Read IP packet from tun/tap interface daddr=%s saddr=%s total_size = %d "
                    //        , str_daddr, str_saddr, read_ret);
                    dap_chain_net_srv_ch_vpn_t * l_ch_vpn = NULL;
                    pthread_rwlock_rdlock(&s_clients_rwlock);
                    HASH_FIND(hh,s_ch_vpn_addrs, &in_daddr, sizeof (in_daddr), l_ch_vpn);
//                  HASH_ADD_INT(CH_SF(ch)->socks, id, sf_sock );
//                  HASH_DEL(CH_SF(ch)->socks,sf_sock);

                    ///
                    if(l_ch_vpn) { // Is present in hash table such destination address

                        if (dap_stream_ch_get_ready_to_read(l_ch_vpn->ch ) ){
                            dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION (l_ch_vpn->ch->stream->session );
                            dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find(l_srv_session,  l_ch_vpn->usage_id);
                            ch_vpn_pkt_t *l_pkt_out = DAP_NEW_Z_SIZE(ch_vpn_pkt_t, sizeof(l_pkt_out->header) + l_read_ret);
                            l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_RECV;
                            l_pkt_out->header.sock_id = s_raw_server->tun_fd;
                            l_pkt_out->header.usage_id = l_ch_vpn->usage_id;
                            l_pkt_out->header.op_data.data_size = l_read_ret;
                            memcpy(l_pkt_out->data, l_tmp_buf, l_read_ret);
                            dap_stream_ch_pkt_write(l_ch_vpn->ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, l_pkt_out,
                                    l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                            s_update_limits(l_ch_vpn->ch,l_srv_session,l_usage, l_read_ret);
                        }
                    }
                    pthread_rwlock_unlock(&s_clients_rwlock);\
                }
            }/*else {
             log_it(L_CRITICAL,"select() has no tun handler in the returned set");
             break;

             }*/
        } else {
            //log_it(L_WARNING, "Select returned %d: %s", ret, strerror(errno));
            //break;
        }
    } while(! s_srv_ch_sf_thread_raw_is_exit );
    log_it(L_NOTICE, "Raw sockets listen thread is stopped");
    s_tun_destroy();
    return NULL;
}

#ifdef DAP_TUN_IN_WORKER
void m_es_tun_delete(dap_events_socket_t * a_es, void * arg)
{
  log_it(L_WARNING, __PRETTY_FUNCTION__);
  log_it(L_NOTICE, "Raw sockets listen thread is stopped");
  dap_events_socket_remove_and_delete_mt(s_raw_server->tun_events_socket);
  s_tun_destroy();
}

void m_es_tun_write(dap_events_socket_t * a_es, void * arg)
{

}

void m_es_tun_read(dap_events_socket_t * a_es, void * arg)
{
    const static int tun_MTU = 100000; /// TODO Replace with detection of MTU size
    uint8_t l_tmp_buf[tun_MTU];

    size_t l_read_ret;


    l_read_ret = dap_events_socket_pop_from_buf_in(s_raw_server->tun_events_socket, l_tmp_buf, sizeof(l_tmp_buf));

    if(l_read_ret > 0) {
        struct iphdr *iph = (struct iphdr*) l_tmp_buf;
        struct in_addr in_daddr, in_saddr;
        in_daddr.s_addr = iph->daddr;
        in_saddr.s_addr = iph->saddr;
        char str_daddr[42], str_saddr[42];
        dap_snprintf(str_saddr, sizeof(str_saddr), "%s",inet_ntoa(in_saddr) );
        dap_snprintf(str_daddr, sizeof(str_daddr), "%s",inet_ntoa(in_daddr) );

        dap_chain_net_srv_ch_vpn_t * l_ch_vpn = NULL;
        pthread_rwlock_rdlock(&s_clients_rwlock);
        HASH_FIND(hh,s_ch_vpn_addrs, &in_daddr, sizeof (in_daddr), l_ch_vpn);

        if(l_ch_vpn) { // Is present in hash table such destination address

            if (dap_stream_ch_get_ready_to_read(l_ch_vpn->ch ) ){
                dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION (l_ch_vpn->ch->stream->session );
                dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find(l_srv_session,  l_ch_vpn->usage_id);
                ch_vpn_pkt_t *l_pkt_out = DAP_NEW_Z_SIZE(ch_vpn_pkt_t, sizeof(l_pkt_out->header) + l_read_ret);
                l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_RECV;
                l_pkt_out->header.sock_id = s_raw_server->tun_fd;
                l_pkt_out->header.usage_id = l_ch_vpn->usage_id;
                l_pkt_out->header.op_data.data_size = l_read_ret;
                memcpy(l_pkt_out->data, l_tmp_buf, l_read_ret);
                dap_stream_ch_pkt_write(l_ch_vpn->ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, l_pkt_out,
                        l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                s_update_limits(l_ch_vpn->ch,l_srv_session,l_usage, l_read_ret);
            }
        }
        pthread_rwlock_unlock(&s_clients_rwlock);
    }


    dap_events_socket_set_readable_unsafe(a_es, true);
}

void m_es_tun_error(dap_events_socket_t * a_es, void * arg)
{
  log_it(L_WARNING, __PRETTY_FUNCTION__);
}
#endif


static void s_es_tun_new(dap_events_socket_t * a_es, void * arg)
{
    (void) arg;
    ch_sf_tun_socket_t * l_tun_socket = DAP_NEW_Z(ch_sf_tun_socket_t);
    if ( l_tun_socket ){
        l_tun_socket->worker = a_es->worker;
        l_tun_socket->worker_id = l_tun_socket->worker->id;
        l_tun_socket->es = a_es;
        pthread_rwlock_wrlock(&s_tun_sockets_rwlock);
        HASH_ADD_INT( s_tun_sockets, worker_id, l_tun_socket);
        pthread_rwlock_unlock(&s_tun_sockets_rwlock);
        a_es->_inheritor = l_tun_socket;
        s_tun_attach_queue( a_es->fd );
        log_it(L_NOTICE,"New TUN event socket initialized for worker %u" , l_tun_socket->worker_id);
    }else{
        log_it(L_ERROR, "Can't allocate memory for tun socket");
    }
}

static void s_es_tun_delete(dap_events_socket_t * a_es, void * arg)
{
    if (! a_es->_inheritor) // There is moment between inheritor initialization and active live of event socket in worker.
        return;

    ch_sf_tun_socket_t * l_tun_socket = CH_SF_TUN_SOCKET( a_es );
    pthread_rwlock_wrlock(&s_tun_sockets_rwlock);
    HASH_DEL(s_tun_sockets,l_tun_socket);
    DAP_DELETE(l_tun_socket);
    a_es->_inheritor = NULL;
    pthread_rwlock_unlock(&s_tun_sockets_rwlock);
    log_it(L_NOTICE,"Destroyed TUN event socket");
}

static void s_es_tun_error(dap_events_socket_t * a_es, void * arg)
{
    if (! a_es->_inheritor)
        return;
    log_it(L_ERROR,"%s: error in socket %u (socket type %d)", __PRETTY_FUNCTION__, a_es->socket, a_es->type);
}

void s_es_tun_read(dap_events_socket_t * a_es, void * arg)
{
    //TODO: implement
}
