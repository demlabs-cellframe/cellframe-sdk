#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "sap_common.h"
#include "sap_config.h"
#include "sap_events.h"
#include "sap_events_socket.h"
#include "ch_sf.h"
#include "ch_sf_tun.h"
#include "sf_client.h"
#include "mod_sf.h"

#define LOG_TAG "mod_sf"

static struct sap_events * s_events = NULL;

// Single-linked peers list
struct sf_client_list{
    sf_client_t * item;
    char * name;
    struct sf_client_list * next;
};

static struct sf_client_list * s_peers = NULL;

void m_sf_client_callback_connected(sf_client_t * a_client, void * arg);
void m_sf_client_callback_disconnected(sf_client_t * a_client, void * arg);
void m_sf_client_callback_error(sf_client_t * a_client, void * arg);

/**
 * @brief mod_sf_peer_start
 * @param a_events
 * @param a_worker
 */
void mod_sf_peer_start(struct sap_events * a_events)
{
    if( s_events != NULL ){
        log_it(L_WARNING, "Peering is already started");
        return;
    }
    s_events = a_events;

    // Prepare dir parse
    DIR *d;
    struct dirent *dir;
    size_t buf_size = strlen(sap_configs_path())+1+strlen(SF_CLIENT_CONFIGS_PATH)+1;
    char * buf = SAP_NEW_Z_SIZE(char,buf_size);
    snprintf(buf,buf_size,"%s/%s",sap_configs_path(),SF_CLIENT_CONFIGS_PATH);
    d = opendir(buf);
    if (d) {
        // Process every dir entry
        while ((dir = readdir(d)) != NULL) {
            if( dir->d_name[0]=='.' ) continue;
            log_it(L_DEBUG,"Peer config '%s'", dir->d_name);
            // List the peer in memory
            struct  sf_client_list * l_peer = SAP_NEW_Z(struct sf_client_list);
            l_peer->next = s_peers;
            l_peer->name = SAP_NEW_Z_SIZE(char, strlen(dir->d_name));
            strcpy(l_peer->name, dir->d_name);

            s_peers = l_peer;

            sf_client_t * l_sf_client = sf_client_new(a_events,dir->d_name);
            if( l_sf_client == NULL){
                SAP_DELETE(l_peer);
                log_it(L_WARNING, "Can't init peer config '%s'",dir->d_name);
                continue;
            }
            l_peer->item = l_sf_client;

            // Setup callbacks
            sf_client_set_callback_connected(l_sf_client,m_sf_client_callback_connected );
            sf_client_set_callback_disconnected( l_sf_client,m_sf_client_callback_disconnected );
            sf_client_set_callback_error(l_sf_client,m_sf_client_callback_error );
        }
        closedir(d);
    }else{
        log_it(L_ERROR, "Can't open path %s: %s",buf,strerror(errno));
    }
}

/**
 * @brief mod_sf_peer_stop
 */
void mod_sf_peer_stop()
{
    struct sf_client_list * l_item = s_peers, *l_tmp;
    while (l_item){
        sf_client_delete(l_item->item);
        l_tmp = l_item->next;
        SAP_DELETE(l_item->name);
        SAP_DELETE(l_item);
        l_item = l_tmp;
    }
}

/**
 * @brief m_sf_client_callback_connected
 * @param a_client
 * @param arg
 */
void m_sf_client_callback_connected(sf_client_t * a_client, void * arg)
{
    log_it(L_DEBUG,"mod_sf_client connected");
}

/**
 * @brief m_sf_client_callback_disconnected
 * @param a_client
 * @param arg
 */
void m_sf_client_callback_disconnected(sf_client_t * a_client, void * arg)
{
    log_it(L_DEBUG,"mod_sf_client disconnected");
}

/**
 * @brief m_sf_client_callback_error
 * @param a_client
 * @param arg
 */
void m_sf_client_callback_error(sf_client_t * a_client, void * arg)
{
    log_it(L_WARNING,"mod_sf_client error");
}

