#include "dap_udp_server.h"
#include <stdio.h>
#include "dap_common.h"
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <ev.h>
#include "utlist.h"

#define LOG_TAG "dap_udp_server"

#define BUFSIZE 1024

char buf[BUFSIZE]; /* message buf */
struct ev_io w_read;
struct ev_io w_write;

static void write_cb(struct ev_loop* _loop, struct ev_io* watcher, int revents);
int check_close(dap_server_client_t* client);

/**
 */
void error(char *msg) {
  perror(msg);
  exit(1);
}

/**
 * @brief dap_udp_server_new Initialize server structure
 * @return Server pointer
 */
dap_server_t * dap_udp_server_new()
{
    dap_udp_server_t* udp_server = (dap_udp_server_t*)calloc(1,sizeof(dap_udp_server_t));
    udp_server->waiting_clients = NULL;
    dap_server_t* sh = (dap_server_t*) calloc(1,sizeof(dap_server_t));
    sh->_inheritor = udp_server;
    udp_server->dap_server = sh;
    return sh;
}

/**
 * @brief dap_udp_client_loop Create client listening event loop
 */
void* dap_udp_client_loop(void * arg)
{
    dap_server_t* sh = (dap_server_t*)arg;
    log_it(L_NOTICE, "Start client listener thread");
    struct ev_loop * ev_client_loop = ev_loop_new(0);
    w_write.data = sh;
    ev_io_init(&w_write, write_cb, sh->socket_listener, EV_WRITE);
    ev_io_start(ev_client_loop, &w_write);
    ev_loop(ev_client_loop, 0);
    return NULL;
}

/**
 * @brief dap_udp_server_delete Safe delete server structure
 * @param sh Server instance
 */
void dap_udp_server_delete(dap_server_t * sh)
{
    if(sh->address)
        free(sh->address);

    dap_server_client_t * client, * tmp;
    HASH_ITER(hh,sh->clients,client,tmp)
        dap_client_remove(client, sh);    

    if(sh->server_delete_callback)
        sh->server_delete_callback(sh,NULL);
    if(sh->_inheritor)
        free(sh->_inheritor);
    free(sh);
}

/**
 * @brief dap_udp_server_listen Create and bind server structure
 * @param port Binding port
 * @return Server instance 
 */
dap_server_t * dap_udp_server_listen(uint16_t port){
    dap_server_t* sh = dap_udp_server_new();

    sh->socket_listener = socket (AF_INET, SOCK_DGRAM, 0);

    if (sh->socket_listener < 0){
        log_it (L_ERROR,"Socket error %s",strerror(errno));
        dap_udp_server_delete(sh);
        return NULL;
    }

    int optval = 1;
    if(setsockopt(sh->socket_listener, SOL_SOCKET, SO_REUSEADDR,(const void *)&optval , sizeof(int)) < 0)
        log_it(L_WARNING, "Can't set up REUSEADDR flag to the socket");

    bzero((char *) &(sh->listener_addr), sizeof(sh->listener_addr));
    sh->listener_addr.sin_family = AF_INET;
    sh->listener_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    sh->listener_addr.sin_port = htons(port);

    if(bind (sh->socket_listener, (struct sockaddr *) &(sh->listener_addr), sizeof(sh->listener_addr)) < 0) {
        log_it(L_ERROR,"Bind error: %s",strerror(errno));
        dap_udp_server_delete(sh);
        return NULL;
    }
    pthread_mutex_init(&DAP_UDP_SERVER(sh)->mutex_on_list, NULL);
    return sh;
}

/**
 * @brief write_cb
 */
static void write_cb(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
    if( ( revents & EV_WRITE ) ) {
        dap_server_t* sh = watcher->data;
        dap_udp_server_t* udp = DAP_UDP_SERVER(sh);
        dap_udp_client_t * udp_client, * tmp;
        pthread_mutex_lock(&udp->mutex_on_list);
        LL_FOREACH_SAFE(udp->waiting_clients,udp_client,tmp)
        {            
            //log_it(L_INFO,"write_cb");
            //pthread_mutex_lock(&udp_client->mutex_on_client);
            dap_server_client_t* client = udp_client->client;
            if(client != NULL && check_close(client) == 0 && client->_ready_to_write)
            {
                if(sh->client_write_callback)
                    sh->client_write_callback(client, NULL);
                if(client->buf_out_size > 0)
                {
                    //log_it(L_INFO,"write_cb_client");
                    for(size_t total_sent = 0; total_sent < client->buf_out_size;) {
                        struct sockaddr_in addr;
                        addr.sin_family = AF_INET;
                        dap_udp_client_get_address(client,&addr.sin_addr.s_addr,&addr.sin_port);
                        int bytes_sent = sendto(sh->socket_listener, client->buf_out + total_sent, client->buf_out_size - total_sent, 0, (struct sockaddr*) &addr, sizeof(addr));
                        if(bytes_sent < 0) {
                            log_it(L_ERROR,"Some error occured in send() function");
                            break;
                        }
                        total_sent += bytes_sent;
                    }
                    client->buf_out_size = 0;
                    bzero(client->buf_out, DAP_CLIENT_REMOTE_BUF + 1);

                }
                LL_DELETE(udp->waiting_clients,udp_client);
            }
            else if(client == NULL)
                LL_DELETE(udp->waiting_clients,udp_client);
            //pthread_mutex_unlock(&udp_client->mutex_on_client);
        }
        pthread_mutex_unlock(&udp->mutex_on_list);
    }
}

/**
 * @brief check_close Check if client need to close
 * @param client Client structure
 * @return 1 if client deleted, 0 if client is no need to delete
 */
int check_close(dap_server_client_t* client){
    if(client->signal_close)
    {
        dap_udp_client_t* udp_client = DAP_UDP_CLIENT(client);
        dap_server_t* sh = client->server;
        dap_udp_server_t* udp_server = DAP_UDP_SERVER(sh);
        dap_udp_client_t * client_check, * tmp;
        LL_FOREACH_SAFE(udp_server->waiting_clients,client_check,tmp)
            if(client_check->host_key == udp_client->host_key)
                LL_DELETE(udp_server->waiting_clients,client_check);
        dap_client_remove(client, sh);
        return 1;
    }
    return 0;
}

/**
 * @brief read_cb
 */
static void read_cb(struct ev_loop* loop, struct ev_io* watcher, int revents)
{
    //log_it(L_INFO,"read_cb");
    if ( revents & EV_READ )
    {
        struct sockaddr_in clientaddr;
        int clientlen = sizeof(clientaddr);
        dap_server_t* sh = watcher->data;
        bzero(buf, BUFSIZE);
        socklen_t bytes = recvfrom(sh->socket_listener, buf, BUFSIZE, 0,(struct sockaddr *) &clientaddr, &clientlen);
        dap_server_client_t *client = dap_udp_client_find(sh,clientaddr.sin_addr.s_addr,clientaddr.sin_port);
        if(client != NULL && check_close(client) != 0)
            return;
        if(bytes > 0){
            char * hostaddrp = inet_ntoa(clientaddr.sin_addr);
            if(hostaddrp == NULL)
            {
                dap_udp_server_delete(sh);
                error("ERROR on inet_ntoa\n");
            }
            if(client == NULL)
            {
                client = dap_udp_client_create(sh,&w_write,clientaddr.sin_addr.s_addr,clientaddr.sin_port);
                if(client == NULL)
                {
                    dap_udp_server_delete(sh);
                    error("ERROR create client structure\n");
                }
            }
            dap_udp_client_t* udp_client = client->_inheritor;
            pthread_mutex_lock(&udp_client->mutex_on_client);
            size_t bytes_processed = 0;
            size_t bytes_recieved = bytes;
            while(bytes_recieved > 0){
                size_t bytes_to_transfer = 0;
                if(bytes_recieved > UDP_CLIENT_BUF - client->buf_in_size)
                    bytes_to_transfer = UDP_CLIENT_BUF - client->buf_in_size;
                else
                    bytes_to_transfer = bytes_recieved;
                memcpy(client->buf_in + client->buf_in_size,buf+bytes_processed,bytes_to_transfer);
                client->buf_in_size += bytes_to_transfer;

                if(sh->client_read_callback)
                    sh->client_read_callback(client,NULL);
                
                bytes_processed += bytes_to_transfer;
                bytes_recieved -= bytes_to_transfer;
            }
            client->buf_in_size = 0;
            bzero(client->buf_in, DAP_CLIENT_REMOTE_BUF + 1);
            pthread_mutex_unlock(&udp_client->mutex_on_client);

        }
        else if(bytes < 0)
        {
            log_it(L_ERROR,"Bytes read Error %s",strerror(errno));
            if(client != NULL)
                client->signal_close = true;

        }
        else if (bytes == 0)
        {
            if(client != NULL)
                client->signal_close = true;
        }
    }
}

/**
 * @brief dap_udp_server_loop Start server event loop
 * @param sh Server instance
 */
void dap_udp_server_loop(dap_server_t * sh){
    sh->proc_thread.tid = pthread_self();

    pthread_t thread;
    pthread_create(&thread, NULL, dap_udp_client_loop, sh);
    struct ev_loop * ev_main_loop = ev_default_loop(0);
    w_read.data = sh;
    ev_io_init(&w_read, read_cb, sh->socket_listener, EV_READ);
    ev_io_start(ev_main_loop, &w_read);
    ev_run(ev_main_loop, 0);
}

