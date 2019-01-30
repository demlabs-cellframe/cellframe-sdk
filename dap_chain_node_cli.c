/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h> // for close
#include <fcntl.h>
//#include <sys/poll.h>
//#include <sys/select.h>
#include <netinet/in.h>
#include <sys/un.h>
#define closesocket close
typedef int SOCKET;
#define SOCKET_ERROR    -1  // for win32 =  (-1)
#define INVALID_SOCKET  -1  // for win32 =  (SOCKET)(~0)
// for Windows
#else
#include <winsock2.h>
#include <WS2tcpip.h>
#endif

#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_node_cli.h"

//#include "dap_chain_node_cli.h"

#define LOG_TAG "chain_node_cli"

#define SOCKET_FILE "/opt/kelvin-node/var/run/node_cli.sock"

static SOCKET server_sockfd = -1;
/**
 * threading function for processing a request from a client
 */
static void* thread_one_client_func(void *args)
{
    return NULL;
}

/**
 * main threading server function
 */
static void* thread_main_func(void *args)
{
    SOCKET sockfd = (SOCKET) (intptr_t) args;
    SOCKET newsockfd;
    // wait of clients
    while(1)
    {
        pthread_t threadId;
        struct sockaddr_in peer;
        socklen_t size = sizeof(peer);
        // received a new connection request
        if((newsockfd = accept(sockfd, (struct sockaddr*) &peer, &size)) == (SOCKET) -1) {
            log_it(L_ERROR, "new connection break newsockfd=%d", newsockfd);
            break;
        }
        log_it(L_INFO, "new connection newsockfd=%d", newsockfd);

        // create child thread for a client connection
        pthread_create(&threadId, NULL, thread_one_client_func, (void*) (intptr_t) newsockfd);
        // in order to thread not remain in state "dead" after completion
        pthread_detach(threadId);
    };
    // закрыть соединение
    int cs = closesocket(sockfd);
    log_it(L_INFO, "Exit server thread socket=%d closesocket=%d\n", sockfd, cs);
    return NULL;
}

/**
 * Initialization of the server side of the interaction
 * with the console kelvin-node-cli
 *
 * return 0 if OK, -1 error
 */
int dap_chain_node_cli_init(dap_config_t * g_config)
{
    struct sockaddr_un server = { AF_UNIX, SOCKET_FILE };
    //server.sun_family = AF_UNIX;
    //strcpy(server.sun_path, SOCKET_FILE);

    SOCKET sockfd;

    if(server_sockfd >= 0) {
        dap_chain_node_cli_delete();
        server_sockfd = 0;
    }

    // create socket
    if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == INVALID_SOCKET)
        return -1;
    int gdsg = sizeof(struct sockaddr_un);
    if( access( SOCKET_FILE, R_OK ) != -1 )
    {
        unlink(SOCKET_FILE);
    }
    // connecting the address with a socket
    if(bind(sockfd, (const struct sockaddr*) &server, sizeof(struct sockaddr_un)) == SOCKET_ERROR) {
        log_it(L_ERROR, "Server can't start(err=%d). may be file=%s absent", errno, SOCKET_FILE);
        closesocket(sockfd);
        return -1;
    }
    else
        log_it(L_INFO, "Server start sock-file=%s", SOCKET_FILE);
    // turn on reception of connections
    if(listen(sockfd, 5) == SOCKET_ERROR)
        return -1;
    // create thread for waiting of clients
    pthread_t threadId;
    if(pthread_create(&threadId, NULL, thread_main_func, (void*) (intptr_t) sockfd) != 0) {
        closesocket(sockfd);
        return -1;
    }
    // in order to thread not remain in state "dead" after completion
    pthread_detach(threadId);
    server_sockfd = sockfd;
    return 0;
}

/**
 * Deinitialization of the server side
 *
 */
void dap_chain_node_cli_delete(void)
{
    if(server_sockfd >= 0)
        closesocket(server_sockfd);
}
