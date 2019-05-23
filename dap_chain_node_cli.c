/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
//#include <glib.h>

#ifndef _WIN32
#include <poll.h>
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

#include "iputils/iputils.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli.h"

//#include "dap_chain_node_cli.h"

#define LOG_TAG "chain_node_cli"

static SOCKET server_sockfd = -1;

static dap_chain_node_cmd_item_t * s_commands = NULL;


/**
 * Wait for data
 * timeout -  timeout in ms
 * [Specifying a negative value in timeout means an infinite timeout.]
 * [Specifying a timeout of zero causes poll() to return immediately, even if no file descriptors are ready.]
 * return zero if the time limit expired
 * return: >0 if data is present to read
 * return: -1 if error
 */
static int s_poll(int socket, int timeout)
{
    struct pollfd fds;
    int res;
    fds.fd = socket;
    // POLLIN - received data
    // POLLNVAL - closed the socket on our side
    // POLLHUP - closed the socket on another side (does not work! Received POLLIN and the next reading returns 0 bytes)
    fds.events = POLLIN; // | | POLLNVAL | POLLHUP | POLLERR | POLLPRI
    res = poll(&fds, 1, timeout);

    // since POLLIN=(POLLRDNORM | POLLRDBAND), then maybe revents=POLLRDNORM
    if(res == 1 && !(fds.revents & POLLIN)) //if(res==1 && fds.revents!=POLLIN)
        return -1;
    return res;
}

/**
 * Check socket for validity
 */
static bool is_valid_socket(SOCKET sock)
{
    struct pollfd fds;
    fds.fd = sock;
    fds.events = POLLIN;
    // return: -1 err, 0 timeout, 1 waited
    int count_desc = poll(&fds, 1, 0);
    // error
    if(count_desc == -1)
        return false;
    // event with an error code
    if(count_desc > 0)
            {
        // feature of disconnection under Windows
        // under Windows, with socket closed fds.revents=POLLHUP, in Unix fds.events = POLLIN
        if(fds.revents & (POLLERR | POLLHUP | POLLNVAL))
            return false;
        // feature of disconnection under Unix (QNX)
        // under Windows, with socket closed res = 0, in Unix res = -1
        char buf[2];
        long res = recv(sock, buf, 1, MSG_PEEK); // MSG_PEEK  The data is treated as unread and the next recv() function shall still return this data.
        if(res < 0)
            return false;
        // data in the buffer must be(count_desc>0), but read 0 bytes(res=0)
        if(!res && (fds.revents & POLLIN))
            return false;
    }
    return true;
}

/**
 * Read from socket
 *
 * timeout in milliseconds
 * return the number of read bytes (-1 err or -2 timeout)
 */
long s_recv(SOCKET sock, unsigned char *buf, size_t bufsize, int timeout)
{
    struct pollfd fds;
    long res;
    fds.fd = sock;
    fds.events = POLLIN; // | POLLNVAL | POLLHUP | POLLERR | POLLPRI;// | POLLRDNORM;//POLLOUT |
    res = poll(&fds, 1, timeout);
    if(res == 1 && !(fds.revents & POLLIN))
        return -1;
    if(!res) // timeout
        return -2;
    if(res < 1) {
        return -1;
    }
    //    res = read(sock, (char*) buf, bufsize);
    res = recv(sock, (char*) buf, bufsize, 0); //MSG_WAITALL
    if(res <= 0) { //EINTR=4  ENOENT=2 EINVAL=22 ECONNRESET=254
        printf("[s_recv] recv()=%ld errno=%d\n", res, errno);
    }
    return res;
}

/**
 * Reading from the socket till arrival the specified string
 *
 * stop_str - string to which reading will continue
 * del_stop_str - удалять ли строку для поиска в конце
 * timeout - in ms
 * return: string (if waited for final characters) or NULL, if the string requires deletion
 */
char* s_get_next_str(SOCKET nSocket, int *dwLen, const char *stop_str, bool del_stop_str, int timeout)
{
    bool bSuccess = false;
    long nRecv = 0; // count of bytes received
    size_t stop_str_len = (stop_str) ? strlen(stop_str) : 0;
    // if there is nothing to look for
    if(!stop_str_len)
        return NULL;
    size_t lpszBuffer_len = 256;
    char *lpszBuffer = DAP_NEW_Z_SIZE(char, lpszBuffer_len);
    // received string will not be larger than MAX_REPLY_LEN
    while(1) //nRecv < MAX_REPLY_LEN)
    {
        // read one byte
        long ret = s_recv(nSocket, (unsigned char *) (lpszBuffer + nRecv), 1, timeout);
        //int ret = recv(nSocket,lpszBuffer+nRecv,1, 0);
        if(ret <= 0)
                {
            break;
        }
        nRecv += ret;
        //printf("**debug** socket=%d read  %d bytes '%0s'",nSocket, ret, (lpszBuffer + nRecv));
        while((nRecv + 1) >= (long) lpszBuffer_len)
        {
            lpszBuffer_len *= 2;
            lpszBuffer = (char*) realloc(lpszBuffer, lpszBuffer_len);
        }
        // search for the required string
        if(nRecv >=  (long) stop_str_len) {
            // found the required string
            if(!strncasecmp(lpszBuffer + nRecv - stop_str_len, stop_str, stop_str_len)) {
                bSuccess = true;
                break;
            }
        }
    };
    // end reading
    if(bSuccess) {
        // delete the searched string
        if(del_stop_str) {
            lpszBuffer[nRecv -  (long) stop_str_len] = '\0';
            if(dwLen)
                *dwLen =(int) nRecv - (int) stop_str_len;
        }
        else {
            lpszBuffer[nRecv] = '\0';
            if(dwLen)
                *dwLen = (int) nRecv;
        }
        lpszBuffer = DAP_REALLOC(lpszBuffer,(size_t) *dwLen + 1);
        return lpszBuffer;
    }
    // in case of an error or missing string
    if(dwLen)
        *dwLen = 0;
    free(lpszBuffer);
    return NULL;
}

/**
 * threading function for processing a request from a client
 */
static void* thread_one_client_func(void *args)
{
    SOCKET newsockfd = (SOCKET) (intptr_t) args;
    log_it(L_INFO, "new connection sockfd=%d", newsockfd);

    int str_len, marker = 0;
    int timeout = 5000; // 5 sec
    char **argv = NULL;
    int argc = 0;
    dap_list_t *cmd_param_list = NULL;
    while(1)
    {
        // wait data from client
        int is_data = s_poll(newsockfd, timeout);
        // timeout
        if(!is_data)
            continue;
        // error (may be socket closed)
        if(is_data < 0)
            break;

        int is_valid = is_valid_socket(newsockfd);
        if(!is_valid)
        {
            break;
        }
        // receiving http header
        char *str_header = s_get_next_str(newsockfd, &str_len, "\r\n", true, timeout);
        // bad format
        if(!str_header)
            break;
        if(str_header && strlen(str_header) == 0) {
            marker++;
            if(marker == 1)
                continue;
        }
        // filling parameters of command
        if(marker == 1) {
            cmd_param_list = dap_list_append(cmd_param_list, str_header);
            //printf("g_list_append argc=%d command=%s ", argc, str_header);
            argc++;
        }
        else
            free(str_header);
        if(marker == 2) {
            dap_list_t *list = cmd_param_list;
            // form command
            unsigned int argc = dap_list_length(list);
            // command is found
            if(argc >= 1) {
                char *cmd_name = list->data;
                list = dap_list_next(list);
                // execute command
                char *str_cmd = dap_strdup_printf("%s", cmd_name);
                dap_chain_node_cmd_item_t *l_cmd = dap_chain_node_cli_cmd_find(cmd_name);
                int res = -1;
                char *str_reply = NULL;
                if(l_cmd){
                    while(list) {
                        str_cmd = dap_strdup_printf("%s;%s", str_cmd, list->data);
                        list = dap_list_next(list);
                    }
                    log_it(L_INFO, "execute command=%s", str_cmd);
                    // exec command

                    char **argv = dap_strsplit(str_cmd, ";", -1);
                    // Call the command function
                    if(l_cmd && l_cmd->func)
                        res = (*(l_cmd->func))(argc, (const char **) argv, &str_reply);
                    else {
                        log_it(L_WARNING,"No function for command \"%s\" but it registred?!", str_cmd);
                    }
                    dap_strfreev(argv);
                } else {
                    str_reply = dap_strdup_printf("can't recognize command=%s", str_cmd);
                    log_it(L_ERROR, str_reply);
                }
                char *reply_body = dap_strdup_printf("ret_code: %d\r\n%s\r\n", res, (str_reply) ? str_reply : "");
                // return the result of the command function
                char *reply_str = dap_strdup_printf("HTTP/1.1 200 OK\r\n"
                                                    "Content-Length: %d\r\n\r\n"
                                                    "%s",
                        strlen(reply_body), reply_body);
                int ret = send(newsockfd, reply_str, strlen(reply_str) ,0);
                DAP_DELETE(str_reply);
                DAP_DELETE(reply_str);
                DAP_DELETE(reply_body);

                DAP_DELETE(str_cmd);
            }
            dap_list_free_full(cmd_param_list, free);
            break;
        }
    }
    // close connection
    int cs = closesocket(newsockfd);
    log_it(L_INFO, "close connection=%d sockfd=%d", cs, newsockfd);
    return NULL;
}

/**
 * main threading server function
 */
static void* thread_main_func(void *args)
{
    SOCKET sockfd = (SOCKET) (intptr_t) args;
    SOCKET newsockfd;
    log_it(L_INFO, "Server start socket=%s", UNIX_SOCKET_FILE);
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
        // create child thread for a client connection
        pthread_create(&threadId, NULL, thread_one_client_func, (void*) (intptr_t) newsockfd);
        // in order to thread not remain in state "dead" after completion
        pthread_detach(threadId);
    };
    // close connection
    int cs = closesocket(sockfd);
    log_it(L_INFO, "Exit server thread=%d socket=%d", cs, sockfd);
    return NULL;
}

/**
 * Write text to reply string
 */
void dap_chain_node_cli_set_reply_text(char **str_reply, const char *str, ...)
{
    if(str_reply) {
        if(*str_reply) {
            assert(! *str_reply );
            DAP_DELETE(*str_reply);
            *str_reply = NULL;
        }
        va_list args;
        va_start(args, str);
        *str_reply = dap_strdup_vprintf(str, args); //*str_reply = dap_strdup(str);
        va_end(args);
    }
}

/**
 * find option value
 *
 * return index of string in argv, or 0 if not found
 */
int dap_chain_node_cli_find_option_val(const char** argv, int arg_start, int arg_end, const char *opt_name, const char **opt_value)
{
    int arg_index = arg_start;
    const char *arg_string;

    while(arg_index < arg_end)
    {
        arg_string = argv[arg_index];
        // find opt_name
        if(arg_string && opt_name && !strcmp(arg_string, opt_name)) {
            // find opt_value
            if(opt_value) {
                arg_string = argv[++arg_index];
                if(arg_string) {
                    *opt_value = arg_string;
                    return arg_index;
                }
            }
            else
                // need only opt_name
                return arg_index;
        }
        arg_index++;
    }
    return 0;
}

/**
 * @brief s_cmd_item_create
 * @param a_name
 * @param func
 * @param doc
 * @param doc_ex
 * @return
 */
void dap_chain_node_cli_cmd_item_create(const char * a_name, cmdfunc_t *a_func, const char *a_doc, const char *a_doc_ex)
{
    dap_chain_node_cmd_item_t *l_cmd_item = DAP_NEW_Z(dap_chain_node_cmd_item_t);
    snprintf(l_cmd_item->name,sizeof (l_cmd_item->name),"%s",a_name);
    l_cmd_item->doc = strdup( a_doc);
    l_cmd_item->doc_ex = strdup( a_doc_ex);
    l_cmd_item->func = a_func;
    HASH_ADD_STR(s_commands,name,l_cmd_item);
    log_it(L_DEBUG,"Added command %s",l_cmd_item->name);
}

/**
 * @brief dap_chain_node_cli_command_get_first
 * @return
 */
dap_chain_node_cmd_item_t* dap_chain_node_cli_cmd_get_first()
{
    return s_commands;
}

/**
 * @brief dap_chain_node_cli_command_find
 * @param a_name
 * @return
 */
dap_chain_node_cmd_item_t* dap_chain_node_cli_cmd_find(const char *a_name)
{
    dap_chain_node_cmd_item_t *l_cmd_item = NULL;
    HASH_FIND_STR(s_commands,a_name,l_cmd_item);
    return l_cmd_item;
}


/**
 * Initialization of the server side of the interaction
 * with the console kelvin-node-cli
 *
 * return 0 if OK, -1 error
 */
int dap_chain_node_cli_init(dap_config_t * g_config)
{
    struct sockaddr_un server = { AF_UNIX, UNIX_SOCKET_FILE };
    //server.sun_family = AF_UNIX;
    //strcpy(server.sun_path, SOCKET_FILE);
    dap_chain_node_cli_cmd_item_create ("global_db", com_global_db, "Work with global database",
           "global_db wallet_info set -addr <wallet address> -cell <cell id> \n\n"
           "global_db cells add -cell <cell id> \n\n"
           "global_db node add  -net <net name> -addr {<node address> | -alias <node alias>} -cell <cell id>  {-ipv4 <ipv4 external address> | -ipv6 <ipv6 external address>}\n\n"
                    "global_db node del  -net <net name> -addr <node address> | -alias <node alias>\n\n"
                    "global_db node link {add|del}  -net <net name> {-addr <node address> | -alias <node alias>} -link <node address>\n\n"
                        );
    dap_chain_node_cli_cmd_item_create ("node", com_node, "Work with node",
            "node alias {<node address> | -alias <node alias>}\n\n"
                    "node connect {<node address> | -alias <node alias>}\n\n"
                    "node handshake {<node address> | -alias <node alias>}\n"
                    "node dump -net <net name> [ -addr <node address> | -alias <node alias>]\n\n"
                                        );
    dap_chain_node_cli_cmd_item_create ("ping", com_ping, "Send ICMP ECHO_REQUEST to network hosts",
            "ping [-c <count>] host\n");
    dap_chain_node_cli_cmd_item_create ("traceroute", com_traceroute, "Print the hops and time of packets trace to network host",
            "traceroute host\n");
    dap_chain_node_cli_cmd_item_create ("tracepath", com_tracepath, "Traces path to a network host along this path",
            "tracepath host\n");
    dap_chain_node_cli_cmd_item_create ("help", com_help, "Description of command parameters",
                                        "help [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_chain_node_cli_cmd_item_create ("?", com_help, "Synonym for \"help\"",
                                        "? [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_chain_node_cli_cmd_item_create("wallet", com_tx_wallet, "Wallet operations",
            "wallet [new -w <wallet_name> | list | info -addr <addr> -w <wallet_name> -net <net_name>]\n");

    // Token commands
    dap_chain_node_cli_cmd_item_create ("token_decl", com_token_decl, "Token declaration",
            "token_decl -net <net name> -chain <chain name> token <token ticker> total_supply <total supply> signs_total <sign total> signs_emission <signs for emission> certs <certs list>\n"
            "\t Declare new token for <netname>:<chain name> with ticker <token ticker>, maximum emission <total supply> and <signs for emission> from <signs total> signatures on valid emission\n"
            "token_decl_sign -net <net name> -chain <chain name> datum <datum_hash>  certs <certs list>\n"
            "\t Sign existent <datum hash> in mempool with <certs list>\n"
            );

    dap_chain_node_cli_cmd_item_create ("token_decl_sign", com_token_decl_sign, "Token declaration add sign",
            "token_decl_sign -net <net name> -chain <chain name> datum <datum_hash>  certs <certs list>\n"
            "\t Sign existent <datum hash> in mempool with <certs list>\n"
            );

    dap_chain_node_cli_cmd_item_create ("token_emit", com_token_emit, "Token emission",
            "token_emit -net <net name> -chain_emission <chain for emission> -chain_base_tx <chain for base tx> -addr <addr> token <token ticker> -certs <cert> -emission_value <val>\n");

    dap_chain_node_cli_cmd_item_create ("mempool_list", com_mempool_list, "List mempool entries for selected chain network and chain id",
            "mempool_list -net <net name> -chain <chain name>\n");

    dap_chain_node_cli_cmd_item_create ("mempool_proc", com_mempool_proc, "Proc mempool entries for selected chain network and chain id",
            "mempool_proc -net <net name> -chain <chain name>\n");

    dap_chain_node_cli_cmd_item_create ("mempool_delete", com_mempool_delete, "Delete datum with hash <datum hash>",
            "mempool_delete -net <net name> -chain <chain name> -datum <datum hash>\n");


    // Transaction commands
    dap_chain_node_cli_cmd_item_create ("tx_create", com_tx_create, "Make transaction",
            "tx_create -net <net name> -chain <chain name> -from_wallet <name> -to_addr <addr> -token <token ticker> -value <value> [-fee <addr> -value_fee <val>]\n" );
    dap_chain_node_cli_cmd_item_create ("tx_cond_create", com_tx_cond_create, "Make cond transaction",
            "tx_cond_create todo\n" );
    dap_chain_node_cli_cmd_item_create ("tx_verify", com_tx_verify, "Verifing transaction",
            "tx_verify  -wallet <wallet name> [-path <wallet path>]\n" );

    // Log
    dap_chain_node_cli_cmd_item_create ("print_log", com_print_log, "Print log info",
                "print_log [ts_after <timestamp >] [limit <line numbers>]\n" );


    // init client for handshake

    SOCKET sockfd;

    if(server_sockfd >= 0) {
        dap_chain_node_cli_delete();
        server_sockfd = 0;
    }

    // create socket
    if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == INVALID_SOCKET)
        return -1;
    int gdsg = sizeof(struct sockaddr_un);
    if(access( UNIX_SOCKET_FILE, R_OK) != -1)
            {
        unlink(UNIX_SOCKET_FILE);
    }
    // connecting the address with a socket
    if(bind(sockfd, (const struct sockaddr*) &server, sizeof(struct sockaddr_un)) == SOCKET_ERROR) {
        // errno = EACCES  13  Permission denied
        if(errno == EACCES) // EACCES=13
            log_it(L_ERROR, "Server can't start(err=%d). Can't create file=%s [Permission denied]", errno,
                    UNIX_SOCKET_FILE);
        else
            log_it(L_ERROR, "Server can't start(err=%d). May be problem with file=%s?", errno, UNIX_SOCKET_FILE);
        closesocket(sockfd);
        return -1;
    }
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

    // deinit client for handshake
    dap_chain_node_client_deinit();
}
