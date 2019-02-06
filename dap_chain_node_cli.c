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
#include <glib.h>

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
#include "dap_chain_node_cli.h"

//#include "dap_chain_node_cli.h"

#define LOG_TAG "chain_node_cli"

static SOCKET server_sockfd = -1;

/**
 * find option value
 */
static bool find_option_val(const char** argv, int arg_start, int arg_end, const char *opt_name, const char **opt_value)
{
    int arg_index = arg_start;
    int arg_character, on_or_off, next_arg, i;
    char *arg_string;

    while(arg_index < arg_end)
    {
        arg_string = (char *) argv[arg_index];
        // find opt_name
        if(arg_string && opt_name && !strcmp(arg_string, opt_name)) {
            // find opt_value
            if(opt_value) {
                arg_string = (char *) argv[++arg_index];
                if(arg_string) {
                    *opt_value = arg_string;
                    return true;
                }
            }
            else
                // need only opt_name
                return true;
        }
        arg_index++;
    }
    return false;
}

static int com_global_db(int argc, const char ** argv, char **str_reply)
{
    printf("com_global_db\n");
    return 0;
}

/**
 * Node command
 */
static int com_node(int argc, const char ** argv, char **str_reply)
{
    for(int i = 0; i < argc; i++)
        printf("com_node i=%d str=%s\n", i, argv[i]);
    if(str_reply)
        *str_reply = g_strdup("text");
    return 0;
}

/**
 * Traceroute command
 *
 * return 0 OK, -1 Err
 */
static int com_traceroute(int argc, const char** argv, char **str_reply)
{
    const char *addr = NULL;
    int hops = 0, time_usec = 0;
    if(argc > 1)
        addr = argv[1];
    iputils_set_verbose();
    int res = (addr) ? traceroute_util(addr, &hops, &time_usec) : -EADDRNOTAVAIL;
    if(res >= 0) {
        if(str_reply)
            *str_reply = g_strdup_printf("traceroute %s hops=%d time=%.1lf ms", addr, hops, time_usec * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                *str_reply = g_strdup_printf("traceroute %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case 2:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "Unknown traceroute module");
                break;
            case 3:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "first hop out of range");
                break;
            case 4:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "max hops cannot be more than 255");
                break;
            case 5:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "no more than 10 probes per hop");
                break;
            case 6:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "bad wait specifications");
                break;
            case 7:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "too big packetlen ");
                break;
            case 8:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr,
                        "IP version mismatch in addresses specified");
                break;
            case 9:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "bad sendtime");
                break;
            case 10:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "init_ip_options");
                break;
            case 11:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "calloc");
                break;
            case 12:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "parse cmdline");
                break;
            case 13:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "trace method's init failed");
                break;
            default:
                *str_reply = g_strdup_printf("traceroute %s error(%d)", addr, res);
            }
        }
    }
    return res;
}

/**
 * Tracepath command
 *
 * return 0 OK, -1 Err
 */
static int com_tracepath(int argc, const char** argv, char **str_reply)
{
    const char *addr = NULL;
    int hops = 0, time_usec = 0;
    if(argc > 1)
        addr = argv[1];
    iputils_set_verbose();
    int res = (addr) ? tracepath_util(addr, &hops, &time_usec) : -EADDRNOTAVAIL;
    if(res >= 0) {
        if(str_reply)
            *str_reply = g_strdup_printf("tracepath %s hops=%d time=%.1lf ms", addr, hops, time_usec * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                *str_reply = g_strdup_printf("tracepath %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case ESOCKTNOSUPPORT:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't create socket");
                break;
            case 2:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IPV6_MTU_DISCOVER");
                break;
            case 3:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IPV6_RECVERR");
                break;
            case 4:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IPV6_HOPLIMIT");
                break;
            case 5:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IP_MTU_DISCOVER");
                break;
            case 6:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IP_RECVERR");
                break;
            case 7:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IP_RECVTTL");
                break;
            case 8:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "malloc");
                break;
            case 9:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IPV6_UNICAST_HOPS");
                break;
            case 10:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IP_TTL");
                break;
            default:
                *str_reply = g_strdup_printf("tracepath %s error(%d)", addr, res);
            }
        }
    }
    return res;
}

/**
 * Ping command
 *
 * return 0 OK, -1 Err
 */
static int com_ping(int argc, const char** argv, char **str_reply)
{
    const char *addr = NULL;
    int n = 4;
    if(argc > 1)
        addr = argv[1];
    const char *n_str = NULL;
    if(find_option_val(argv, 2, argc, "-n", &n_str))
        n = (n_str) ? atoi(n_str) : 4;
    else if(find_option_val(argv, 2, argc, "-c", &n_str))
        n = (n_str) ? atoi(n_str) : 4;
    if(n <= 1)
        n = 1;
    iputils_set_verbose();
    int res = (addr) ? ping_util(addr, n) : -EADDRNOTAVAIL;
    if(res >= 0) {
        if(str_reply)
            *str_reply = g_strdup_printf("ping %s time=%.1lf ms", addr, res * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EDESTADDRREQ:
                *str_reply = g_strdup_printf("ping %s error: %s", addr, "Destination address required");
                break;
            case EADDRNOTAVAIL:
                *str_reply = g_strdup_printf("ping %s error: %s", (addr) ? addr : "",
                        (addr) ? "Host not found" : "Host not defined");
                break;
            case EPFNOSUPPORT:
                *str_reply = g_strdup_printf("ping %s error: %s", addr, "Unknown protocol family");
                break;
            default:
                *str_reply = g_strdup_printf("ping %s error(%d)", addr, -res);
            }
        }
    }
    return res;
}

/**
 * Help command
 */
static int com_help(int argc, const char ** argv, char **str_reply)
{
    if(argc > 1) {
        const COMMAND *cmd = find_command(argv[1]);
        if(cmd)
        {
            if(str_reply)
                *str_reply = g_strdup(cmd->doc);
            return 1;
        }
        if(str_reply)
            *str_reply = g_strdup_printf("command \"%s\" not recognized", argv[1]);
    }
    if(str_reply)
        *str_reply = g_strdup("command not defined, enter \"help <cmd name>\"");
    return -1;
}

static const COMMAND commands[] = {
    { "global_db", com_global_db, "Work with database" },
    { "node", com_node, "Work with node" },
    { "ping", com_ping, "Ping utility" },
    { "traceroute", com_traceroute, "Traceroute utility" },
    { "tracepath", com_tracepath, "Tracepath utility" },
    { "help", com_help, "Display this text" },
    { "?", com_help, "Synonym for `help'" },
    { (char *) NULL, (cmdfunc_t *) NULL, (char *) NULL }
};

/**
 *  Look up NAME as the name of a command, and return a pointer to that
 *  command.  Return a NULL pointer if NAME isn't a command name.
 */
const COMMAND* find_command(const char *name)
{
    register int i;

    for(i = 0; commands[i].name; i++)
        if(strcmp(name, commands[i].name) == 0)
            return (&commands[i]);

    return ((COMMAND *) NULL);
}

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
        int res = recv(sock, buf, 1, MSG_PEEK); // MSG_PEEK  The data is treated as unread and the next recv() function shall still return this data.
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
int s_recv(SOCKET sock, unsigned char *buf, int bufsize, int timeout)
{
    struct pollfd fds;
    int res;
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
        printf("[s_recv] recv()=%d errno=%d\n", res, errno);
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
    int nRecv = 0; // count of bytes received
    int stop_str_len = (stop_str) ? strlen(stop_str) : 0;
// if there is nothing to look for
    if(!stop_str_len)
        return NULL;
    int lpszBuffer_len = 256;
    char *lpszBuffer = calloc(1, lpszBuffer_len);
// received string will not be larger than MAX_REPLY_LEN
    while(1) //nRecv < MAX_REPLY_LEN)
    {
// read one byte
        int ret = s_recv(nSocket, (unsigned char *) (lpszBuffer + nRecv), 1, timeout);
//int ret = recv(nSocket,lpszBuffer+nRecv,1, 0);
        if(ret <= 0)
                {
            break;
        }
        nRecv += ret;
//printf("**debug** socket=%d read  %d bytes '%0s'",nSocket, ret, (lpszBuffer + nRecv));
        while((nRecv + 1) >= lpszBuffer_len)
        {
            lpszBuffer_len *= 2;
            lpszBuffer = (char*) realloc(lpszBuffer, lpszBuffer_len);
        }
// search for the required string
        if(nRecv >= stop_str_len) {
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
            lpszBuffer[nRecv - stop_str_len] = '\0';
            if(dwLen)
                *dwLen = nRecv - stop_str_len;
        }
        else {
            lpszBuffer[nRecv] = '\0';
            if(dwLen)
                *dwLen = nRecv;
        }
        lpszBuffer = realloc(lpszBuffer, *dwLen + 1);
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
    GList *cmd_param_list = NULL;
    while(1)
    {
// wait data from client
        int is_data = s_poll(newsockfd, timeout);
//printf("is data=%d sockfd=%d \n", is_data, newsockfd);
// timeout
        if(!is_data)
            continue;
// error (may be socket closed)
        if(is_data < 0)
            break;

        int is_valid = is_valid_socket(newsockfd);
        if(!is_valid)
        {
            //printf("isvalid=%d sockfd=%d \n", is_valid, newsockfd);
            break;
        }
// receiving http header
        char *str_header = s_get_next_str(newsockfd, &str_len, "\r\n", true, timeout);
//printf("str_header='%s' sock=%d\n", str_header, newsockfd);
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
            cmd_param_list = g_list_append(cmd_param_list, str_header);
            //printf("g_list_append argc=%d command=%s ", argc, str_header);
            argc++;
        }
        else
            free(str_header);
        if(marker == 2) {
            GList *list = cmd_param_list;
            // form command
            guint argc = g_list_length(list);
            // command is found
            if(argc >= 1) {
                char *cmd_name = list->data;
                list = g_list_next(list);
                // execute command
                char *str_cmd = g_strdup_printf("%s", cmd_name);
                const COMMAND *command = find_command(cmd_name);
                if(command)
                {
                    while(list) {
                        str_cmd = g_strdup_printf("%s;%s", str_cmd, list->data);
                        list = g_list_next(list);
                    }
                    log_it(L_INFO, "execute command=%s", str_cmd);
                    // exec command
                    int res = 0;
                    char **argv = g_strsplit(str_cmd, ";", -1);
                    char *str_reply = NULL;
                    // Call the command function
                    if(command && command->func)
                        res = (*(command->func))(argc, (const char **) argv, &str_reply);
                    g_strfreev(argv);
                    gchar *reply_body = g_strdup_printf("%d\r\n%s\r\n", res, (str_reply) ? str_reply : "");
                    // return the result of the command function
                    gchar *reply_str = g_strdup_printf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s",
                            strlen(reply_body), reply_body);
                    int ret = send(newsockfd, reply_str, strlen(reply_str), 1000);
                    g_free(str_reply);
                    g_free(reply_str);
                    g_free(reply_body);
                }
                else
                {
                    log_it(L_ERROR, "can't recognize command=%s", str_cmd);
                }
                g_free(str_cmd);
            }
            g_list_free_full(cmd_param_list, free);
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
}
