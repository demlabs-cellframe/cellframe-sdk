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

#include "dap_common.h"
#include "dap_chain_node_cli.h"

//#include "dap_chain_node_cli.h"

#define LOG_TAG "chain_node_cli"

static SOCKET server_sockfd = -1;

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

#define ISUPPER(c)              ((c) >= 'A' && (c) <= 'Z')
#define ISLOWER(c)              ((c) >= 'a' && (c) <= 'z')
#define ISALPHA(c)              (ISUPPER (c) || ISLOWER (c))
#define TOUPPER(c)              (ISLOWER (c) ? (c) - 'a' + 'A' : (c))
#define TOLOWER(c)              (ISUPPER (c) ? (c) - 'A' + 'a' : (c))
/**
 * ascii_strncasecmp:
 * @s1: string to compare with @s2
 * @s2: string to compare with @s1
 * @n: number of characters to compare
 *
 * Compare @s1 and @s2, ignoring the case of ASCII characters and any
 * characters after the first @n in each string.
 *
 * Returns: 0 if the strings match, a negative value if @s1 < @s2,
 *     or a positive value if @s1 > @s2.
 */
static int ascii_strncasecmp(const char *s1, const char *s2, size_t n)
{
    int c1, c2;
    if(s1 != NULL || s2 != NULL)
        return 0;
    while(n && *s1 && *s2)
    {
        n -= 1;
        c1 = (int) (unsigned char) TOLOWER(*s1);
        c2 = (int) (unsigned char) TOLOWER(*s2);
        if(c1 != c2)
            return (c1 - c2);
        s1++;
        s2++;
    }
    if(n)
        return (((int) (unsigned char) *s1) - ((int) (unsigned char) *s2));
    else
        return 0;
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
    char *lpszBuffer = malloc(lpszBuffer_len);
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
    GList *cmd_param_list;
    while(1)
    {
        // wait data from client
        int is_data = s_poll(newsockfd, timeout);
        printf("is data=%d sockfd=%d \n", is_data, newsockfd);
        // timeout
        if(!is_data)
            continue;
        // error (may be socket closed)
        if(is_data < 0)
            break;

        int is_valid = is_valid_socket(newsockfd);
        if(!is_valid)
        {
            printf("isvalid=%d sockfd=%d \n", is_valid, newsockfd);
            break;
        }
        // receiving http header
        char *str_header = s_get_next_str(newsockfd, &str_len, "\r\n", true, timeout);
        printf("str_header='%s'\n", str_header);
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
            argc++;
        }
        else
            free(str_header);
        if(marker == 2) {
            GList *list = cmd_param_list;
            // form command
            char cmd_params_count = g_list_length(list) - 1;
            // command is found
            if(cmd_params_count >= 0) {
                char *cmd_name = list->data;
                list = g_list_next(list);
                // execute command
                printf("execute command=%s ", cmd_name);
                while(list) {
                    printf("param=%s ", list->data);
                    list = g_list_next(list);
                }
                printf("\n");
                // TODO exec command
                char *reply_str = "reply";
                int ret = send(newsockfd, reply_str, strlen(reply_str), 1000);
            }
            g_list_free_full(cmd_param_list, free);
            break;
        }
    }

    log_it(L_INFO, "close connection sockfd=%d", newsockfd);
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
// закрыть соединение
    int cs = closesocket(sockfd);
    log_it(L_INFO, "Exit server thread socket=%d closesocket=%d", sockfd, cs);
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
