/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe  https://cellframe.net
 * Copyright  (c) 2019-2021
 * All rights reserved.

 This file is part of Cellframe SDK

 Cellframe SDK is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Cellframe SDK is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
//#include <glib.h>
#include <unistd.h>

#ifndef _WIN32
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
//#include <unistd.h> // for close
#include <fcntl.h>
//#include <sys/poll.h>
//#include <sys/select.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/stat.h>
//#define closesocket close
//typedef int SOCKET;
//#define SOCKET_ERROR    -1  // for win32 =  (-1)
//#define INVALID_SOCKET  -1  // for win32 =  (SOCKET)(~0)
// for Windows
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "iputils/iputils.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_list.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_chain_node_cli.h"

//#include "dap_chain_node_cli.h"

#define LOG_TAG "chain_node_cli"

#define MAX_CONSOLE_CLIENTS 16

static SOCKET server_sockfd = -1; // network or local unix
uint32_t l_listen_port = 0;
bool s_debug_cli = false;

#ifdef _WIN32
  #define poll WSAPoll
#endif

static dap_chain_node_cmd_item_t * s_commands = NULL;

/**
 * @brief int s_poll
 * Wait for data
 * timeout -  timeout in ms
 * [Specifying a negative value in timeout means an infinite timeout.]
 * [Specifying a timeout of zero causes poll() to return immediately, even if no file descriptors are ready.]
 * return zero if the time limit expired
 * return: >0 if data is present to read
 * return: -1 if error
 * @param socket 
 * @param timeout 
 * @return int 
 */
static int s_poll( int socket, int timeout )
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
 * @brief is_valid_socket
 * Check socket for validity
 * @param sock 
 * @return true 
 * @return false 
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
 * @brief s_recv
 * timeout in milliseconds
 * return the number of read bytes (-1 err or -2 timeout)
 * @param sock 
 * @param buf 
 * @param bufsize 
 * @param timeout 
 * @return long 
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
 * @brief s_get_next_str
 * Reading from the socket till arrival the specified string
 *
 * stop_str - string to which reading will continue
 * del_stop_str - удалять ли строку для поиска в конце
 * timeout - in ms
 * return: string (if waited for final characters) or NULL, if the string requires deletion
 * @param nSocket 
 * @param dwLen 
 * @param stop_str 
 * @param del_stop_str 
 * @param timeout 
 * @return char* 
 */
char* s_get_next_str( SOCKET nSocket, int *dwLen, const char *stop_str, bool del_stop_str, int timeout )
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
        char * l_buf_realloc = DAP_REALLOC(lpszBuffer,(size_t) *dwLen + 1);
        if( l_buf_realloc)
            lpszBuffer = l_buf_realloc;
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
    if(s_debug_cli)
        log_it(L_DEBUG, "new connection sockfd=%"DAP_FORMAT_SOCKET, newsockfd);

    int str_len, marker = 0;
    int timeout = 5000; // 5 sec
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
            if(marker == 1){
                DAP_DELETE(str_header);
                continue;
            }
        }
        // filling parameters of command
        if(marker == 1) {
            cmd_param_list = dap_list_append(cmd_param_list, str_header);
            //printf("g_list_append argc=%d command=%s ", argc, str_header);
            argc++;
        }
        else
            DAP_DEL_Z(str_header);
        if(marker == 2 &&  cmd_param_list) {
            dap_list_t *list = cmd_param_list;
            // form command
            unsigned int argc = dap_list_length(list);
            // command is found
            if(argc >= 1) {
              int l_verbose = 0;
                char *cmd_name = list->data;
                list = dap_list_next(list);
                // execute command
                char *str_cmd = dap_strdup_printf("%s", cmd_name);
                dap_chain_node_cmd_item_t *l_cmd = dap_chain_node_cli_cmd_find(cmd_name);
                int res = -1;
                char *str_reply = NULL;
                if(l_cmd){
                    while(list) {
                        char *str_cmd_prev = str_cmd;
                        str_cmd = dap_strdup_printf("%s;%s", str_cmd, list->data);
                        list = dap_list_next(list);
                        DAP_DELETE(str_cmd_prev);
                    }
                    if(l_cmd->overrides.log_cmd_call)
                        l_cmd->overrides.log_cmd_call(str_cmd);
                    else
                        log_it(L_DEBUG, "execute command=%s", str_cmd);
                    // exec command

                    char **l_argv = dap_strsplit(str_cmd, ";", -1);
                    // Call the command function
                    if(l_cmd &&  l_argv && l_cmd->func) {
                        if (l_cmd->arg_func) {
                            res = l_cmd->func_ex(argc, l_argv, l_cmd->arg_func, &str_reply);
                        } else {
                            res = l_cmd->func(argc, l_argv, &str_reply);
                        }
                    } else if (l_cmd) {
                        log_it(L_WARNING,"NULL arguments for input for command \"%s\"", str_cmd);
                    }else {
                        log_it(L_WARNING,"No function for command \"%s\" but it registred?!", str_cmd);
                    }
                    // find '-verbose' command
                    l_verbose = dap_chain_node_cli_find_option_val(l_argv, 1, argc, "-verbose", NULL);
                    dap_strfreev(l_argv);
                } else {
                    str_reply = dap_strdup_printf("can't recognize command=%s", str_cmd);
                    log_it(L_ERROR, str_reply);
                }
                char *reply_body;
                if(l_verbose)
                  reply_body = dap_strdup_printf("%d\r\nret_code: %d\r\n%s\r\n", res, res, (str_reply) ? str_reply : "");
                else
                  reply_body = dap_strdup_printf("%d\r\n%s\r\n", res, (str_reply) ? str_reply : "");
                // return the result of the command function
                char *reply_str = dap_strdup_printf("HTTP/1.1 200 OK\r\n"
                                                    "Content-Length: %d\r\n\r\n"
                                                    "%s",
                        strlen(reply_body), reply_body);
                size_t l_reply_step = 32768;
                size_t l_reply_len = strlen(reply_str);
                size_t l_reply_rest = l_reply_len;
                while(l_reply_rest) {
                    size_t l_send_bytes = min(l_reply_step, l_reply_rest);
                    int ret = send(newsockfd, reply_str + l_reply_len - l_reply_rest, l_send_bytes, 0);
                    if(ret<=0)
                        break;
                    l_reply_rest-=l_send_bytes;
                };
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
    if (s_debug_cli)
        log_it(L_DEBUG, "close connection=%d sockfd=%"DAP_FORMAT_SOCKET, cs, newsockfd);
    return NULL;
}

#ifdef _WIN32

/**
 * @brief p_get_next_str
 * 
 * @param hPipe 
 * @param dwLen 
 * @param stop_str 
 * @param del_stop_str 
 * @param timeout 
 * @return char* 
 */
char *p_get_next_str( HANDLE hPipe, int *dwLen, const char *stop_str, bool del_stop_str, int timeout )
{
    UNUSED(timeout);
    bool bSuccess = false;
    long nRecv = 0; // count of bytes received
    size_t stop_str_len = (stop_str) ? strlen(stop_str) : 0;
    // if there is nothing to look for

    if(!stop_str_len)
        return NULL;

    size_t lpszBuffer_len = 256;
    char *lpszBuffer = DAP_NEW_Z_SIZE(char, lpszBuffer_len);
    // received string will not be larger than MAX_REPLY_LEN

    while( 1 ) //nRecv < MAX_REPLY_LEN)
    {
      long ret = 0;
        // read one byte
//        long ret = s_recv( nSocket, (unsigned char *) (lpszBuffer + nRecv), 1, timeout);

      bSuccess = ReadFile( hPipe, lpszBuffer + nRecv,
         lpszBuffer_len - nRecv, (LPDWORD)&ret, NULL );

        //int ret = recv(nSocket,lpszBuffer+nRecv,1, 0);
        if ( ret <= 0 || !bSuccess )
            break;

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
 * @brief thread_pipe_client_func
 * threading function for processing a request from a client
 * @param args 
 * @return void* 
 */
static void *thread_pipe_client_func( void *args )
{
    HANDLE hPipe = (HANDLE)args;

//    SOCKET newsockfd = (SOCKET) (intptr_t) args;
    if(s_debug_cli)
        log_it(L_INFO, "new connection pipe = %p", hPipe);

    int str_len, marker = 0;
    int timeout = 5000; // 5 sec
    int argc = 0;

    dap_list_t *cmd_param_list = NULL;

    while( 1 )
    {
        // wait data from client
//        int is_data = s_poll( newsockfd, timeout );
        // timeout
//        if(!is_data)
//            continue;
        // error (may be socket closed)
//        if(is_data < 0)
//            break;

//        int is_valid = is_valid_socket(newsockfd);
//        if(!is_valid)
//        {
//            break;
//        }

        // receiving http header
        char *str_header = p_get_next_str( hPipe, &str_len, "\r\n", true, timeout );

        // bad format
        if(!str_header)
            break;

        if ( str_header && strlen(str_header) == 0) {
            marker++;
            if(marker == 1)
                continue;
        }

        // filling parameters of command
        if ( marker == 1 ) {
            cmd_param_list = dap_list_append( cmd_param_list, str_header );
            //printf("g_list_append argc=%d command=%s ", argc, str_header);
            argc ++;
        }
        else
            free( str_header );

        if ( marker == 2 ) {

            dap_list_t *list = cmd_param_list;
            // form command

            unsigned int argc = dap_list_length( list );
            // command is found

            if ( argc >= 1) {

                int l_verbose = 0;
                char *cmd_name = list->data;
                list = dap_list_next( list );

                // execute command
                char *str_cmd = dap_strdup_printf( "%s", cmd_name );
                dap_chain_node_cmd_item_t *l_cmd = dap_chain_node_cli_cmd_find( cmd_name );
                int res = -1;
                char *str_reply = NULL;

                if ( l_cmd ) {

                    while( list ) {
                        str_cmd = dap_strdup_printf( "%s;%s", str_cmd, list->data );
                        list = dap_list_next(list);
                    }

                    log_it(L_INFO, "execute command = %s", str_cmd );
                    // exec command

                    char **l_argv = dap_strsplit( str_cmd, ";", -1 );
                    // Call the command function

                    if ( l_cmd &&  l_argv && l_cmd->func ) {
                        if (l_cmd->arg_func) {
                            res = l_cmd->func_ex(argc, l_argv, l_cmd->arg_func, &str_reply);
                        } else {
                            res = l_cmd->func(argc, l_argv, &str_reply);
                        }
                    }

                    else if ( l_cmd ) {
                        log_it(L_WARNING,"NULL arguments for input for command \"%s\"", str_cmd );
                    }else {
                        log_it(L_WARNING,"No function for command \"%s\" but it registred?!", str_cmd );
                    }

                    // find '-verbose' command
                    l_verbose = dap_chain_node_cli_find_option_val( l_argv, 1, argc, "-verbose", NULL );
                    dap_strfreev( l_argv );

                } else {
                    str_reply = dap_strdup_printf("can't recognize command = %s", str_cmd );
                    log_it( L_ERROR, str_reply );
                }

                char *reply_body;

                if(l_verbose)
                  reply_body = dap_strdup_printf("%d\r\nret_code: %d\r\n%s\r\n", res, res, (str_reply) ? str_reply : "");
                else
                  reply_body = dap_strdup_printf("%d\r\n%s\r\n", res, (str_reply) ? str_reply : "");

                // return the result of the command function
                char *reply_str = dap_strdup_printf( "HTTP/1.1 200 OK\r\n"
                                                    "Content-Length: %d\r\n\r\n"
                                                    "%s",
                        strlen(reply_body), reply_body );

                int ret;// = send( newsockfd, reply_str, strlen(reply_str) ,0 );

                WriteFile( hPipe, reply_str, strlen(reply_str), (LPDWORD)&ret, NULL );

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
//    int cs = closesocket(newsockfd);

    log_it( L_INFO, "close connection pipe = %p", hPipe );

    FlushFileBuffers( hPipe );
    DisconnectNamedPipe( hPipe );
    CloseHandle( hPipe );

    return NULL;
}


/**
 * @brief thread_pipe_func
 * main threading server function pipe win32
 * @param args 
 * @return void* 
 */
static void* thread_pipe_func( void *args )
{
   UNUSED(args);
   BOOL   fConnected = FALSE;
   pthread_t threadId;
   HANDLE hPipe = INVALID_HANDLE_VALUE;
   static const char *cPipeName = "\\\\.\\pipe\\node_cli.pipe";

   for (;;)
   {
///      printf( "\nPipe Server: Main thread awaiting client connection on %s\n", lpszPipename );

      hPipe = CreateNamedPipe(
          cPipeName,                // pipe name
          PIPE_ACCESS_DUPLEX,       // read/write access
          PIPE_TYPE_MESSAGE |       // message type pipe
          PIPE_READMODE_MESSAGE |   // message-read mode
          PIPE_WAIT,                // blocking mode
          PIPE_UNLIMITED_INSTANCES, // max. instances
          4096,                     // output buffer size
          4096,                     // input buffer size
          0,                        // client time-out
          NULL );                   // default security attribute

      if ( hPipe == INVALID_HANDLE_VALUE ) {
          log_it( L_ERROR, "CreateNamedPipe failed, GLE = %lu.\n", GetLastError() );
          return NULL;
      }

      fConnected = ConnectNamedPipe( hPipe, NULL ) ? TRUE : ( GetLastError() == ERROR_PIPE_CONNECTED );

      if ( fConnected )
      {
        log_it( L_INFO, "Client %p connected, creating a processing thread.\n", hPipe );

        pthread_create( &threadId, NULL, thread_pipe_client_func, hPipe );
        pthread_detach( threadId );
      }
      else
         CloseHandle( hPipe );
    }

    return NULL;
}
#endif


/**
 * @brief thread_main_func
 * main threading server function
 * @param args 
 * @return void* 
 */
static void* thread_main_func(void *args)
{
    SOCKET sockfd = (SOCKET) (intptr_t) args;
    SOCKET newsockfd;

    log_it( L_INFO, "Server start socket = %s", dap_config_get_item_str( g_config, "conserver", "listen_unix_socket_path") );
    // wait of clients
    while(1)
    {
        pthread_t threadId;
        struct sockaddr_in peer;
        socklen_t size = sizeof(peer);
        // received a new connection request
        if((newsockfd = accept(sockfd, (struct sockaddr*) &peer, &size)) == (SOCKET) -1) {
            log_it(L_ERROR, "new connection break newsockfd=%"DAP_FORMAT_SOCKET, newsockfd);
            break;
        }
        // create child thread for a client connection
        pthread_create(&threadId, NULL, thread_one_client_func, (void*) (intptr_t) newsockfd);
        // in order to thread not remain in state "dead" after completion
        pthread_detach(threadId);
    };
    // close connection
    int cs = closesocket(sockfd);
    log_it(L_INFO, "Exit server thread=%d socket=%"DAP_FORMAT_SOCKET, cs, sockfd);
    return NULL;
}


/**
 * @brief dap_chain_node_cli_set_reply_text
 * Write text to reply string
 * @param str_reply 
 * @param str 
 * @param ... 
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
 * @brief dap_chain_node_cli_check_option
 * @param argv
 * @param arg_start
 * @param arg_end
 * @param opt_name
 * @return
 */
int dap_chain_node_cli_check_option( char** argv, int arg_start, int arg_end, const char *opt_name)
{
    int arg_index = arg_start;
    const char *arg_string;

    while(arg_index < arg_end)
    {
        char * l_argv_cur = argv[arg_index];
        arg_string = l_argv_cur;
        // find opt_name
        if(arg_string && opt_name && arg_string[0] && opt_name[0] && !strcmp(arg_string, opt_name)) {
                return arg_index;
        }
        arg_index++;
    }
    return -1;
}


/**
 * @brief dap_chain_node_cli_find_option_val
 * return index of string in argv, or 0 if not found
 * @param argv 
 * @param arg_start 
 * @param arg_end 
 * @param opt_name 
 * @param opt_value 
 * @return int 
 */
int dap_chain_node_cli_find_option_val( char** argv, int arg_start, int arg_end, const char *opt_name, const char **opt_value)
{
    assert(argv);
    int arg_index = arg_start;
    const char *arg_string;
    int l_ret_pos = 0;

    while(arg_index < arg_end)
    {
        char * l_argv_cur = argv[arg_index];
        arg_string = l_argv_cur;
        // find opt_name
        if(arg_string && opt_name && arg_string[0] && opt_name[0] && !strcmp(arg_string, opt_name)) {
            // find opt_value
            if(opt_value) {
                arg_string = argv[++arg_index];
                if(arg_string) {
                    *opt_value = arg_string;
                    return arg_index;
                }
                // for case if opt_name exist without value
                else
                    l_ret_pos = arg_index;
            }
            else
                // need only opt_name
                return arg_index;
        }
        arg_index++;
    }
    return l_ret_pos;
}

/**
 * @brief s_cmd_item_create
 * @param a_name
 * @param func
 * @param a_arg_func
 * @param doc
 * @param doc_ex
 * @return
 */
void dap_chain_node_cli_cmd_item_create_ex(const char * a_name, cmdfunc_ex_t *a_func, void *a_arg_func, const char *a_doc, const char *a_doc_ex)
{
    dap_chain_node_cmd_item_t *l_cmd_item = DAP_NEW_Z(dap_chain_node_cmd_item_t);
    dap_snprintf(l_cmd_item->name,sizeof (l_cmd_item->name),"%s",a_name);
    l_cmd_item->doc = strdup( a_doc);
    l_cmd_item->doc_ex = strdup( a_doc_ex);
    if (a_arg_func) {
        l_cmd_item->func_ex = a_func;
        l_cmd_item->arg_func = a_arg_func;
    } else {
        l_cmd_item->func = (cmdfunc_t *)(void *)a_func;
    }
    HASH_ADD_STR(s_commands,name,l_cmd_item);
    log_it(L_DEBUG,"Added command %s",l_cmd_item->name);
}

/**
 * @brief dap_chain_node_cli_cmd_item_apply_overrides
 * 
 * @param a_name 
 * @param a_overrides 
 */
void dap_chain_node_cli_cmd_item_apply_overrides(const char * a_name, const dap_chain_node_cmd_item_func_overrides_t * a_overrides){
    dap_chain_node_cmd_item_t *l_cmd_item = dap_chain_node_cli_cmd_find(a_name);
    if(l_cmd_item)
        l_cmd_item->overrides = *a_overrides;
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
 * @brief dap_chain_node_cli_init
 * Initialization of the server side of the interaction
 * with the console kelvin-node-cli
 * init commands description
 * return 0 if OK, -1 error
 * @param g_config 
 * @return int 
 */
int dap_chain_node_cli_init(dap_config_t * g_config)
{
    s_debug_cli = dap_config_get_item_bool_default(g_config,"conserver","debug_cli",false);
#ifndef _WIN32
    struct sockaddr_un l_server_addr={0};
    l_server_addr.sun_family =  AF_UNIX;
    snprintf(l_server_addr.sun_path,sizeof(l_server_addr.sun_path), "%s", dap_config_get_item_str( g_config, "conserver", "listen_unix_socket_path") );
#else
   pthread_t threadId;
#endif

    struct sockaddr_in server_addr;
    SOCKET sockfd = -1;

    bool l_conserver_enabled = dap_config_get_item_bool_default( g_config, "conserver", "enabled", true );

    if ( !l_conserver_enabled ) {

        log_it( L_WARNING, "Console Server is dissabled." );
        return 0;
    }

#ifdef __WIN32
    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        log_it(L_CRITICAL, "Couldn't init Winsock DLL, error: %d", ret);
        return 2;
    }
#endif

    dap_chain_node_cli_cmd_item_create("global_db", com_global_db, "Work with global database",
            "global_db cells add -cell <cell id> \n"
            "global_db flush \n\n"
//                    "global_db wallet_info set -addr <wallet address> -cell <cell id> \n\n"
            );

    dap_chain_node_cli_cmd_item_create("node", com_node, "Work with node",
            "node add  -net <net name> -addr {<node address> | -alias <node alias>} {-port <port>} -cell <cell id>  {-ipv4 <ipv4 external address> | -ipv6 <ipv6 external address>}\n\n"
                    "node del  -net <net name> -addr <node address> | -alias <node alias>\n\n"
                    "node link {add|del}  -net <net name> {-addr <node address> | -alias <node alias>} -link <node address>\n\n"
                    "node alias -addr <node address> -alias <node alias>\n\n"
                    "node connect {<node address> | -alias <node alias> | auto}\n\n"
                    "node handshake {<node address> | -alias <node alias>}\n"
                    "node dump -net <net name> [ -addr <node address> | -alias <node alias>] [-full]\n\n"
                                        );
    dap_chain_node_cli_cmd_item_create ("ping", com_ping, "Send ICMP ECHO_REQUEST to network hosts",
            "ping [-c <count>] host\n");
    dap_chain_node_cli_cmd_item_create ("traceroute", com_traceroute, "Print the hops and time of packets trace to network host",
            "traceroute host\n");
    dap_chain_node_cli_cmd_item_create ("tracepath", com_tracepath,"Traces path to a network host along this path",
            "tracepath host\n");
    dap_chain_node_cli_cmd_item_create ("version", com_version, "Return software version",
                                        "version\n"
                                        "\tReturn version number\n"
                                        );

    dap_chain_node_cli_cmd_item_create ("help", com_help, "Description of command parameters",
                                        "help [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_chain_node_cli_cmd_item_create ("?", com_help, "Synonym for \"help\"",
                                        "? [<command>]\n"
                                        "\tObtain help for <command> or get the total list of the commands\n"
                                        );
    dap_chain_node_cli_cmd_item_create("wallet", com_tx_wallet, "Wallet operations",
            "wallet [new -w <wallet_name> [-sign <sign_type>] [-restore <hex value>] [-net <net_name>] [-force]| list | info -addr <addr> -w <wallet_name> -net <net_name>]\n");

    // Token commands
    dap_chain_node_cli_cmd_item_create ("token_update", com_token_update, "Token update",
            "\nPrivate token update\n"
            "\t token_update -net <net name> -chain <chain name> -token <token ticker> [-type private] [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
            "\t   Update private token <token ticker> for <netname>:<chain name> with"
            "\t   custom parameters list <Param 1>, <Param 2>...<Param N>."
            "\n"
            "==Params==\n"
            "General:\n"
            "\t -flags_set <value>:\t Set list of flags from <value> to token declaration\n"
            "\t -flags_unset <value>:\t Unset list of flags from <value> from token declaration\n"
            "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
            "\t -total_signs_valid <value>:\t Set valid signatures count's minimum\n"
            "\t -signs_add <value>:\t Add signature's pkey fingerprint to the list of owners\n"
            "\t -signs_remove <value>:\t Remove signature's pkey fingerprint from the owners\n"
            "\nDatum type allowed/blocked updates:\n"
            "\t -datum_type_allowed_add <value>:\t Add allowed datum type(s)\n"
            "\t -datum_type_allowed_remove <value>:\t Remove datum type(s) from allowed\n"
            "\t -datum_type_allowed_clear:\t Remove all datum types from allowed\n"
            "\t -datum_type_blocked_add <value>:\t Add blocked datum type(s)\n"
            "\t -datum_type_blocked_remove <value>:\t Remove datum type(s) from blocked\n"
            "\t -datum_type_blocked_clear:\t Remove all datum types from blocked\n"
            "\nTx receiver addresses allowed/blocked updates:\n"
            "\t -tx_receiver_allowed_add <value>:\t Add allowed tx receiver(s)\n"
            "\t -tx_receiver_allowed_remove <value>:\t Remove tx receiver(s) from allowed\n"
            "\t -tx_receiver_allowed_clear:\t Remove all tx receivers from allowed\n"
            "\t -tx_receiver_blocked_add <value>:\t Add blocked tx receiver(s)\n"
            "\t -tx_receiver_blocked_remove <value>:\t Remove tx receiver(s) from blocked\n"
            "\t -tx_receiver_blocked_clear:\t Remove all tx receivers from blocked\n"
            "\nTx sender addresses allowed/blocked updates:\n"
            "\t -tx_sender_allowed_add <value>:\t Add allowed tx sender(s)\n"
            "\t -tx_sender_allowed_remove <value>:\t Remove tx sender(s) from allowed\n"
            "\t -tx_sender_allowed_clear:\t Remove all tx senders from allowed\n"
            "\t -tx_sender_blocked_add <value>:\t Add allowed tx sender(s)\n"
            "\t -tx_sender_blocked_remove <value>:\t Remove tx sender(s) from blocked\n"
            "\t -tx_sender_blocked_clear:\t Remove all tx sender(s) from blocked\n"
            "\n"
            "==Flags=="
            "\t ALL_BLOCKED:\t Blocked all permissions, usefull add it first and then add allows what you want to allow\n"
            "\t ALL_ALLOWED:\t Allowed all permissions if not blocked them. Be careful with this mode\n"
            "\t ALL_FROZEN:\t All permissions are temprorary frozen\n"
            "\t ALL_UNFROZEN:\t Unfrozen permissions\n"
            "\t STATIC_ALL:\t No token manipulations after declarations at all. Token declares staticly and can't variabed after\n"
            "\t STATIC_FLAGS:\t No token manipulations after declarations with flags\n"
            "\t STATIC_PERMISSIONS_ALL:\t No all permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_DATUM_TYPE:\t No datum type permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_TX_SENDER:\t No tx sender permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_TX_RECEIVER:\t No tx receiver permissions lists manipulations after declarations\n"
            "\n"
            );
    // Token commands
    dap_chain_node_cli_cmd_item_create ("token_decl", com_token_decl, "Token declaration",
            "Simple token declaration:\n"
            "\t token_decl -net <net name> -chain <chain name> -token <token ticker> -total_supply <total supply> -signs_total <sign total> -signs_emission <signs for emission> -certs <certs list>\n"
            "\t  Declare new simple token for <netname>:<chain name> with ticker <token ticker>, maximum emission <total supply> and <signs for emission> from <signs total> signatures on valid emission\n"
            "\nExtended private token declaration\n"
            "\t token_decl -net <net name> -chain <chain name> -token <token ticker> -type private -flags [<Flag 1>][,<Flag 2>]...[,<Flag N>]...  [-<Param name 1> <Param Value 1>] [-Param name 2> <Param Value 2>] ...[-<Param Name N> <Param Value N>]\n"
            "\t   Declare new token for <netname>:<chain name> with ticker <token ticker>, flags <Flag 1>,<Flag2>...<Flag N>"
            "\t   and custom parameters list <Param 1>, <Param 2>...<Param N>."
            "\n"
            "==Flags=="
            "\t ALL_BLOCKED:\t Blocked all permissions, usefull add it first and then add allows what you want to allow\n"
            "\t ALL_ALLOWED:\t Allowed all permissions if not blocked them. Be careful with this mode\n"
            "\t ALL_FROZEN:\t All permissions are temprorary frozen\n"
            "\t ALL_UNFROZEN:\t Unfrozen permissions\n"
            "\t STATIC_ALL:\t No token manipulations after declarations at all. Token declares staticly and can't variabed after\n"
            "\t STATIC_FLAGS:\t No token manipulations after declarations with flags\n"
            "\t STATIC_PERMISSIONS_ALL:\t No all permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_DATUM_TYPE:\t No datum type permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_TX_SENDER:\t No tx sender permissions lists manipulations after declarations\n"
            "\t STATIC_PERMISSIONS_TX_RECEIVER:\t No tx receiver permissions lists manipulations after declarations\n"
            "\n"
            "==Params==\n"
            "General:\n"
            "\t -flags <value>:\t List of flags from <value> to token declaration\n"
            "\t -total_supply <value>:\t Set total supply - emission's maximum - to the <value>\n"
            "\t -total_signs_valid <value>:\t Set valid signatures count's minimum\n"
            "\t -signs <value>:\t Signature's fingerprint list\n"
            "\nDatum type allowed/blocked:\n"
            "\t -datum_type_allowed <value>:\t Set allowed datum type(s)\n"
            "\t -datum_type_blocked <value>:\t Set blocked datum type(s)\n"
            "\nTx receiver addresses allowed/blocked:\n"
            "\t -tx_receiver_allowed <value>:\t Set allowed tx receiver(s)\n"
            "\t -tx_receiver_blocked <value>:\t Set blocked tx receiver(s)\n"
            "\nTx sender addresses allowed/blocked:\n"
            "\t -tx_sender_allowed <value>:\t Set allowed tx sender(s)\n"
            "\t -tx_sender_blocked <value>:\t Set allowed tx sender(s)\n"
            "\n"
            );

    dap_chain_node_cli_cmd_item_create ("token_decl_sign", com_token_decl_sign, "Token declaration add sign",
            "token_decl_sign -net <net name> -chain <chain name> -datum <datum_hash> -certs <certs list>\n"
            "\t Sign existent <datum hash> in mempool with <certs list>\n"
            );

    dap_chain_node_cli_cmd_item_create ("token_emit", com_token_emit, "Token emission",
            "token_emit -net <net name> -chain_emission <chain for emission> -chain_base_tx <chain for base tx> -addr <addr> -token <token ticker> -certs <cert> -emission_value <val>\n");

    dap_chain_node_cli_cmd_item_create ("mempool_list", com_mempool_list, "List mempool entries for selected chain network",
            "mempool_list -net <net name>\n");

    dap_chain_node_cli_cmd_item_create ("mempool_proc", com_mempool_proc, "Proc mempool entrie with specified hash for selected chain network",
            "mempool_proc -net <net name> -datum <datum hash>\n");

    dap_chain_node_cli_cmd_item_create ("mempool_delete", com_mempool_delete, "Delete datum with hash <datum hash> for selected chain network",
            "mempool_delete -net <net name> -datum <datum hash>\n");

    dap_chain_node_cli_cmd_item_create ("mempool_add_ca", com_mempool_add_ca,
                                        "Add pubic certificate into the mempool to prepare its way to chains",
            "mempool_add_ca -net <net name> [-chain <chain name>] -ca_name <Certificate name>\n");

    dap_chain_node_cli_cmd_item_create ("chain_ca_pub", com_chain_ca_pub,
                                        "Add pubic certificate into the mempool to prepare its way to chains",
            "chain_ca -net <net name> [-chain <chain name>] -ca_name <Certificate name>\n");

    dap_chain_node_cli_cmd_item_create ("chain_ca_copy", com_chain_ca_copy,
                                        "Copy pubic certificate into the mempool to prepare its way to chains",
            "chain_ca -net <net name> [-chain <chain name>] -ca_name <Public certificate name>\n");

    // Transaction commands
    dap_chain_node_cli_cmd_item_create ("tx_create", com_tx_create, "Make transaction",
            "tx_create -net <net name> -chain <chain name> -from_wallet <name> -to_addr <addr> -token <token ticker> -value <value> [-fee <addr> -value_fee <val>]\n" );
    dap_chain_node_cli_cmd_item_create ("tx_cond_create", com_tx_cond_create, "Make cond transaction",
            "tx_cond_create -net <net name> -token <token_ticker> -wallet_f <wallet_from> -wallet_t <wallet_to>"
                                        "-value <value_datoshi> -unit <mb|kb|b|sec|day> -service <vpn>\n" );
    dap_chain_node_cli_cmd_item_create ("tx_verify", com_tx_verify, "Verifing transaction in mempool",
            "tx_verify -net <net name> -chain <chain name> -tx <tx_hash>\n" );

    // Transaction history
    dap_chain_node_cli_cmd_item_create("tx_history", com_tx_history, "Transaction history (for address or by hash)",
            "tx_history  [-addr <addr> | -w <wallet name> | -tx <tx_hash>] -net <net name> -chain <chain name>\n");

    // Ledger info
    dap_chain_node_cli_cmd_item_create("ledger", com_ledger, "Ledger info",
            "ledger list coins -net <network name>\n"
            "ledger list coins_cond -net <network name>\n"
            "ledger list addrs -net <network name>\n"
            "ledger tx [all | -addr <addr> | -w <wallet name> | -tx <tx_hash>] [-chain <chain name>] -net <network name>\n");

    // Token info
    dap_chain_node_cli_cmd_item_create("token", com_token, "Token info",
            "token list -net <network name>\n"
            "token info -net <network name> -name <token name>\n"
            "token tx [all | -addr <wallet_addr> | -wallet <wallet_name>] -name <token name> -net <network name> [-page_start <page>] [-page <page>]\n");

    // Log
    dap_chain_node_cli_cmd_item_create ("print_log", com_print_log, "Print log info",
                "print_log [ts_after <timestamp >] [limit <line numbers>]\n" );

    // Statisticss
    dap_chain_node_cli_cmd_item_create("stats", com_stats, "Print statistics",
                "stats cpu");



    // Exit
    dap_chain_node_cli_cmd_item_create ("exit", com_exit, "Stop application and exit",
                "exit\n" );

     // Export GDB to JSON
     dap_chain_node_cli_cmd_item_create("gdb_export", cmd_gdb_export, "Export gdb to JSON",
                                        "gdb_export filename <filename without extension>");

     //Import GDB from JSON
     dap_chain_node_cli_cmd_item_create("gdb_import", cmd_gdb_import, "Import gdb from JSON",
                                        "gdb_import filename <filename without extension>");

    // create thread for waiting of clients
    pthread_t l_thread_id;

    l_listen_port = dap_config_get_item_uint16_default( g_config, "conserver", "listen_port_tcp",0);

    const char * l_listen_unix_socket_path = dap_config_get_item_str( g_config, "conserver", "listen_unix_socket_path");



    const char * l_listen_unix_socket_permissions_str = dap_config_get_item_str( g_config, "conserver", "listen_unix_socket_permissions");
    mode_t l_listen_unix_socket_permissions = 0770;

    if ( l_listen_unix_socket_path && l_listen_unix_socket_permissions ) {
        if ( l_listen_unix_socket_permissions_str ) {
            uint16_t l_perms;
            dap_sscanf(l_listen_unix_socket_permissions_str,"%ho", &l_perms);
            l_listen_unix_socket_permissions = l_perms;
        }
        log_it( L_INFO, "Console interace on path %s (%04o) ", l_listen_unix_socket_path, l_listen_unix_socket_permissions );

      #ifndef _WIN32

        if ( server_sockfd >= 0 ) {
            dap_chain_node_cli_delete( );
            server_sockfd = 0;
        }

        // create socket
        sockfd = socket( AF_UNIX, SOCK_STREAM, 0 );
        if( sockfd == INVALID_SOCKET )
            return -1;

        //int gdsg = sizeof(struct sockaddr_un);

        // Creatuing directory if not created
        char * l_listen_unix_socket_path_dir = dap_path_get_dirname(l_listen_unix_socket_path);
        dap_mkdir_with_parents(l_listen_unix_socket_path_dir);
        DAP_DELETE(l_listen_unix_socket_path_dir);

        if ( access( l_listen_unix_socket_path , R_OK) != -1 )
            unlink( l_listen_unix_socket_path );


        // connecting the address with a socket
        if( bind(sockfd, (const struct sockaddr*) &l_server_addr, sizeof(struct sockaddr_un)) == SOCKET_ERROR) {
            // errno = EACCES  13  Permission denied
            if ( errno == EACCES ) // EACCES=13
                log_it( L_ERROR, "Server can't start(err=%d). Can't create file=%s [Permission denied]", errno,
                        l_listen_unix_socket_path );
            else
                log_it( L_ERROR, "Server can't start(err=%d). May be problem with file=%s?", errno, l_listen_unix_socket_path );
            closesocket( sockfd );
            return -2;
        }
        chmod(l_listen_unix_socket_path,l_listen_unix_socket_permissions);

      #else

//    Sleep( 3000 );

        if( pthread_create(&threadId, NULL, thread_pipe_func, (void*) (intptr_t) sockfd) != 0 ) {
            closesocket( sockfd );
            return -7;
        }

        return 0;
      #endif

    }
    else if (l_listen_port ){

        const char *l_listen_addr_str = dap_config_get_item_str(g_config, "conserver", "listen_address");

        log_it( L_INFO, "Console interace on addr %s port %u ", l_listen_addr_str, l_listen_port );

        server_addr.sin_family = AF_INET;
#ifdef _WIN32
        struct in_addr _in_addr = { { .S_addr = htonl(INADDR_LOOPBACK) } };
        server_addr.sin_addr = _in_addr;
        server_addr.sin_port = l_listen_port;
#else
        inet_pton( AF_INET, l_listen_addr_str, &server_addr.sin_addr );
        server_addr.sin_port = htons( (uint16_t)l_listen_port );
#endif
        // create socket
        if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET ) {
#ifdef __WIN32
            _set_errno(WSAGetLastError());
#endif
            log_it( L_ERROR, "Console Server: can't create socket, err %d", errno );
            return -3;
        }

        // connecting the address with a socket
        if ( bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == SOCKET_ERROR ) {
#ifdef __WIN32
            _set_errno(WSAGetLastError());
#endif
            log_it( L_ERROR, "Console Server: can't bind socket, err %d", errno );
            closesocket( sockfd );
            return -4;
        }
    }else {
        log_it (L_INFO, "Not defined console interface");
        return 0;
    }

    // turn on reception of connections
    if( listen(sockfd, MAX_CONSOLE_CLIENTS) == SOCKET_ERROR )
        return -5;

    if( pthread_create(&l_thread_id, NULL, thread_main_func, (void*) (intptr_t) sockfd) != 0 ) {
        closesocket( sockfd );
        return -6;
    }

    // in order to thread not remain in state "dead" after completion
    pthread_detach( l_thread_id );
    server_sockfd = sockfd;

    return 0;
}


/**
 * @brief dap_chain_node_cli_delete
 * Deinitialization of the server side
 */
void dap_chain_node_cli_delete(void)
{
    if(server_sockfd != INVALID_SOCKET)
        closesocket(server_sockfd);
#ifdef __WIN32
    WSACleanup();
#endif
    // deinit client for handshake
    dap_chain_node_client_deinit();
}
