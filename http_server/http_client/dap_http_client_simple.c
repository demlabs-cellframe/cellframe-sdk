
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>
#else
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#include "wrappers.h"
#include <wepoll.h>
#include "../../pthread-win32/pthread.h"
#endif

#include <curl/curl.h>

#include "utlist.h"

#include "dap_common.h"

#include "dap_http_client.h"
#include "dap_http_client_simple.h"

typedef struct dap_http_client_internal {

  dap_http_client_simple_callback_data_t response_callback;
  dap_http_client_simple_callback_error_t error_callback;

  void *obj;
  uint8_t *request;
  size_t request_size;
  size_t request_sent_size;

  struct curl_slist *request_headers;

  uint8_t *response;
  size_t response_size;
  size_t response_size_max;

} dap_http_client_internal_t;

CURLM *m_curl_mh = NULL; // Multi-thread handle to stack lot of parallel requests

#ifndef _WIN32
  pthread_t curl_pid = 0;
#else
  pthread_t curl_pid = { NULL, 0 };
#endif

pthread_cond_t  m_curl_cond  = PTHREAD_COND_INITIALIZER;
pthread_mutex_t m_curl_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *dap_http_client_thread( void *arg );

size_t dap_http_client_curl_request_callback( char *a_ptr, size_t a_size, size_t a_nmemb, void *a_userdata );
size_t dap_http_client_curl_response_callback(char *a_ptr, size_t a_size, size_t a_nmemb, void *a_userdata );
size_t dap_http_client_curl_close_callback( char *a_ptr, size_t a_size, size_t a_nmemb, void *a_userdata );

void dap_http_client_internal_delete( dap_http_client_internal_t *a_client );

#define DAP_HTTP_CLIENT_RESPONSE_SIZE_MAX 40960

#define LOG_TAG "dap_http_client"

/**
 * @brief dap_http_client_init
 * @return
 */
int dap_http_client_simple_init( )
{
  log_it( L_NOTICE,"dap_http_client_simple_init( )" );

  curl_global_init( CURL_GLOBAL_ALL );
  m_curl_mh = curl_multi_init( );

  pthread_create( &curl_pid, NULL, dap_http_client_thread, NULL );

  return 0;
}


/**
 * @brief dap_http_client_deinit
 */
void dap_http_client_simple_deinit( )
{
  curl_multi_cleanup( m_curl_mh );
}

/**
 * @brief dap_http_client_internal_delete
 * @param a_client
 */
void dap_http_client_internal_delete( dap_http_client_internal_t * a_client_internal )
{
  log_it( L_NOTICE,"dap_http_client_internal_delete" );

  if( a_client_internal->request_headers )
    curl_slist_free_all( a_client_internal->request_headers );

  if ( a_client_internal->request )
    free( a_client_internal->request );

  if ( a_client_internal->response )
    free( a_client_internal->response );

  free( a_client_internal );
}

/**
 * @brief dap_http_client_simple_request
 * @param a_url
 * @param a_method
 * @param a_request_content_type
 * @param a_request
 * @param a_request_size
 * @param a_response_callback
 * @param a_error_callback
 * @param a_obj
 */
void dap_http_client_simple_request_custom( const char *a_url, const char *a_method, const char *a_request_content_type, 
                                            void *a_request, size_t a_request_size, char *a_cookie, 
                                            dap_http_client_simple_callback_data_t a_response_callback,
                                            dap_http_client_simple_callback_error_t a_error_callback, 
                                            void *a_obj, char **a_custom, size_t a_custom_count )
{
  log_it( L_DEBUG, "Simple HTTP request with static predefined buffer (%lu bytes) on url '%s'",
         DAP_HTTP_CLIENT_RESPONSE_SIZE_MAX, a_url );

  CURL *l_curl_h = curl_easy_init( );

  dap_http_client_internal_t *l_client_internal = DAP_NEW_Z( dap_http_client_internal_t );

  l_client_internal->error_callback = a_error_callback;
  l_client_internal->response_callback = a_response_callback;
  l_client_internal->obj = a_obj;

  l_client_internal->response_size_max = DAP_HTTP_CLIENT_RESPONSE_SIZE_MAX;
  l_client_internal->response = (uint8_t*) calloc( 1 ,DAP_HTTP_CLIENT_RESPONSE_SIZE_MAX );

  l_client_internal->request = malloc(a_request_size);
  memcpy(l_client_internal->request, a_request, a_request_size);
  l_client_internal->request_size = a_request_size;

  if( ( a_request ) && ( (
                            (strcmp( a_method , "POST" ) == 0)  ||
                            (strcmp( a_method , "POST_ENC" ) == 0)
                        ) ) ){
     char l_buf[1024];
     log_it ( L_DEBUG , "POST request with %u bytes of decoded data" , a_request_size );

     if( a_request_content_type )
       l_client_internal->request_headers = curl_slist_append(l_client_internal->request_headers, a_request_content_type );

      if ( a_custom ) {
        for( int i = 0; i < a_custom_count; i++ ) {
          l_client_internal->request_headers = curl_slist_append( l_client_internal->request_headers, (char*) a_custom[i] );
        }
      }

      if ( a_cookie )
        l_client_internal->request_headers = curl_slist_append( l_client_internal->request_headers,(char*) a_cookie );

        snprintf(l_buf,sizeof(l_buf),"Content-Length: %lu", a_request_size );
        l_client_internal->request_headers = curl_slist_append(l_client_internal->request_headers, l_buf);

        //curl_easy_setopt( l_curl_h , CURLOPT_READDATA , l_client_internal );
        curl_easy_setopt( l_curl_h , CURLOPT_POST , 1 );
        curl_easy_setopt( l_curl_h , CURLOPT_POSTFIELDSIZE, a_request_size );

  }

  if ( l_client_internal->request_headers )
    curl_easy_setopt( l_curl_h, CURLOPT_HTTPHEADER, l_client_internal->request_headers );

  curl_easy_setopt( l_curl_h , CURLOPT_PRIVATE, l_client_internal );
  curl_easy_setopt( l_curl_h , CURLOPT_URL, a_url);

  curl_easy_setopt( l_curl_h , CURLOPT_READDATA , l_client_internal  );
  curl_easy_setopt( l_curl_h , CURLOPT_READFUNCTION , dap_http_client_curl_request_callback );

  curl_easy_setopt( l_curl_h , CURLOPT_WRITEDATA , l_client_internal );
  curl_easy_setopt( l_curl_h , CURLOPT_WRITEFUNCTION , dap_http_client_curl_response_callback );

  curl_easy_setopt( l_curl_h , CURLOPT_CLOSESOCKETDATA , l_client_internal );
  curl_easy_setopt( l_curl_h , CURLOPT_CLOSESOCKETFUNCTION , dap_http_client_curl_close_callback );

  curl_multi_add_handle( m_curl_mh, l_curl_h );
    //curl_multi_perform(m_curl_mh, &m_curl_cond);

  pthread_cond_signal( &m_curl_cond);

  send_select_break( );
}

/**
 * @brief dap_http_client_simple_request
 * @param a_url
 * @param a_method
 * @param a_request_content_type
 * @param a_request
 * @param a_request_size
 * @param a_response_callback
 * @param a_error_callback
 * @param a_obj
 */
void dap_http_client_simple_request(const char * a_url, const char * a_method, const char* a_request_content_type, void *a_request, size_t a_request_size, char * a_cookie, dap_http_client_simple_callback_data_t a_response_callback,
                                   dap_http_client_simple_callback_error_t a_error_callback, void *a_obj, void * a_custom)
{
    char *a_custom_new[1];
    size_t a_custom_count = 0;

    a_custom_new[0] = (char*)a_custom;

    if(a_custom)
        a_custom_count = 1;

    dap_http_client_simple_request_custom(a_url, a_method, a_request_content_type, a_request, a_request_size,
            a_cookie, a_response_callback, a_error_callback, a_obj, a_custom_new, a_custom_count);
}

/**
 * @brief dap_http_client_curl_response_callback
 * @param a_ptr
 * @param a_size
 * @param a_nmemb
 * @param a_userdata
 * @return
 */
size_t dap_http_client_curl_response_callback( char *a_ptr, size_t a_size, size_t a_nmemb, void *a_userdata )
{
  dap_http_client_internal_t * l_client_internal = (dap_http_client_internal_t *) a_userdata;

  log_it(L_DEBUG, "Recieved %lu bytes in HTTP resonse", a_size*a_nmemb);

    if( l_client_internal->response_size < l_client_internal->response_size_max){
        size_t l_size = a_size * a_nmemb;
        if( l_size > ( l_client_internal->response_size_max - l_client_internal->response_size) )
            l_size = l_client_internal->response_size_max - l_client_internal->response_size;
        memcpy(l_client_internal->response + l_client_internal->response_size,a_ptr,l_size);
        l_client_internal->response_size += l_size;
    }else{
        log_it(L_WARNING,"Too big reply, %lu bytes a lost",a_size*a_nmemb);
    }

    return a_size*a_nmemb;
}


/**
 * @brief dap_http_client_curl_response_callback
 * @param a_ptr
 * @param a_size
 * @param a_nmemb
 * @param a_userdata
 * @return
 */
size_t dap_http_client_curl_close_callback( char *a_ptr, size_t a_size, size_t a_nmemb, void *a_userdata )
{
    dap_http_client_internal_t * l_client_internal = (dap_http_client_internal_t *) a_userdata;
    printf("\n*** close l_client_internal=%x\n\n", l_client_internal);
}

/**
 * @brief dap_http_client_curl_request_callback
 * @param a_ptr
 * @param a_size
 * @param a_nmemb
 * @param a_userdata
 * @return
 */
size_t dap_http_client_curl_request_callback(char * a_ptr, size_t a_size, size_t a_nmemb, void * a_userdata)
{
    dap_http_client_internal_t * l_client_internal = (dap_http_client_internal_t *) a_userdata;

    size_t l_size = a_size * a_nmemb;

    if( ( l_size + l_client_internal->request_sent_size) > l_client_internal->request_size )
        l_size = l_client_internal->request_size - l_client_internal->request_sent_size;

    if( l_size ) {
        memcpy( a_ptr, l_client_internal->request + l_client_internal->request_sent_size, l_size );
        l_client_internal->request_sent_size += l_size;
    }

    return l_size;
}

/**
 * @brief dap_http_client_thread
 * @param arg
 */
static void* dap_http_client_thread(void * arg)
{
    (void) arg;

    bool l_still_running = true;

//    return NULL;

    log_it(L_DEBUG, "dap_http_client_thread started");

    do {
        struct timeval timeout;
        int rc = 0; /* select() return code */
        CURLMcode mc; /* curl_multi_fdset() return code */

        fd_set fdread;
        fd_set fdwrite;
        fd_set fdexcep;
        int maxfd = -1;

        long curl_timeo = -1;

        FD_ZERO(&fdread);
        FD_ZERO(&fdwrite);
        FD_ZERO(&fdexcep);

        /* set a suitable timeout to play around with */
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        curl_multi_timeout( m_curl_mh, &curl_timeo );

        if(curl_timeo >= 0) {
          timeout.tv_sec = curl_timeo / 1000;
          if(timeout.tv_sec > 1)
            timeout.tv_sec = 1;
          else
            timeout.tv_usec = (curl_timeo % 1000) * 1000;
        }

        /* get file descriptors from the transfers */
        mc = curl_multi_fdset(m_curl_mh, &fdread, &fdwrite, &fdexcep, &maxfd);

        FD_SET(get_select_breaker(),&fdread);

        if(get_select_breaker() > maxfd)
            maxfd = get_select_breaker();

        if(mc != CURLM_OK) {
          log_it(L_ERROR, "curl_multi_fdset() failed, code %d.\n", mc);
          break;
        }

        /* On success the value of maxfd is guaranteed to be >= -1. We call
           select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
           no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
           to sleep 100ms, which is the minimum suggested value in the
           curl_multi_fdset() doc. */

        rc = 0;

        if(maxfd == -1) {
//            log_it(L_DEBUG, "Waiting for signal");
            pthread_cond_wait(&m_curl_cond,&m_curl_mutex);
        }  else {
//            log_it(L_DEBUG, "Selecting stuff");
          /* Note that on some platforms 'timeout' may be modified by select().
             If you need access to the original value save a copy beforehand. */
          rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
        }

        switch(rc) {
            case -1: {
              /* select error */
            } break;
            case 0: /* timeout */
            default: { /* action */
              int l_curl_eh_count = 0;
              curl_multi_perform( m_curl_mh , &l_curl_eh_count );
               // Check if we have smth complete
              struct CURLMsg *m;
              do {
                  int msgq = 0;

                  m = curl_multi_info_read(m_curl_mh, &msgq);

                  if(m && (m->msg == CURLMSG_DONE)) {
                      CURL *e = m->easy_handle;
                      char * l_private = NULL;
                      int l_err_code = 0;
                      curl_easy_getinfo( e, CURLINFO_PRIVATE, &l_private );
                      if( l_private ){

                          bool l_is_ok = false;
                          dap_http_client_internal_t *l_client_internal = (dap_http_client_internal_t *) l_private;

                          switch ( m->data.result){
                              case CURLE_OUT_OF_MEMORY: l_err_code = 1 ; log_it(L_CRITICAL, "Out of memory"); break;
                              case CURLE_COULDNT_CONNECT: l_err_code = 2 ; log_it(L_ERROR, "Couldn't connect to the destination server"); break;
                              case CURLE_COULDNT_RESOLVE_HOST: l_err_code = 3 ; log_it(L_ERROR, "Couldn't resolve destination address"); break;
                              case CURLE_OPERATION_TIMEDOUT: l_err_code = 4 ; log_it(L_ERROR, "HTTP request timeout"); break;
                              case CURLE_URL_MALFORMAT: l_err_code = 5 ; log_it(L_ERROR, "Wrong URL format in the outgoing request"); break;
                              case CURLE_FTP_WEIRD_SERVER_REPLY: l_err_code = 6 ; log_it(L_WARNING, "Weird server reply"); break;
                              case CURLE_OK:{
                                l_is_ok = true;
                                log_it(L_DEBUG, "Response size %u",l_client_internal->response_size);
                              }break;
                              default: l_err_code = 12345;
                          }

                          if( l_is_ok){
                                l_client_internal->response_callback(l_client_internal->response,
                                                                   l_client_internal->response_size,
                                                                   l_client_internal->obj );
                          }else {
                                log_it(L_WARNING, "HTTP request wasn't processed well with error code %d",m->data.result );
                                l_client_internal->error_callback(l_err_code , l_client_internal->obj );

                          }

                          dap_http_client_internal_delete(l_client_internal);

                      } 
                      else {
                        log_it(L_CRITICAL, "Can't get private information from libcurl handle to perform the reply to SAP connection");
                      }

                      curl_multi_remove_handle(m_curl_mh, e);
                      curl_easy_cleanup(e);
                  }

             } while(m);
            } break;
        }

    } while(l_still_running);

    return NULL;
}

