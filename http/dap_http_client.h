#ifndef _DAP_HTTP_CLIENT_H_
#define _DAP_HTTP_CLIENT_H_

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
struct dap_client;
struct dap_http_client;
struct dap_http;
struct dap_http_url_proc;


typedef enum dap_http_client_state{
    DAP_HTTP_CLIENT_STATE_NONE=0,
    DAP_HTTP_CLIENT_STATE_START=1,
    DAP_HTTP_CLIENT_STATE_HEADERS=2,
    DAP_HTTP_CLIENT_STATE_DATA=3
} dap_http_client_state_t;

typedef void (*dap_http_client_callback_t) (struct dap_http_client *,void * arg); // Callback for specific client operations

typedef struct dap_http_client
{
    char action[128]; // Type of HTTP action (GET, PUT and etc)
    char url_path[2048]; // URL path of requested document
    uint32_t http_version_major; // Major version of HTTP protocol
    uint32_t http_version_minor; // Minor version of HTTP protocol
    bool keep_alive;

    dap_http_client_state_t state_read;
    dap_http_client_state_t state_write;

    struct dap_http_header * in_headers;
    uint64_t in_content_length;
    char in_content_type[256];
    char in_query_string[1024];
    char in_cookie[1024];

    struct dap_http_header * out_headers;
    uint64_t out_content_length;
    bool out_content_ready;
    char out_content_type[256];
    time_t out_last_modified;
    bool out_connection_close;


    struct dap_client * client;
    struct dap_http * http;

    uint32_t reply_status_code;
    char reply_reason_phrase[256];

    struct dap_http_url_proc * proc;

    void * internal;

} dap_http_client_t;
#define DAP_HTTP_CLIENT(a)  ((dap_http_client_t *) (a)->internal )

extern int dap_http_client_init();
extern void dap_http_client_deinit();


extern void dap_http_client_new(struct dap_client * cl,void * arg); // Creates HTTP client's internal structure
extern void dap_http_client_delete(struct dap_client * cl,void * arg); // Free memory for HTTP client's internal structure

extern void dap_http_client_read(struct dap_client * cl,void * arg); // Process read event
extern void dap_http_client_write(struct dap_client * cl,void * arg); // Process write event
extern void dap_http_client_error(struct dap_client * cl,void * arg); // Process error event


#endif
