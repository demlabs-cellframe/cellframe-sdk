#ifndef _DAP_HTTP_SIMPLE_H_
#define _DAP_HTTP_SIMPLE_H_
#include <stddef.h>
#include "dap_http.h"

#define DAP_HTTP_SIMPLE_REQUEST_MAX 100000

struct dap_http_simple;
typedef void (*dap_http_simple_callback_t)(struct dap_http_simple *,void*);

typedef struct dap_http_simple{
    dap_http_client_t * http;
    union{
        void * request;
        char * request_str;
    };
    size_t request_size;

    union{
        void * reply;
        char * reply_str;
    };
    size_t reply_size_max;
    size_t reply_size;

    size_t reply_sent;
    char reply_mime[256];

    dap_http_simple_callback_t reply_proc_post_callback;
} dap_http_simple_t;

#define DAP_HTTP_SIMPLE(a) ((dap_http_simple_t*) (a)->internal )


extern void dap_http_simple_proc_add(dap_http_t *sh, const char * url_path, size_t reply_size_max, dap_http_simple_callback_t cb); // Add simple processor
extern int dap_http_simple_module_init();
extern size_t dap_http_simple_reply(dap_http_simple_t * shs, void * data, size_t data_size);
extern size_t dap_http_simple_reply_f(dap_http_simple_t * shs, const char * data, ...);
#endif
