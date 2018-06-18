#ifndef DAP_HTTP_CLIENT_H
#define DAP_HTTP_CLIENT_H
#include <stddef.h>
struct dap_http_client_simple;
typedef void (*dap_http_client_simple_callback_error_t) (int,void *); // Callback for specific http client operations
typedef void (*dap_http_client_simple_callback_data_t) (void *,size_t,void *); // Callback for specific http client operations

typedef struct dap_http_client_simple {
    void * _inheritor;
} dap_http_client_simple_t;

int dap_http_client_simple_init();
void dap_http_client_simple_deinit();

void dap_http_client_simple_request(const char * a_url, const char * a_method,
                                   const char* a_request_content_type , void *a_request, size_t a_request_size, char * a_cookie,
                                   dap_http_client_simple_callback_data_t a_response_callback,
                                   dap_http_client_simple_callback_error_t a_error_callback, void *a_obj, void * a_custom);

#endif
