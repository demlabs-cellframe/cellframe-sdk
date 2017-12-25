#ifndef _DAP_HTTP_HEADER_H_
#define _DAP_HTTP_HEADER_H_

//Structure for holding HTTP header in the bidirectional list
typedef struct dap_http_header{
    char * name;
    char * value;
    struct dap_http_header * next;
    struct dap_http_header * prev;
} dap_http_header_t;

struct dap_http_client;

extern int dap_http_header_init(); // Init module
extern void dap_http_header_deinit(); // Deinit module

extern int dap_http_header_parse(struct dap_http_client * cl_ht, const char * str);

extern dap_http_header_t * dap_http_header_add(dap_http_header_t ** top, const char*name, const char * value);

extern dap_http_header_t * dap_http_out_header_add(struct dap_http_client * ht, const char*name, const char * value);
extern dap_http_header_t * dap_http_out_header_add_f(struct dap_http_client * ht, const char*name, const char * value,...);

extern dap_http_header_t * dap_http_header_find(dap_http_header_t * top, const char*name);

extern void dap_http_header_remove(dap_http_header_t ** top,dap_http_header_t * hdr );

#endif
