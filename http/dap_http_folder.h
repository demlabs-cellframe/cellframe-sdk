#ifndef _DAP_HTTP_FOLDER_H_
#define _DAP_HTTP_FOLDER_H_

struct dap_http;

extern int dap_http_folder_init();
extern void dap_http_folder_deinit();

extern int dap_http_folder_add(struct dap_http *sh, const char * url_path, const char * local_path); // Add folder for reading to the HTTP server

#endif
