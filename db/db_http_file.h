#ifndef _DB_HTTP_FILE_H_
#define _DB_HTTP_FILE_H_
struct dap_http;

extern int db_http_file_init();
extern void db_http_file_deinit();

extern void db_http_file_proc_add(struct dap_http *sh, const char * url_path);

#endif
