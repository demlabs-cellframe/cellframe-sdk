#ifndef _DB_HTTP_H_
#define _DB_HTTP_H_

#include "enc_ks.h"
#include "enc_key.h"
#include "config.h"

extern int db_http_init();
extern void db_http_deinit();
extern void db_http_add_proc(struct dap_http * sh, const char * url);
#endif
