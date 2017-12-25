
#ifndef COMMON_H
#define COMMON_H
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#define CALLOC(a) ((a *) calloc(1,sizeof(a)))
#define DUP(a) (__typeof(a) ret = memcpy(ret,a,sizeof(*a)) )

#define DEF_LOG  "/opt/dapserver/log/dapserver.log"
//#define DEF_LOG  "/opt/DAP/log/confcall_server.log"

enum log_level{CRITICAL=5,ERROR=4, WARNING=3,NOTICE=2,INFO=1,DEBUG=0};
extern enum log_level log_level;

extern int common_init();
extern void common_deinit();

extern void _log_it(const char * log_tag, enum log_level, const char * format,...);
#define log_it(_log_level,...) _log_it(LOG_TAG,_log_level,##__VA_ARGS__)

extern const char * log_error();

extern char *itoa(int i);
extern int time_to_rfc822(char * out, size_t out_size_max, time_t t);

extern void get_utc_date_time(char buf_out[]);
extern void hexdump(const void* data, size_t size);
extern int send_select_break();
extern int get_select_breaker();
#endif
