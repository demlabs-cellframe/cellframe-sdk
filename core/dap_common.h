#ifndef COMMON_H
#define COMMON_H

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#define DAP_NEW(a)    ( (a*) malloc(sizeof(a)))
#define DAP_NEW_SIZE(a,b)    ( (a*) malloc(b))
#define DAP_NEW_Z(a) ( (a*) calloc(1,sizeof(a)))
#define DAP_NEW_Z_SIZE(a,b) ( (a*) calloc(1,b))

#define DAP_DUP(a) (__typeof(a) ret = memcpy(ret,a,sizeof(*a)) )

enum log_level{L_CRITICAL=5,L_ERROR=4, L_WARNING=3,L_NOTICE=2,L_INFO=1,L_DEBUG=0};
extern enum log_level log_level;

#ifdef __cplusplus
extern "C" {
#endif

int dap_common_init( const char * a_log_file );
void dap_common_deinit();

void _log_it(const char * log_tag, enum log_level, const char * format,...);
void _vlog_it(const char * log_tag, enum log_level, const char * format, va_list ap );
#define log_it(_log_level,...) _log_it(LOG_TAG,_log_level,##__VA_ARGS__)
#define vlog_it(a_log_level,a_format,a_ap) _vlog_it(LOG_TAG,a_log_level,a_format,a_ap)

const char * log_error();

#ifdef __GNUC__
char *itoa(int i);
#elif _MSC_VER
char *strndup(const char *s, size_t n);
#endif
int time_to_rfc822(char * out, size_t out_size_max, time_t t);

int get_select_breaker();
int send_select_break();
char * exec_with_ret(const char * a_cmd);
char * exec_with_ret_multistring(const char * a_cmd);

#ifdef __cplusplus
}
#endif

#endif
