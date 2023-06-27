/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#define _POSIX_THREAD_SAFE_FUNCTIONS
#include <stdio.h>
#include <stdlib.h>
#include <time.h> /* 'nanosleep' */
#include <unistd.h> /* 'pipe', 'read', 'write' */
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>
#include <ctype.h>
#include "utlist.h"
#include "uthash.h"

#ifdef DAP_OS_ANDROID
  #include <android/log.h>
#endif

#ifndef _WIN32

  #include <pthread.h>
  #include <syslog.h>
  #include <signal.h>

#else // WIN32

  #include <stdlib.h>
  #include <process.h>
  #include <pthread.h>

  #include "win32/dap_console_manager.h"

  #define popen _popen
  #define pclose _pclose
#endif

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_file_utils.h"
#include "dap_lut.h"

#define DAP_LOG_USE_SPINLOCK    0
#define DAP_LOG_HISTORY         1

#define LAST_ERROR_MAX  255

#define LOG_TAG "dap_common"


#ifndef DAP_GLOBAL_IS_INT128
const uint128_t uint128_0 = {};
const uint128_t uint128_1 = {.hi = 0, .lo = 1};
#else // DAP_GLOBAL_IS_INT128
const uint128_t uint128_0 = 0;
const uint128_t uint128_1 = 1;
#endif // DAP_GLOBAL_IS_INT128

const uint256_t uint256_0 = {};
#ifndef DAP_GLOBAL_IS_INT128
const uint256_t uint256_1 = {.hi = {}, .lo = {.hi = 0, .lo = 1}};
#else // DAP_GLOBAL_IS_INT128
const uint256_t uint256_1 = {.hi = 0, .lo = 1};
#endif // DAP_GLOBAL_IS_INT128
const uint512_t uint512_0 = {};

static const char *s_log_level_tag[ 16 ] = {
    " [DBG] ", // L_DEBUG     = 0
    " [INF] ", // L_INFO      = 1,
    " [ * ] ", // L_NOTICE    = 2,
    " [MSG] ", // L_MESSAGE   = 3,
    " [DAP] ", // L_DAP       = 4,
    " [WRN] ", // L_WARNING   = 5,
    " [ATT] ", // L_ATT       = 6,
    " [ERR] ", // L_ERROR     = 7,
    " [ ! ] ", // L_CRITICAL  = 8,
    " [---] ", //             = 9
    " [---] ", //             = 10
    " [---] ", //             = 11
    " [---] ", //             = 12
    " [---] ", //             = 13
    " [---] ", //             = 14
    " [---] ", //             = 15
};

const char *s_ansi_seq_color[ 16 ] = {

    "\x1b[0;37;40m",   // L_DEBUG     = 0
    "\x1b[1;32;40m",   // L_INFO      = 2,
    "\x1b[0;32;40m",   // L_NOTICE    = 1,
    "\x1b[1;33;40m",   // L_MESSAGE   = 3,
    "\x1b[0;36;40m",   // L_DAP       = 4,
    "\x1b[1;35;40m",   // L_WARNING   = 5,
    "\x1b[1;36;40m",   // L_ATT       = 6,
    "\x1b[1;31;40m",   // L_ERROR     = 7,
    "\x1b[1;37;41m",   // L_CRITICAL  = 8,
    "", //             = 9
    "", //             = 10
    "", //             = 11
    "", //             = 12
    "", //             = 13
    "", //             = 14
    "", //             = 15
};

static unsigned int s_ansi_seq_color_len[16] = {0};

#ifdef _WIN32
    WORD log_level_colors[ 16 ] = {
        7,              // L_DEBUG
        10,              // L_INFO
         2,             // L_NOTICE
        11,             // L_MESSAGE
         9,             // L_DAP
        13,             // L_WARNING
        14,             // L_ATT
        12,             // L_ERROR
        (12 << 4) + 15, // L_CRITICAL
        7,
        7,
        7,
        7,
        7,
        7,
        7
      };
#endif

static volatile bool s_log_term_signal = false;
char* g_sys_dir_path = NULL;

static char s_last_error[LAST_ERROR_MAX]    = {'\0'},
    s_log_file_path[MAX_PATH]               = {'\0'},
    s_log_dir_path[MAX_PATH]                = {'\0'},
    s_log_tag_fmt_str[10]                   = {'\0'};

static enum dap_log_level s_dap_log_level = L_DEBUG;
static FILE *s_log_file = NULL;

#if DAP_LOG_USE_SPINLOCK
    static dap_spinlock_t log_spinlock;
#else
    static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static pthread_cond_t s_log_cond = PTHREAD_COND_INITIALIZER;
static volatile int s_log_count = 0;

static pthread_t s_log_thread = 0;
static void  *s_log_thread_proc(void *arg);

#define STR_LOG_BUF_MAX                       1000

typedef struct log_str_t {
    char str[STR_LOG_BUF_MAX];
    unsigned int offset;
    struct log_str_t *prev, *next;
} log_str_t;

static log_str_t *s_log_buffer = NULL;
static char* s_appname = NULL;

DAP_STATIC_INLINE void s_update_log_time(char *a_datetime_str) {
    time_t t = time(NULL);
    struct tm tmptime;
    if(localtime_r(&t, &tmptime))
        strftime(a_datetime_str, 32, "[%x-%X]", &tmptime);
}

/**
 * @brief set_log_level Sets the logging level
 * @param[in] ll logging level
 */
void dap_log_level_set( enum dap_log_level a_ll ) {
    s_dap_log_level = a_ll;
}

/**
 * @brief dap_get_appname
 * @return
 */
const char * dap_get_appname()
{
    return s_appname?s_appname: "dap";
}

/**
 * @brief dap_set_appname set application name in global s_appname variable
 * @param a_appname
 * @return
 */
void dap_set_appname(const char * a_appname)
{
    s_appname = dap_strdup(a_appname);

}

enum dap_log_level dap_log_level_get( void ) {
    return s_dap_log_level ;
}

/**
 * @brief dap_set_log_tag_width Sets the length of the label
 * @param[in] width Length not more than 99
 */
void dap_set_log_tag_width(size_t a_width) {

    if (a_width > 99) {
        dap_fprintf(stderr,"Can't set width %zd", a_width);
        return;
    }
    dap_snprintf(s_log_tag_fmt_str,sizeof (s_log_tag_fmt_str), "[%%%zds]\t",a_width);
}


/**
 * @brief this function is used for dap sdk modules initialization
 * @param a_console_title const char *: set console title. Can be result of dap_get_appname(). For example: cellframe-node
 * @param a_log_file_path const char *: path to log file. Saved in s_log_file_path variable. For example: C:\\Users\\Public\\Documents\\cellframe-node\\var\\log\\cellframe-node.log
 * @param a_log_dirpath const char *: path to log directory. Saved in s_log_dir_path variable. For example. C:\\Users\\Public\\Document\\cellframe-node\\var\\log
 * @return int. (0 if succcess, -1 if error)
 */
int dap_common_init( const char *a_console_title, const char *a_log_file_path, const char *a_log_dirpath) {

    // init randomer
    srand( (unsigned int)time(NULL) );
    (void) a_console_title;
    strncpy( s_log_tag_fmt_str, "[%s]\t",sizeof (s_log_tag_fmt_str));
    for (int i = 0; i < 16; ++i)
            s_ansi_seq_color_len[i] =(unsigned int) strlen(s_ansi_seq_color[i]);
    if ( a_log_file_path ) {
        s_log_file = fopen( a_log_file_path , "a" );
        if( s_log_file == NULL)
            s_log_file = fopen( a_log_file_path , "w" );
        if ( s_log_file == NULL ) {
            dap_fprintf( stderr, "Can't open log file %s \n", a_log_file_path );
            return -1;   //switch off show log in cosole if file not open
        }
        dap_stpcpy(s_log_dir_path,  a_log_dirpath);
        dap_stpcpy(s_log_file_path, a_log_file_path);
    }
    pthread_create( &s_log_thread, NULL, s_log_thread_proc, NULL );
    return 0;
}

#ifdef WIN32
int wdap_common_init( const char *a_console_title, const wchar_t *a_log_filename ) {

    // init randomer
    srand( (unsigned int)time(NULL) );
    (void) a_console_title;
    strncpy( s_log_tag_fmt_str, "[%s]\t",sizeof (s_log_tag_fmt_str));
    for (int i = 0; i < 16; ++i)
            s_ansi_seq_color_len[i] =(unsigned int) strlen(s_ansi_seq_color[i]);
    if ( a_log_filename ) {
        s_log_file = _wfopen( a_log_filename , L"a" );
        if( s_log_file == NULL)
            s_log_file = _wfopen( a_log_filename , L"w" );
        if ( s_log_file == NULL ) {
            dap_fprintf( stderr, "Can't open log file %ls to append\n", a_log_filename );
            return -1;
        }
        //dap_stpcpy(s_log_file_path, a_log_filename);
    }
    pthread_create( &s_log_thread, NULL, s_log_thread_proc, NULL );
    return 0;
}

#endif

/**
 * @brief dap_common_deinit Deinitialise
 */
void dap_common_deinit( ) {
    pthread_mutex_lock(&s_log_mutex);
    s_log_term_signal = true;
    pthread_cond_signal(&s_log_cond);
    pthread_mutex_unlock(&s_log_mutex);
    pthread_join(s_log_thread, NULL);
    if (s_log_file)
        fclose(s_log_file);
}


/**
 * @brief s_log_thread_proc
 * @param arg
 * @return
 */
static void *s_log_thread_proc(void *arg) {
    (void) arg;
    for ( ; !s_log_term_signal; ) {
        pthread_mutex_lock(&s_log_mutex);
        for ( ; s_log_count == 0 && !s_log_term_signal; ) {
            pthread_cond_wait(&s_log_cond, &s_log_mutex);
        }
        if (s_log_count) {
            log_str_t *elem, *tmp;
            if(s_log_file) {
                if(!dap_file_test(s_log_file_path)) {
                    fclose(s_log_file);
                    s_log_file = fopen(s_log_file_path, "a");
                    if( s_log_file == NULL) {
                        dap_mkdir_with_parents(s_log_dir_path);
                        s_log_file = fopen( s_log_file_path , "w" );
                    }
                }
            }
            DL_FOREACH_SAFE(s_log_buffer, elem, tmp) {
                if(s_log_file)
                    fwrite(elem->str + elem->offset, strlen(elem->str) - elem->offset, 1, s_log_file);
                fwrite(elem->str, strlen(elem->str), 1, stdout);

                DL_DELETE(s_log_buffer, elem);
                DAP_FREE(elem);
                --s_log_count;

                if(s_log_file)
                    fflush(s_log_file);
                fflush(stdout);
            }
        }
        pthread_mutex_unlock(&s_log_mutex);
    }
    return NULL;
}

#ifdef DAP_SYS_DEBUG
#ifdef __APPLE__
#define PID_FMT "%08x"
static inline uint64_t gettid(void)
{
uint64_t tid;

    pthread_threadid_np(NULL, &tid);
    return  tid;
}
#else
#define PID_FMT "%6d"
#endif

#define     SPACES  74
const   char spaces[SPACES] = {"                                                                          "};



void    _log_it_ext   (
                const char *    a_rtn_name,
            unsigned    a_line_no,
    enum dap_log_level  a_ll,
        const char *    a_fmt,
                        ...
                        )
{
va_list arglist;
const char      lfmt [] = {"%02u-%02u-%04u %02u:%02u:%02u.%03u  "  PID_FMT "  %s [%s:%u] "};
char    out[1024] = {0};
int     olen, len;
struct tm _tm;
struct timespec now;

    if ( (a_ll == -1) )
        return;

    if ( a_ll < s_dap_log_level )
        return;



	clock_gettime(CLOCK_REALTIME, &now);

#ifdef	WIN32
	localtime_s(&_tm, (time_t *)&now);
#else
	localtime_r((time_t *)&now, &_tm);
#endif

	olen = snprintf (out, sizeof(out), lfmt, _tm.tm_mday, _tm.tm_mon + 1, 1900 + _tm.tm_year,
			_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/(1024*1024),
			(unsigned) gettid(), s_log_level_tag[a_ll], a_rtn_name, a_line_no);


	if ( 0 < (len = (74 - olen)) )
		{
		memcpy(out + olen, spaces, len);
		olen += len;
		}

	/*
	** Format variable part of string line
	*/
	va_start (arglist, a_fmt);
	olen += vsnprintf(out + olen, sizeof(out) - olen, a_fmt, arglist);
	va_end (arglist);

	olen = MIN(olen, sizeof(out) - 1);

	/* Add <LF> at end of record*/
	out[olen++] = '\n';

    if(s_log_file)
    {
        fwrite(out, olen, 1,  s_log_file);
        fflush(s_log_file);
    }

    len = write(STDOUT_FILENO, out, olen);
}



void	_dump_it	(
		const char      *a_rtn_name,
    		unsigned	a_line_no,
        const char      *a_var_name,
		const void      *src,
		unsigned short	srclen
			)
{
#define HEXDUMP$SZ_WIDTH    80
const char	lfmt [] = {"%02u-%02u-%04u %02u:%02u:%02u.%03u  "  PID_FMT "  [%s:%u]  HEX Dump of <%.*s>, %u octets:\n"};
char	out[8192] = {0};
unsigned char *srcp = (unsigned char *) src, low, high;
unsigned olen = 0, i, j, len;
struct tm _tm;
struct timespec now;


    clock_gettime(CLOCK_REALTIME, &now);

    #ifdef	WIN32
    localtime_s(&_tm, (time_t *)&now);
    #else
    localtime_r((time_t *)&now, &_tm);
    #endif

    olen = snprintf (out, sizeof(out), lfmt, _tm.tm_mday, _tm.tm_mon + 1, 1900 + _tm.tm_year,
            _tm.tm_hour, _tm.tm_min, _tm.tm_sec, (unsigned) now.tv_nsec/(1024*1024),
            (unsigned) gettid(), a_rtn_name, a_line_no, 48, a_var_name, srclen);

    if(s_log_file)
    {
        fwrite(out, olen, 1,  s_log_file);
        fflush(s_log_file);
    }

    len = write(STDOUT_FILENO, out, olen);


	/*
	** Format variable part of string line
	*/
    memset(out, ' ', sizeof(out));

	for (i = 0; i < ((srclen / 16));  i++)
		{
		olen = snprintf(out, HEXDUMP$SZ_WIDTH, "\t+%04x:  ", i * 16);
		memset(out + olen, ' ', HEXDUMP$SZ_WIDTH - olen);

		for (j = 0; j < 16; j++, srcp++)
			{
			high = (*srcp) >> 4;
			low = (*srcp) & 0x0f;

			out[olen + j * 3] = high + ((high < 10) ? '0' : 'a' - 10);
			out[olen + j * 3 + 1] = low + ((low < 10) ? '0' : 'a' - 10);

			out[olen + 16*3 + 2 + j] = isprint(*srcp) ? *srcp : '.';
			}

		/* Add <LF> at end of record*/
		out[HEXDUMP$SZ_WIDTH - 1] = '\n';

        if(s_log_file)
        {
            fwrite(out, HEXDUMP$SZ_WIDTH, 1,  s_log_file);
            fflush(s_log_file);
        }

        len = write(STDOUT_FILENO, out, HEXDUMP$SZ_WIDTH);
    }

	if ( srclen % 16 )
		{
		olen = snprintf(out, HEXDUMP$SZ_WIDTH, "\t+%04x:  ", i * 16);
		memset(out + olen, ' ', HEXDUMP$SZ_WIDTH - olen);

		for (j = 0; j < srclen % 16; j++, srcp++)
			{
			high = (*srcp) >> 4;
			low = (*srcp) & 0x0f;

			out[olen + j * 3] = high + ((high < 10) ? '0' : 'a' - 10);
			out[olen + j * 3 + 1] = low + ((low < 10) ? '0' : 'a' - 10);

			out[olen + 16*3 + 2 + j] = isprint(*srcp) ? *srcp : '.';
			}

		/* Add <LF> at end of record*/
		out[HEXDUMP$SZ_WIDTH - 1] = '\n';

        if(s_log_file)
        {
            fwrite(out, HEXDUMP$SZ_WIDTH, 1,  s_log_file);
            fflush(s_log_file);
        }

        len = write(STDOUT_FILENO, out, HEXDUMP$SZ_WIDTH);
    }
}

#endif  /* DAP_SYS_DEBUG */

/**
 * @brief _log_it
 * @param log_tag
 * @param ll
 * @param fmt
 */
void _log_it(const char *a_log_tag, enum dap_log_level a_ll, const char *a_fmt, ...) {
    if ( a_ll < s_dap_log_level || a_ll >= 16 || !a_log_tag )
        return;
    log_str_t *l_log_string = DAP_NEW_Z(log_str_t);
    size_t offset2 = sizeof(l_log_string->str) - 2;
    strncpy(l_log_string->str, s_ansi_seq_color[a_ll], offset2);
    l_log_string->offset = s_ansi_seq_color_len[a_ll];
    s_update_log_time(l_log_string->str + l_log_string->offset);
    size_t offset = strlen(l_log_string->str);
    offset += dap_snprintf(l_log_string->str + offset, offset2, "%s[%s%s", s_log_level_tag[a_ll], a_log_tag, "] ");
    offset2 -= offset;
    va_list va;
    va_start( va, a_fmt );
    size_t l_offset = dap_vsnprintf(l_log_string->str + offset, offset2, a_fmt, va);
    offset = (l_offset < offset2) ? offset + l_offset : offset;
    offset2 = (l_offset < offset2) ? offset2 - offset : 0;
    va_end( va );
    char *dummy = (offset2 == 0) ? memcpy(&l_log_string->str[sizeof(l_log_string->str) - 6], "...\n\0", 5)
        : memcpy(&l_log_string->str[offset], "\n", 1);
    UNUSED(dummy);
#ifdef DAP_OS_ANDROID
    android_LogPriority l_alp;
    switch (a_ll) {
    case L_DEBUG:
        l_alp = ANDROID_LOG_DEBUG; break;
    case L_INFO:
    case L_NOTICE:
    case L_MSG:
        l_alp = ANDROID_LOG_INFO; break;
    case L_WARNING:
    case L_ATT:
        l_alp = ANDROID_LOG_WARN; break;
    case L_ERROR:
        l_alp = ANDROID_LOG_ERROR; break;
    case L_CRITICAL:
        l_alp = ANDROID_LOG_FATAL; break;
    default:
        l_alp = ANDROID_LOG_VERBOSE;
        break;
    }
    __android_log_write(l_alp, a_log_tag, l_log_string->str);
#endif
    pthread_mutex_lock(&s_log_mutex);
    DL_APPEND(s_log_buffer, l_log_string);
    ++s_log_count;
    pthread_cond_signal(&s_log_cond);
    pthread_mutex_unlock(&s_log_mutex);
}

static int s_check_and_fill_buffer_log(char **m, struct tm *a_tm_st, char *a_tmp)
{
	char *s = *m;
	struct tm l_tm;
	if (sscanf(a_tmp, "[%d/%d/%d-%d:%d:%d]", &l_tm.tm_mon, &l_tm.tm_mday, &l_tm.tm_year, &l_tm.tm_hour, &l_tm.tm_min, &l_tm.tm_sec) == 6) {
		l_tm.tm_mon--;
		if (a_tm_st->tm_year >= l_tm.tm_year &&
			a_tm_st->tm_mon >= l_tm.tm_mon &&
			a_tm_st->tm_mday >= l_tm.tm_mday &&
			a_tm_st->tm_hour >= l_tm.tm_hour &&
			a_tm_st->tm_min >= l_tm.tm_min &&
			a_tm_st->tm_sec >= l_tm.tm_sec) {
			size_t l_len = strlen(a_tmp);
            memcpy(s, a_tmp, l_len);
            s[l_len] = '\0';
			s += l_len;
			//*s++ = '\n';
			*m = s;
			return 1;
		}
	}
	return 0;
}
/**
 * @brief dap_log_get_item
 * @param a_start_time
 * @param a_limit
 * @return
 */
char *dap_log_get_item(time_t a_start_time, int a_limit)
{
#if 0
    UNUSED(a_start_time);
    UNUSED(a_limit);
#endif

	log_str_t *elem, *tmp;
	elem = tmp = NULL;
	char *l_buf = DAP_CALLOC(STR_LOG_BUF_MAX, a_limit);
	char *l_line = DAP_CALLOC(1, STR_LOG_BUF_MAX + 1);
	char *s = l_buf;

	//char *l_log_file = dap_strdup_printf("%s/var/log/%s.log", g_sys_dir_path, dap_get_appname());
	char *l_log_file = dap_strdup_printf("%s", s_log_file_path);
	FILE *fp = fopen(l_log_file, "r");
	if (!fp) {
		DAP_FREE(l_buf);
		DAP_FREE(l_line);
		return NULL;
	}

	struct tm *l_tm_st = localtime (&a_start_time);

	pthread_mutex_lock(&s_log_mutex);

	while (fgets(l_line, STR_LOG_BUF_MAX, fp)) {
		if (a_limit <= 0) break;
		a_limit -= s_check_and_fill_buffer_log(&s, l_tm_st, l_line);
	}

    DL_FOREACH_SAFE(s_log_buffer, elem, tmp) {
        if (!tmp->str[0]) continue;
		if (a_limit <= 0) break;
		a_limit -= s_check_and_fill_buffer_log(&s, l_tm_st, tmp->str);
	}

	pthread_mutex_unlock(&s_log_mutex);

	fclose(fp);
	DAP_FREE(l_line);

    return l_buf;
}

/**
 * @brief log_error Error log
 * @return
 */
const char *log_error()
{
    return s_last_error;
}


#if 1
#define INT_DIGITS 19   /* enough for 64 bit integer */

/**
 * @brief itoa  The function converts an integer num to a string equivalent and places the result in a string
 * @param[in] i number
 * @return
 */
char *dap_itoa(int i)
{
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char *p = buf + INT_DIGITS + 1; /* points to terminating '\0' */
    if (i >= 0) {
        do {
            *--p = '0' + (i % 10);
            i /= 10;
        } while (i != 0);
        return p;
    }
    else {      /* i < 0 */
        do {
            *--p = '0' - (i % 10);
            i /= 10;
        } while (i != 0);
        *--p = '-';
    }
    return p;
}

#endif

#define BREAK_LATENCY   1

static int breaker_set[2] = { -1, -1 };
static int initialized = 0;
#ifndef _WIN32
static struct timespec break_latency = { 0, BREAK_LATENCY * 1000 * 1000 };
#endif

int get_select_breaker( )
{
  if ( !initialized ) {
    if ( pipe(breaker_set) < 0 )
      return -1;
    else
      initialized = 1;
  }

  return breaker_set[0];
}

int send_select_break( )
{
  if ( !initialized )
    return -1;

  char buffer[1];

  #ifndef _WIN32
    if ( write(breaker_set[1], "\0", 1) <= 0 )
  #else
    if ( _write(breaker_set[1], "\0", 1) <= 0 )
  #endif
    return -1;

  #ifndef _WIN32
    nanosleep( &break_latency, NULL );
  #else
    Sleep( BREAK_LATENCY );
  #endif

  #ifndef _WIN32
    if ( read(breaker_set[0], buffer, 1) <= 0 || buffer[0] != '\0' )
  #else
    if ( _read(breaker_set[0], buffer, 1) <= 0 || buffer[0] != '\0' )
  #endif
    return -1;

  return 0;
}


int exec_with_ret(char** repl, const char * a_cmd) {
    FILE * fp;
    size_t buf_len = 0;
    char buf[4096] = {0};
    fp = popen(a_cmd, "r");
    if (!fp) {
        log_it(L_ERROR,"Cmd execution error: '%s'", strerror(errno));
        return(255);
    }
    memset(buf, 0, sizeof(buf));
    fgets(buf, sizeof(buf) - 1, fp);
    buf_len = strlen(buf);
    if(repl) {
        if(buf[buf_len - 1] == '\n')
            buf[buf_len - 1] ='\0';
        *repl = strdup(buf);
    }
    return pclose(fp);
}

#ifdef ANDROID1
static u_long myNextRandom = 1;

double atof(const char *nptr)
{
    return (strtod(nptr, NULL));
}

int rand(void)
{
    return (int)((myNextRandom = (1103515245 * myNextRandom) + 12345) % ((u_long)RAND_MAX + 1));
}

void srand(u_int seed)
{
    myNextRandom = seed;
}

#endif

#if 0

/**
 * @brief exec_with_ret Executes a command with result return
 * @param[in] a_cmd Command
 * @return Result
 */
char * exec_with_ret(const char * a_cmd)
{
    FILE * fp;
    size_t buf_len = 0;
    char buf[4096] = {0};
    fp= popen(a_cmd, "r");
    if (!fp) {
        goto FIN;
    }
    memset(buf,0,sizeof(buf));
    fgets(buf,sizeof(buf)-1,fp);
    pclose(fp);
    buf_len=strlen(buf);
    if(buf[buf_len-1] =='\n')buf[buf_len-1] ='\0';
FIN:
    return strdup(buf);
}
#endif

/**
 * @brief exec_with_ret_multistring performs a command with a result return in the form of a multistring
 * @param[in] a_cmd Coomand
 * @return Return
 */
char * exec_with_ret_multistring(const char * a_cmd)
{
    FILE * fp;
    size_t buf_len = 0;
    char buf[4096] = {0};
    fp= popen(a_cmd, "r");
    if (!fp) {
        goto FIN;
    }
    memset(buf,0,sizeof(buf));
    char retbuf[4096] = {0};
    while(fgets(buf,sizeof(buf)-1,fp)) {
        strcat(retbuf, buf);
    }
    pclose(fp);
    buf_len=strlen(retbuf);
    if(retbuf[buf_len-1] =='\n')retbuf[buf_len-1] ='\0';
FIN:
    return strdup(retbuf);
}

static const char l_possible_chars[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/**
 * @brief random_string_fill Filling a string with random characters
 * @param[out] str A pointer to a char array
 * @param[in] length The length of the array or string
 */
void dap_random_string_fill(char *str, size_t length) {
    for(size_t i = 0; i < length; i++)
        str[i] = l_possible_chars[
                rand() % (sizeof(l_possible_chars) - 1)];
}

/**
 * @brief random_string_create Generates a random string
 * @param[in] a_length lenght
 * @return a pointer to an array
 */
char * dap_random_string_create_alloc(size_t a_length)
{
    char * ret = DAP_NEW_SIZE(char, a_length+1);
    size_t i;
    for(i=0; i<a_length; ++i) {
        int index = rand() % (sizeof(l_possible_chars)-1);
        ret[i] = l_possible_chars[index];
    }
    return ret;
}

#if 0

#define MAX_PRINT_WIDTH 100

static void _printrepchar(char c, size_t count) {
    assert(count < MAX_PRINT_WIDTH &&
           "Too many characters");
    static char buff[MAX_PRINT_WIDTH];
    memset(buff, (int)c, count);
    printf("%s\n", buff);
}


/**
 * @brief The function displays a dump
 * @param[in] data The data dump you want to display
 * @param[in] size The size of the data whose dump you want to display
 *
 * The function displays a dump, for example an array, in hex format
*/
void dap_dump_hex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((const unsigned char*)data)[i]);
        if (((const unsigned char*)data)[i] >= ' ' && ((const unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((const char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    _printrepchar('-', 70);
}

void *memzero(void *a_buf, size_t n)
{
    memset(a_buf,0,n);
    return a_buf;
}

#endif

/**
 * Convert binary data to binhex encoded data.
 *
 * out output buffer, must be twice the number of bytes to encode.
 * len is the size of the data in the in[] buffer to encode.
 * return the number of bytes encoded, or -1 on error.
 */
size_t dap_bin2hex(char *a_out, const void *a_in, size_t a_len)
{
    size_t ct = a_len;
    static char hex[] = "0123456789ABCDEF";
    const uint8_t *l_in = (const uint8_t *)a_in;

    if(!a_in || !a_out )
        return 0;
    // hexadecimal lookup table

    while(ct-- > 0){
        *a_out++ = hex[*l_in >> 4];
        *a_out++ = hex[*l_in++ & 0x0F];
    }
    return a_len;
}

/**
 * Convert binhex encoded data to binary data
 *
 * len is the size of the data in the in[] buffer to decode, and must be even.
 * out outputbuffer must be at least half of "len" in size.
 * The buffers in[] and out[] can be the same to allow in-place decoding.
 * return the number of bytes encoded, or 0 on error.
 */
size_t dap_hex2bin(uint8_t *a_out, const char *a_in, size_t a_len)
{
    // '0'-'9' = 0x30-0x39
    // 'a'-'f' = 0x61-0x66
    // 'A'-'F' = 0x41-0x46
    int ct = a_len;
    if (!a_in || !a_out)
        return 0;
    while(ct > 0) {
        char ch1;
        if (ct == (int)a_len && a_len & 1)
            ch1 = 0;
        else
            ch1 = ((*a_in >= 'a') ? (*a_in++ - 'a' + 10) : ((*a_in >= 'A') ? (*a_in++ - 'A' + 10) : (*a_in++ - '0'))) << 4;
        char ch2 = ((*a_in >= 'a') ? (*a_in++ - 'a' + 10) : ((*a_in >= 'A') ? (*a_in++ - 'A' + 10) : (*a_in++ - '0')));
        *a_out++ =(uint8_t) ch1 + (uint8_t) ch2;
        ct -= 2;
    }
    return a_len;
}

/**
 * Convert string to digit
 */
void dap_digit_from_string(const char *num_str, void *raw, size_t raw_len)
{
    if(!num_str)
        return;
    uint64_t val;

    if(!strncasecmp(num_str, "0x", 2)) {
        val = strtoull(num_str + 2, NULL, 16);
    }else {
        val = strtoull(num_str, NULL, 10);
    }

    // for LITTLE_ENDIAN (Intel), do nothing, otherwise swap bytes
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    val = le64toh(val);
#endif
    memset(raw, 0, raw_len);
    memcpy(raw, &val, min(raw_len, sizeof(uint64_t)));
}

typedef union {
  uint16_t   addrs[4];
  uint64_t  addr;
} node_addr_t;

void dap_digit_from_string2(const char *num_str, void *raw, size_t raw_len)
{
    if(!num_str)
        return;

    uint64_t val;

    if(!strncasecmp(num_str, "0x", 2)) {
        val = strtoull(num_str + 2, NULL, 16);
    }else {
        node_addr_t *nodeaddr = (node_addr_t *)&val;
        sscanf( num_str, "%hx::%hx::%hx::%hx", &nodeaddr->addrs[3], &nodeaddr->addrs[2], &nodeaddr->addrs[1], &nodeaddr->addrs[0] );
    }

    // for LITTLE_ENDIAN (Intel), do nothing, otherwise swap bytes
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    val = le64toh(val);
#endif
    memset(raw, 0, raw_len);
    memcpy(raw, &val, min(raw_len, sizeof(uint64_t)));
}


/*!
 * \brief Execute shell command silently
 * \param a_cmd command line
 * \return 0 if success, -1 otherwise
 */
int exec_silent(const char * a_cmd) {

#ifdef _WIN32
    PROCESS_INFORMATION p_info;
    STARTUPINFOA s_info;

    memset(&s_info, 0, sizeof(s_info));
    memset(&p_info, 0, sizeof(p_info));

    s_info.cb = sizeof(s_info);
    char cmdline[512] = {'\0'};
    strcat(cmdline, "C:\\Windows\\System32\\cmd.exe /c ");
    strcat(cmdline, a_cmd);

    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0x08000000, NULL, NULL, &s_info, &p_info)) {
        WaitForSingleObject(p_info.hProcess, 0xffffffff);
        CloseHandle(p_info.hProcess);
        CloseHandle(p_info.hThread);
        return 0;
    }
    else {
        return -1;
    }
#else
    return execl(".","%s",a_cmd,NULL);
#endif
}

typedef struct dap_timer_interface {
#ifdef DAP_OS_DARWIN
    dispatch_source_t timer;
#else
    void *timer;
#endif
    dap_timer_callback_t callback;
    void *param;
    UT_hash_handle hh;
} dap_timer_interface_t;
static dap_timer_interface_t *s_timers_map;
static pthread_rwlock_t s_timers_rwlock;

void dap_interval_timer_init()
{
    s_timers_map = NULL;
    pthread_rwlock_init(&s_timers_rwlock, NULL);
}

void dap_interval_timer_deinit() {
    pthread_rwlock_wrlock(&s_timers_rwlock);
    dap_timer_interface_t *l_cur_timer = NULL, *l_tmp;
    HASH_ITER(hh, s_timers_map, l_cur_timer, l_tmp) {
        HASH_DEL(s_timers_map, l_cur_timer);
        dap_interval_timer_disable(l_cur_timer->timer);
        DAP_FREE(l_cur_timer);
    }
    pthread_rwlock_unlock(&s_timers_rwlock);
    pthread_rwlock_destroy(&s_timers_rwlock);
}

#ifdef DAP_OS_LINUX
static void s_posix_callback(union sigval a_arg)
{
    void *l_timer_ptr = a_arg.sival_ptr;
#elif defined (DAP_OS_WINDOWS)
static void CALLBACK s_win_callback(PVOID a_arg, BOOLEAN a_always_true)
{
    UNUSED(a_always_true);
    void *l_timer_ptr = a_arg;
#elif defined (DAP_OS_DARWIN)
static void s_bsd_callback(void *a_arg)
{
    void *l_timer_ptr = &a_arg;
#else
#error "Timaer callback is undefined for your platform"
#endif
    if (!l_timer_ptr) {
        log_it(L_ERROR, "Timer cb arg is NULL");
        return;
    }
    pthread_rwlock_rdlock(&s_timers_rwlock);
    dap_timer_interface_t *l_timer = NULL;
    HASH_FIND_PTR(s_timers_map, l_timer_ptr, l_timer);
    pthread_rwlock_unlock(&s_timers_rwlock);
    if (l_timer && l_timer->callback) {
        //log_it(L_INFO, "Fire %p", l_timer_ptr);
        l_timer->callback(l_timer->param);
    } else {
        log_it(L_WARNING, "Timer '%p' is not initialized", l_timer_ptr);
    }
}

/*!
 * \brief dap_interval_timer_create Create new timer object and set callback function to it
 * \param a_msec Timer period
 * \param a_callback Function to be called with timer period
 * \return pointer to timer object if success, otherwise return NULL
 */
dap_interval_timer_t dap_interval_timer_create(unsigned int a_msec, dap_timer_callback_t a_callback, void *a_param) {
    dap_timer_interface_t *l_timer_obj = DAP_NEW_Z(dap_timer_interface_t);
    l_timer_obj->callback   = a_callback;
    l_timer_obj->param      = a_param;
#if (defined _WIN32)
    if (!CreateTimerQueueTimer(&l_timer_obj->timer , NULL, (WAITORTIMERCALLBACK)s_win_callback, &l_timer_obj->timer, a_msec, a_msec, 0)) {
        return NULL;
    }
#elif (defined DAP_OS_DARWIN)
    dispatch_queue_t l_queue = dispatch_queue_create("tqueue", 0);
    l_timer_obj->timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, l_queue);
    dispatch_source_set_event_handler((l_timer_obj->timer), ^(void){ s_bsd_callback((void*)(l_timer_obj->timer)); });
    dispatch_time_t start = dispatch_time(DISPATCH_TIME_NOW, a_msec * 1000000);
    dispatch_source_set_timer(l_timer_obj->timer, start, a_msec * 1000000, 0);
    dispatch_resume(l_timer_obj->timer);
#else
    struct sigevent l_sig_event = { };
    l_sig_event.sigev_notify = SIGEV_THREAD;
    l_sig_event.sigev_value.sival_ptr = &l_timer_obj->timer;
    l_sig_event.sigev_notify_function = s_posix_callback;
    if (timer_create(CLOCK_MONOTONIC, &l_sig_event, &(l_timer_obj->timer))) {
        return NULL;
    }
    struct itimerspec l_period = { };
    l_period.it_interval.tv_sec = l_period.it_value.tv_sec = a_msec / 1000;
    l_period.it_interval.tv_nsec = l_period.it_value.tv_nsec = (a_msec % 1000) * 1000000;
    timer_settime(l_timer_obj->timer, 0, &l_period, NULL);
#endif
    pthread_rwlock_wrlock(&s_timers_rwlock);
    HASH_ADD_PTR(s_timers_map, timer, l_timer_obj);
    pthread_rwlock_unlock(&s_timers_rwlock);
    log_it(L_DEBUG, "Interval timer %p created", &l_timer_obj->timer);
    return (dap_interval_timer_t)l_timer_obj->timer;
}

int dap_interval_timer_disable(dap_interval_timer_t a_timer) {
#ifdef _WIN32
    return !DeleteTimerQueueTimer(NULL, (HANDLE)a_timer, NULL);
#elif defined (DAP_OS_DARWIN)
    dispatch_source_cancel((dispatch_source_t)a_timer);
    return 0;
#else
    return timer_delete((timer_t)a_timer);
#endif
}

void dap_interval_timer_delete(dap_interval_timer_t a_timer) {
    pthread_rwlock_wrlock(&s_timers_rwlock);
    dap_timer_interface_t *l_timer = NULL;
    HASH_FIND_PTR(s_timers_map, &a_timer, l_timer);
    if (l_timer) {
        HASH_DEL(s_timers_map, l_timer);
        dap_interval_timer_disable(l_timer->timer);
        DAP_FREE(l_timer);
    }
    pthread_rwlock_unlock(&s_timers_rwlock);
}

/**
 * @brief dap_lendian_get16 Get uint16 from little endian memory
 * @param a_buf a buffer read from
 * @return uint16 in host endian memory
 */
uint16_t dap_lendian_get16(const uint8_t *a_buf)
{
    uint8_t u = *a_buf;
    return (uint16_t)(*(a_buf + 1)) << 8 | u;
}

/**
 * @brief dap_lendian_put16 Put uint16 to little endian memory
 * @param buf a buffer write to
 * @param val uint16 in host endian memory
 * @return none
 */
void dap_lendian_put16(uint8_t *a_buf, uint16_t a_val)
{
    *(a_buf) = a_val;
    *(a_buf + 1) = a_val >> 8;
}

/**
 * @brief dap_lendian_get32 Get uint32 from little endian memory
 * @param a_buf a buffer read from
 * @return uint32 in host endian memory
 */
uint32_t dap_lendian_get32(const uint8_t *a_buf)
{
    uint16_t u = dap_lendian_get16(a_buf);
    return (uint32_t)dap_lendian_get16(a_buf + 2) << 16 | u;
}

/**
 * @brief dap_lendian_put32 Put uint32 to little endian memory
 * @param buf a buffer write to
 * @param val uint32 in host endian memory
 * @return none
 */
void dap_lendian_put32(uint8_t *a_buf, uint32_t a_val)
{
    dap_lendian_put16(a_buf, a_val);
    dap_lendian_put16(a_buf + 2, a_val >> 16);
}

/**
 * @brief dap_lendian_get64 Get uint64 from little endian memory
 * @param a_buf a buffer read from
 * @return uint64 in host endian memory
 */
uint64_t dap_lendian_get64(const uint8_t *a_buf)
{
    uint32_t u = dap_lendian_get32(a_buf);
    return (uint64_t)dap_lendian_get32(a_buf + 4) << 32 | u;
}

/**
 * @brief dap_lendian_put64 Put uint64 to little endian memory
 * @param buf a buffer write to
 * @param val uint64 in host endian memory
 * @return none
 */
void dap_lendian_put64(uint8_t *a_buf, uint64_t a_val)
{
    dap_lendian_put32(a_buf, a_val);
    dap_lendian_put32(a_buf + 4, a_val >> 32);
}

int dap_is_alpha_and_(char e)
{
    if ((e >= '0' && e <= '9')||(e >= 'a' && e <= 'z')||(e >= 'A' && e <= 'Z')||(e == '_')) return 1;
    return 0;
}

int dap_is_alpha(char e)
{
    if ((e >= '0' && e <= '9')||(e >= 'a' && e <= 'z')||(e >= 'A' && e <= 'Z')) return 1;
    return 0;
}
int dap_is_digit(char e)
{
    if ((e >= '0' && e <= '9')) return 1;
    return 0;
}
char **dap_parse_items(const char *a_str, char a_delimiter, int *a_count, const int a_only_digit)
{
    int l_count_temp = *a_count = 0;
    int l_len_str = strlen(a_str);
    if (l_len_str == 0) return NULL;
    char *s, *l_temp_str;
    s = l_temp_str = dap_strdup(a_str);

    int l_buf = 0;
    for (int i = 0; i < l_len_str; i++) {
        if (s[i] == a_delimiter && !l_buf) {
            s[i] = 0;
            continue;
        }
        if (s[i] == a_delimiter && l_buf) {
            s[i] = 0;
            l_buf = 0;
            continue;
        }
        if (!dap_is_alpha(s[i]) && l_buf) {
            s[i] = 0;
            l_buf = 0;
            continue;
        }
        if (!dap_is_alpha(s[i]) && !l_buf) {
            s[i] = 0;
            continue;
        }
        if (a_only_digit) {
            if (dap_is_digit(s[i])) {
                l_buf++;
                if (l_buf == 1) l_count_temp++;
                continue;
            }
        } else if (dap_is_alpha(s[i])) {
            l_buf++;
            if (l_buf == 1) l_count_temp++;
            continue;
        }
        if (!dap_is_alpha(s[i])) {
            l_buf = 0;
            s[i] = 0;
            continue;
        }
    }

    s = l_temp_str;
    if (l_count_temp == 0) {
        free (l_temp_str);
        return NULL;
    }

    char **lines = DAP_CALLOC(l_count_temp, sizeof (void *));
    for (int i = 0; i < l_count_temp; i++) {
        while (*s == 0) s++;
        lines[i] = strdup(s);
        s = strchr(s, '\0');
        s++;
    }

    free (l_temp_str);
    *a_count = l_count_temp;
    return lines;
}

#ifdef DAP_OS_WINDOWS
size_t dap_readv(HANDLE a_hf, iovec_t const *a_bufs, int a_bufs_num, DWORD *a_err) {
    if (!a_bufs || !a_bufs_num) {
        return -1;
    }
    DWORD l_ret = 0;
    bool l_is_aligned = false;
    if (!l_is_aligned) {
        for (iovec_t const *cur_buf = a_bufs, *end = a_bufs + a_bufs_num; cur_buf < end; ++cur_buf) {
            DWORD l_read = 0;
            if (ReadFile(a_hf, (char*)cur_buf->iov_base, cur_buf->iov_len, &l_read, 0) == FALSE) {
                if (a_err)
                    *a_err = GetLastError();
                return -1;
            }
            l_ret += l_read;
        }
        return l_ret;
    }

    size_t l_total_bufs_size = 0;
    for (iovec_t const *i = a_bufs, *end = a_bufs + a_bufs_num; i < end; ++i)
        l_total_bufs_size += i->iov_len;
    l_ret += l_total_bufs_size;

    size_t l_page_size = dap_pagesize();
    int l_pages_count = (l_total_bufs_size + l_page_size - 1) / l_page_size;
    PFILE_SEGMENT_ELEMENT l_seg_arr = DAP_PAGE_ALMALLOC(sizeof(FILE_SEGMENT_ELEMENT) * (l_pages_count + 1)),
            l_cur_seg = l_seg_arr;
    /* FILE_SEGMENT_ELEMENT l_seg_arr[l_pages_count + 1], *l_cur_seg = l_seg_arr; */
    for (iovec_t const *i = a_bufs, *end = a_bufs + a_bufs_num; i < end; ++i)
        for (size_t j = 0; j < i->iov_len; j += l_page_size, ++l_cur_seg)
            l_cur_seg->Buffer = PtrToPtr64((((char*)i->iov_base) + j));
    l_cur_seg->Buffer = 0;

    /* lol */
    OVERLAPPED l_ol = {
        .hEvent = CreateEvent(0, TRUE, FALSE, 0)
    };

    l_total_bufs_size = l_pages_count * l_page_size;
    if (!ReadFileScatter(a_hf, l_seg_arr, l_total_bufs_size, 0, &l_ol)) {
        DWORD l_err = GetLastError();
        if (l_err != ERROR_IO_PENDING) {
            if (a_err)
                *a_err = GetLastError();
            CloseHandle(l_ol.hEvent);
            DAP_PAGE_ALFREE(l_seg_arr);
            return -1;
        }
        if (!GetOverlappedResult(a_hf, &l_ol, &l_ret, TRUE)) {
            if (a_err)
                *a_err = GetLastError();
            CloseHandle(l_ol.hEvent);
            DAP_PAGE_ALFREE(l_seg_arr);
            return -1;
        }
    }
    CloseHandle(l_ol.hEvent);
    DAP_PAGE_ALFREE(l_seg_arr);
    return l_ret;
}

size_t dap_writev(HANDLE a_hf, const char* a_filename, iovec_t const *a_bufs, int a_bufs_num, DWORD *a_err) {
    if (!a_bufs || !a_bufs_num) {
        log_it(L_ERROR, "Bad input data");
        return -1;
    }
    DWORD l_ret = 0;
    bool l_is_aligned = false;
    /* For a buffer which is not aligned to the page size, we use regular I/O */
    if (!l_is_aligned) {
        for (iovec_t const *cur_buf = a_bufs, *end = a_bufs + a_bufs_num; cur_buf < end; ++cur_buf) {
            DWORD l_written = 0;
            if (!WriteFile(a_hf, (char const*)cur_buf->iov_base, cur_buf->iov_len, &l_written, NULL)) {
                if (a_err)
                    *a_err = GetLastError();
                return -1;
            }
            l_ret += l_written;
        }
        return l_ret;
    }

    size_t l_total_bufs_size = 0, l_file_size = 0;
    for (iovec_t const *i = a_bufs, *end = a_bufs + a_bufs_num; i < end; ++i)
        l_total_bufs_size += i->iov_len;
    l_ret += l_total_bufs_size;

    size_t l_page_size = dap_pagesize();
    int l_pages_count = (l_total_bufs_size + l_page_size - 1) / l_page_size;
    PFILE_SEGMENT_ELEMENT l_seg_arr = DAP_PAGE_ALMALLOC(sizeof(FILE_SEGMENT_ELEMENT) * (l_pages_count + 1)),
            l_cur_seg = l_seg_arr;
    int l_idx = 0;
    for (iovec_t const *cur_buf = a_bufs; l_idx++ < a_bufs_num; ++cur_buf)
        for (size_t j = 0; j < cur_buf->iov_len; j += l_page_size)
            l_cur_seg++->Buffer = PtrToPtr64((((char*)cur_buf->iov_base) + j));
    l_cur_seg->Buffer = 0;

    /* lol */
    OVERLAPPED l_ol = {
        .Offset = 0xFFFFFFFF, .OffsetHigh = 0xFFFFFFFF,
        .hEvent = CreateEvent(0, TRUE, FALSE, 0)
    };

    /* Let's check whether it's file tail */
    if (l_total_bufs_size & (l_page_size - 1)) {
        l_file_size = l_total_bufs_size;
        l_total_bufs_size = l_pages_count * l_page_size;
    }

    DWORD l_err;
    l_err = GetLastError();
    if (!WriteFileGather(a_hf, l_seg_arr, l_total_bufs_size * 3, 0, &l_ol)) {
        l_err = GetLastError();
        if (l_err != ERROR_IO_PENDING) {
            if (a_err)
                *a_err = l_err;
            DAP_PAGE_ALFREE(l_seg_arr);
            CloseHandle(l_ol.hEvent);
            log_it(L_ERROR, "Write file err: %d", l_err);
            return -1;
        }
        DWORD l_tmp;
        if (!GetOverlappedResult(a_hf, &l_ol, &l_tmp, TRUE)) {
            l_err = GetLastError();
            if (a_err)
                *a_err = l_err;
            DAP_PAGE_ALFREE(l_seg_arr);
            CloseHandle(l_ol.hEvent);
            log_it(L_ERROR, "Async writing failure, err %d", l_err);
            return -1;
        }
        if (l_tmp < l_ret)
            l_ret = l_tmp;
    }
    CloseHandle(l_ol.hEvent);
    DAP_PAGE_ALFREE(l_seg_arr);
    /* Set the proper file size if needed */
    if (l_file_size) {
        HANDLE l_hf = CreateFile(a_filename, GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 0, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
                                 0);
        if (l_hf == INVALID_HANDLE_VALUE) {
            if (a_err)
                *a_err = GetLastError();
            return -1;
        }

        LARGE_INTEGER l_offs = { };
        l_offs.QuadPart = l_file_size;
        if (!SetFilePointerEx(l_hf, l_offs, &l_offs, FILE_BEGIN)) {
            CloseHandle(l_hf);
            if (a_err)
                *a_err = GetLastError();
            log_it(L_ERROR, "File pointer setting err: %d", l_err);
            return -1;
        }
        if (!SetEndOfFile(l_hf)) {
            if (a_err)
                *a_err = GetLastError();
            CloseHandle(l_hf);
            log_it(L_ERROR, "EOF setting err: %d", l_err);
            return -1;
        }
        CloseHandle(l_hf);
    }
    return l_ret;
}
#endif


#ifdef  DAP_SYS_DEBUG
dap_memstat_rec_t    *g_memstat [MEMSTAT$K_MAXNR];                      /* Array to keep pointers to module/facility specific memstat vecros */
static pthread_rwlock_t     s_memstat_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint64_t             s_memstat_nr;                               /* A number of pointers in the <g_memstat> */

int     dap_memstat_reg (
                dap_memstat_rec_t   *a_memstat_rec
                )
{
uint64_t    l_nr;
int l_rc;

        l_rc = pthread_rwlock_wrlock(&s_memstat_lock);

        l_nr = s_memstat_nr;
        if ( s_memstat_nr < MEMSTAT$K_MAXNR )
            s_memstat_nr += 1;

        l_rc = pthread_rwlock_unlock(&s_memstat_lock);

        if ( !( l_nr < MEMSTAT$K_MAXNR) )
            return  log_it(L_ERROR, "[<%.*s>, %zu octets] -- No free slot for memstat vector",
                    a_memstat_rec->fac_len, a_memstat_rec->fac_name, a_memstat_rec->alloc_sz), -ENOMEM;

        g_memstat[l_nr] = a_memstat_rec;

        return  log_it(L_INFO, "[<%.*s>, %zu octets] has been registered",
                    a_memstat_rec->fac_len, a_memstat_rec->fac_name, a_memstat_rec->alloc_sz), 0;
}


void    dap_memstat_show (void)
{
dap_memstat_rec_t   *l_memstat_rec;

    for ( uint64_t i = 0; i < s_memstat_nr; i++)
    {
        if ( (l_memstat_rec = g_memstat[i]) )
            log_it(L_INFO, "[<%.*s>, %zu octets] allocations/deallocations: %lld/%lld (%lld octets still is allocated)",
                l_memstat_rec->fac_len, l_memstat_rec->fac_name, l_memstat_rec->alloc_sz,
                l_memstat_rec->alloc_nr, l_memstat_rec->free_nr,
                (l_memstat_rec->alloc_nr - l_memstat_rec->free_nr) * l_memstat_rec->alloc_sz);
    }
}



#endif  /* DAP_SYS_DEBUG */

