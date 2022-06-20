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
#include <stdatomic.h>
#include <ctype.h>

#include "utlist.h"
//#include <errno.h>

#ifdef DAP_OS_ANDROID
  #include <android/log.h>
#endif

#ifndef _WIN32

  #include <pthread.h>
  #include <syslog.h>
  #include <signal.h>

#else // WIN32

  #include <stdlib.h>
  #include <windows.h>
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
const uint256_t uint256_1 = {.hi = uint128_0, .lo = uint128_1};
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
    pthread_mutex_lock(&s_log_mutex);
    DL_APPEND(s_log_buffer, l_log_string);
    ++s_log_count;
    pthread_cond_signal(&s_log_cond);
    pthread_mutex_unlock(&s_log_mutex);
}










/*	CRC32-C	*/
const  unsigned int g_crc32c_table[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};



const	char spaces[74] = {"                                                                          "};
#define PID_FMT "%6d"

void	_log_it_ext   (
		const char *	a_rtn_name,
            unsigned	a_line_no,
    enum dap_log_level  a_ll,
        const char *	a_fmt,
			...
			)
{
va_list arglist;
const char	lfmt [] = {"%02u-%02u-%04u %02u:%02u:%02u.%03u  "  PID_FMT "  %s [%s:%u] "};
char	out[1024] = {0};
int     olen, len;
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
char	out[512] = {0};
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
#endif

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

static int s_timers_count = 0;
static dap_timer_interface_t s_timers[DAP_INTERVAL_TIMERS_MAX];
#ifdef _WIN32
static CRITICAL_SECTION s_timers_lock;
#else
static pthread_mutex_t s_timers_lock;
#endif

void dap_interval_timer_deinit()
{
    for (int i = 0; i < s_timers_count; i++) {
        dap_interval_timer_delete(s_timers[i].timer);
    }
}

static int s_timer_find(void *a_timer)
{
    for (int i = 0; i < s_timers_count; i++) {
        if (s_timers[i].timer == a_timer) {
            return i;
        }
    }
    return -1;
}

#ifdef _WIN32
static void CALLBACK s_win_callback(PVOID a_arg, BOOLEAN a_always_true)
{
    UNUSED(a_always_true);
    s_timers[(size_t)a_arg].callback(s_timers[(size_t)a_arg].param);
}
#elif defined __MACH__
static void s_bsd_callback(int a_arg)
{
    s_timers[a_arg].callback(s_timers[a_arg].param);
}
#else
static void s_posix_callback(union sigval a_arg)
{
    s_timers[a_arg.sival_int].callback(s_timers[a_arg.sival_int].param);
}
#endif

/*!
 * \brief dap_interval_timer_create Create new timer object and set callback function to it
 * \param a_msec Timer period
 * \param a_callback Function to be called with timer period
 * \return pointer to timer object if success, otherwise return NULL
 */
void *dap_interval_timer_create(unsigned int a_msec, dap_timer_callback_t a_callback, void *a_param)
{
    if (s_timers_count == DAP_INTERVAL_TIMERS_MAX) {
        return NULL;
    }
#if (defined _WIN32)
    if (s_timers_count == 0) {
        InitializeCriticalSection(&s_timers_lock);
    }
    HANDLE l_timer;
    if (!CreateTimerQueueTimer(&l_timer, NULL, (WAITORTIMERCALLBACK)s_win_callback, (PVOID)(size_t)s_timers_count, a_msec, a_msec, 0)) {
        return NULL;
    }
    EnterCriticalSection(&s_timers_lock);
#elif (defined DAP_OS_DARWIN)
    if (s_timers_count == 0) {
        pthread_mutex_init(&s_timers_lock, NULL);
    }
    pthread_mutex_lock(&s_timers_lock);

    dispatch_queue_t l_queue = dispatch_queue_create("tqueue", 0);
    dispatch_source_t l_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, l_queue);
    dispatch_source_set_event_handler(l_timer, ^(void){s_bsd_callback(s_timers_count);});
    dispatch_time_t start = dispatch_time(DISPATCH_TIME_NOW, a_msec * 1000000);
    dispatch_source_set_timer(l_timer, start, a_msec * 1000000, 0);
    dispatch_resume(l_timer);
#else
    if (s_timers_count == 0) {
        pthread_mutex_init(&s_timers_lock, NULL);
    }
    timer_t l_timer;
    struct sigevent l_sig_event = { };
    l_sig_event.sigev_notify = SIGEV_THREAD;
    l_sig_event.sigev_value.sival_int = s_timers_count;
    l_sig_event.sigev_notify_function = s_posix_callback;
    if (timer_create(CLOCK_MONOTONIC, &l_sig_event, &l_timer)) {
        return NULL;
    }
    struct itimerspec l_period = { };
    l_period.it_interval.tv_sec = l_period.it_value.tv_sec = a_msec / 1000;
    l_period.it_interval.tv_nsec = l_period.it_value.tv_nsec = (a_msec % 1000) * 1000000;
    timer_settime(l_timer, 0, &l_period, NULL);
    pthread_mutex_lock(&s_timers_lock);
#endif
    s_timers[s_timers_count].timer = (void *)l_timer;
    s_timers[s_timers_count].callback = a_callback;
    s_timers[s_timers_count].param = a_param;
    s_timers_count++;
#ifdef WIN32
    LeaveCriticalSection(&s_timers_lock);
#else
    pthread_mutex_unlock(&s_timers_lock);
#endif
    return (void *)l_timer;
}

/*!
 * \brief dap_interval_timer_delete Delete existed timer object and stop callback function calls
 * \param a_timer A timer object created previously with dap_interval_timer_create
 * \return 0 if success, -1 otherwise
 */
int dap_interval_timer_delete(void *a_timer)
{
    if (!s_timers_count) {
        return -1;
    }
#if (defined _WIN32)
    EnterCriticalSection(&s_timers_lock);
#elif (defined DAP_OS_UNIX)
    pthread_mutex_lock(&s_timers_lock);
#endif
    int l_timer_idx = s_timer_find(a_timer);
    if (l_timer_idx == -1) {
        return -1;
    }
    for (int i = l_timer_idx; i < s_timers_count - 1; i++) {
        s_timers[i] = s_timers[i + 1];
    }
    s_timers_count--;
#ifdef _WIN32
    LeaveCriticalSection(&s_timers_lock);
    if (s_timers_count == 0) {
        DeleteCriticalSection(&s_timers_lock);
    }
    return !DeleteTimerQueueTimer(NULL, (HANDLE)a_timer, NULL);
#else
    pthread_mutex_unlock(&s_timers_lock);
    if (s_timers_count == 0) {
        pthread_mutex_destroy(&s_timers_lock);
    }
#ifdef DAP_OS_DARWIN
    dispatch_source_cancel(a_timer);
    return 0;
#elif defined(DAP_OS_UNIX)
    // POSIX timer delete
    return timer_delete((timer_t)a_timer);
#endif  // DAP_OS_UNIX

#endif  // _WIN32
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
