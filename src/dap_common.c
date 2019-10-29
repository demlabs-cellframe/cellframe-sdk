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
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <time.h> /* 'nanosleep' */
#include <unistd.h> /* 'pipe', 'read', 'write' */
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>
#include <stdatomic.h>
#include "utlist.h"
#include <errno.h>

#ifdef DAP_OS_ANDROID
  #include <android/log.h>
#endif

#ifndef _WIN32

  #include <pthread.h>
  #include <syslog.h>

#else // WIN32

  #include <stdlib.h>
  #include <windows.h>
  #include <process.h>
  #include <pthread.h>

  #include "win32/dap_console_manager.h"

  #define popen _popen
  #define pclose _pclose
  #define pipe(pfds) _pipe(pfds, 4096, 0x8000)

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

static const char *log_level_tag[ 16 ] = {
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
unsigned int l_sys_dir_path_len = 0;
char s_sys_dir_path[MAX_PATH] = {'\0'};

static char s_last_error[LAST_ERROR_MAX]    = {'\0'},
    s_log_file_path[MAX_PATH]               = {'\0'},
    s_log_tag_fmt_str[10]                   = {'\0'};

static enum dap_log_level dap_log_level = L_DEBUG;
static FILE *s_log_file = NULL;

#if DAP_LOG_USE_SPINLOCK
    static dap_spinlock_t log_spinlock;
#else
    static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static pthread_cond_t s_log_cond = PTHREAD_COND_INITIALIZER;
static volatile int count = 0;

static pthread_t s_log_thread = 0;
static void  *s_log_thread_proc(void *arg);

typedef struct log_str {
    char str[400];
    unsigned int offset;
    struct log_str *prev, *next;
} log_str;

static log_str *log_buffer = NULL;

DAP_STATIC_INLINE void s_update_log_time(char *a_datetime_str) {
    time_t t = time(NULL);
    struct tm *tmptime = localtime(&t);
    strftime(a_datetime_str, 32, "[%x-%X]", tmptime);
}

/**
 * @brief set_log_level Sets the logging level
 * @param[in] ll logging level
 */
void dap_log_level_set( enum dap_log_level a_ll ) {
    dap_log_level = a_ll;
}

enum dap_log_level dap_log_level_get( void ) {
    return dap_log_level ;
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
 * @brief dap_common_init initialise
 * @param[in] a_log_file
 * @return
 */
int dap_common_init( const char *a_console_title, const char *a_log_filename ) {
    srand( (unsigned int)time(NULL) );

    /*
    #ifdef _WIN32
        SetupConsole( a_console_title, L"Lucida Console", 12, 20 );
    #endif
    */
    strncpy( s_log_tag_fmt_str, "[%s]\t",sizeof (s_log_tag_fmt_str));
    if ( a_log_filename ) {
        return 0;
        for (int i = 0; i < 16; ++i)
                s_ansi_seq_color_len[i] = strlen(s_ansi_seq_color[i]);
        s_log_file = fopen( a_log_filename , "a" );
        if ( s_log_file == NULL ) {
            dap_fprintf( stderr, "Can't open log file %s to append\n", a_log_filename );
            return -1;
        }
        dap_stpcpy(s_log_file_path, a_log_filename);
    }
    pthread_create( &s_log_thread, NULL, s_log_thread_proc, NULL );
    return 0;
}

/**
 * @brief dap_common_deinit Deinitialise
 */
void dap_common_deinit( ) {
    s_log_term_signal = true;
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
    for ( ; !s_log_term_signal; ) {
        pthread_mutex_lock(&s_log_mutex);
        for ( ; count == 0; ) {
            pthread_cond_wait(&s_log_cond, &s_log_mutex);
        }
        log_str *elem, *tmp;
        if(s_log_file) {
            if(!dap_file_test(s_log_file_path)) {
                fclose(s_log_file);
                s_log_file = fopen(s_log_file_path, "a");
            }
            if(s_log_file) {
                DL_FOREACH_SAFE(log_buffer, elem, tmp) {
                    fwrite(elem->str + elem->offset, strlen(elem->str) - elem->offset, 1, s_log_file);
                    fwrite(elem->str + elem->offset, strlen(elem->str) - elem->offset, 1, stdout);
                    DL_DELETE(log_buffer, elem);
                    DAP_FREE(elem);
                    --count;
                    fflush(s_log_file);
                    fflush(stdout);
                }
            }
        }
        pthread_mutex_unlock(&s_log_mutex);
    }
    pthread_exit(NULL);
}

void _log_it(const char *log_tag, enum dap_log_level ll, const char *fmt, ...) {
    if ( ll < dap_log_level || ll >= 16 || !log_tag )
        return;
    log_str *log_string = DAP_NEW_Z(log_str);
    strcpy(log_string->str, s_ansi_seq_color[ll]);
    log_string->offset = s_ansi_seq_color_len[ll];
    s_update_log_time(log_string->str + log_string->offset);
    int offset = strlen(log_string->str);
    offset += dap_sprintf(log_string->str + offset, "%s[%s%s", log_level_tag[ll], log_tag, "] ");
    va_list va;
    va_start( va, fmt );
    offset += dap_vsprintf(log_string->str + offset, fmt, va);
    va_end( va );
    memcpy(&log_string->str[offset], "\n", 1);
    pthread_mutex_lock(&s_log_mutex);
    DL_APPEND(log_buffer, log_string);
    ++count;
    pthread_cond_signal(&s_log_cond);
    pthread_mutex_unlock(&s_log_mutex);
}

char *dap_log_get_item(time_t a_start_time, int a_limit) {
   return NULL; // TODO
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


/**
 * @brief time_to_rfc822 Convert time_t to string with RFC822 formatted date and time
 * @param[out] out Output buffer
 * @param[out] out_size_mac Maximum size of output buffer
 * @param[in] t UNIX time
 * @return Length of resulting string if ok or lesser than zero if not
 */
int dap_time_to_str_rfc822(char * out, size_t out_size_max, time_t t)
{
  struct tm *tmp;
  tmp = localtime( &t );

  if ( tmp == NULL ) {
    log_it( L_ERROR, "Can't convert data from unix fromat to structured one" );
    return -2;
  }

  int ret;

  #ifndef _WIN32
    ret = strftime( out, out_size_max, "%a, %d %b %y %T %z", tmp );
  #else
    ret = strftime( out, out_size_max, "%a, %d %b %y %H:%M:%S", tmp );
  #endif

  if ( !ret ) {
    log_it( L_ERROR, "Can't print formatted time in string" );
    return -1;
  }

  return ret;
}

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
    size_t ct = a_len;
    if(!a_in || !a_out || (a_len & 1))
        return 0;
    while(ct > 0) {
        char ch1 = ((*a_in >= 'a') ? (*a_in++ - 'a' + 10) : ((*a_in >= 'A') ? (*a_in++ - 'A' + 10) : (*a_in++ - '0'))) << 4;
        char ch2 = ((*a_in >= 'a') ? (*a_in++ - 'a' + 10) : ((*a_in >= 'A') ? (*a_in++ - 'A' + 10) : (*a_in++ - '0'))); // ((*in >= 'A') ? (*in++ - 'A' + 10) : (*in++ - '0'));
        *a_out++ =(uint8_t) ch1 + (uint8_t) ch2;
        ct -= 2;
    }
    return a_len;
}

/**
 * Convert string to digit
 */
void dap_digit_from_string(const char *num_str, uint8_t *raw, size_t raw_len)
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

void dap_digit_from_string2(const char *num_str, uint8_t *raw, size_t raw_len)
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
    return execl(".",a_cmd);
#endif
}
