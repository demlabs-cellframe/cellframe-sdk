/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include <stdio.h>
#include <stdlib.h>
#include <time.h> /* 'nanosleep' */
#include <unistd.h> /* 'pipe', 'read', 'write' */
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>

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

#include "dap_lut.h"

#define LAST_ERROR_MAX 255

#define LOG_TAG "dap_common"

static char s_last_error[LAST_ERROR_MAX] = {0};
static enum dap_log_level dap_log_level = L_DEBUG;
static FILE *s_log_file = NULL;
static char log_tag_fmt_str[10];

static pthread_mutex_t s_list_logs_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint32_t logh_total    = 0; // log history size
static uint32_t logh_outindex = 0;
static uint8_t *log_buffer  = NULL;
static uint8_t *temp_buffer = NULL;
static uint8_t *end_of_log_buffer = NULL;
static dap_log_str_t *log_history = NULL;

const char *log_level_tag[ 16 ] = {

  " [DBG] [       ", // L_DEBUG     = 0 
  " [INF] [       ", // L_INFO      = 1,
  " [ * ] [       ", // L_NOTICE    = 2,
  " [MSG] [       ", // L_MESSAGE   = 3,
  " [DAP] [       ", // L_DAP       = 4,
  " [WRN] [       ", // L_WARNING   = 5,
  " [ATT] [       ", // L_ATT       = 6,
  " [ERR] [       ", // L_ERROR     = 7,
  " [ ! ] [       ", // L_CRITICAL  = 8,
  " [---] [       ", //             = 9
  " [---] [       ", //             = 10
  " [---] [       ", //             = 11
  " [---] [       ", //             = 12
  " [---] [       ", //             = 13
  " [---] [       ", //             = 14
  " [---] [       ", //             = 15
};

const char *ansi_seq_color[ 16 ] = {

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

#ifdef _WIN32

  OSVERSIONINFO win32_osvi;
  bool  bUseANSIEscapeSequences = false;
  HANDLE hWin32ConOut = INVALID_HANDLE_VALUE;

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

uint32_t ansi_seq_color_len[ 16 ];

/**
 * @brief set_log_level Sets the logging level
 * @param[in] ll logging level
 */
void dap_log_level_set( enum dap_log_level ll ) {
    dap_log_level = ll;
}

enum dap_log_level dap_log_level_get( void ) {
    return dap_log_level ;
}

/**
 * @brief dap_set_log_tag_width Sets the length of the label
 * @param[in] width Length not more than 99
 */
void dap_set_log_tag_width(size_t width) {

  if (width > 99) {
      dap_fprintf(stderr,"Can't set width %zd", width);
      return;
  }

  // construct new log_tag_fmt_str
  strcpy( log_tag_fmt_str, "[%" );
  strcat( log_tag_fmt_str, dap_itoa((int)width) );
//  strcat( log_tag_fmt_str, itoa((int)width) );
  strcat( log_tag_fmt_str, "s]\t" );
}

/**
 * @brief dap_common_init initialise
 * @param[in] a_log_file
 * @return
 */
int dap_common_init( const char *console_title, const char *a_log_file )
{
  srand( (unsigned int)time(NULL) );

  #ifdef _WIN32
    SetupConsole( console_title, L"Lucida Console", 12, 20 );
  #endif

  // init default log tag 8 width
  strcpy( log_tag_fmt_str, "[%8s]\t");

  log_buffer = (uint8_t *)malloc( DAP_LOG_HISTORY_BUFFER_SIZE + 65536 );
  if ( !log_buffer )
    goto err;

  temp_buffer = log_buffer + 65536;
  end_of_log_buffer = log_buffer + DAP_LOG_HISTORY_BUFFER_SIZE;

  log_history = (dap_log_str_t *)malloc( DAP_LOG_HISTORY_MAX_STRINGS * sizeof(dap_log_str_t) );
  if ( !log_history )
    goto err;

  for ( uint32_t i = 0; i < DAP_LOG_HISTORY_MAX_STRINGS; ++ i ) {
    log_history[ i ].t   = 0;
    log_history[ i ].str = log_buffer + DAP_LOG_HISTORY_STR_SIZE * i;
  }

  for ( uint32_t i = 0; i < 16; ++ i )
    ansi_seq_color_len[ i ] = strlen( ansi_seq_color[i] );

  #ifdef _WIN32

    memset( &win32_osvi, 0, sizeof(OSVERSIONINFO) );

    win32_osvi.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
    GetVersionEx( (OSVERSIONINFO *)&win32_osvi );

    bUseANSIEscapeSequences = (win32_osvi.dwMajorVersion >= 10);
    //if ( !bUseANSIEscapeSequences )
    hWin32ConOut = GetStdHandle( STD_OUTPUT_HANDLE );

    #if 0
    printf( "Windows version %u.%u platformID %u \n", 
            win32_osvi.dwMajorVersion, 
            win32_osvi.dwMinorVersion,
            win32_osvi.dwPlatformId );
    #endif
  #endif

  if ( !a_log_file )
    return 0;

  s_log_file = fopen( a_log_file , "a" );
  if( s_log_file == NULL ) {
    dap_fprintf( stderr, "Can't open log file %s to append\n", a_log_file );
    return -1;
  }

  return 0;

err:
  printf( "Fatal Error: Out of memory!\n" );
  dap_common_deinit( );

  return -1;
}

/**
 * @brief dap_common_deinit Deinitialise
 */
void dap_common_deinit( )
{
  printf("dap_common_deinit( )\n");

  if ( s_log_file )
    fclose( s_log_file );

  if( log_history ) 
    free( log_history );

  if( log_buffer ) 
    free( log_buffer );
}

void log_log( char *str, uint32_t len, time_t t )
{
  pthread_mutex_lock( &s_list_logs_mutex );

  while( len ) {

    uint8_t   *out = log_history[ logh_outindex ].str;
    uint32_t  ilen = len;

    if ( out + len >= end_of_log_buffer )
      ilen = end_of_log_buffer - out;

    memcpy( out, str, ilen );
    len -= ilen;

    do {

      log_history[ logh_outindex ].t = t;

      if ( ilen >= DAP_LOG_HISTORY_STR_SIZE ) {
        log_history[ logh_outindex ].len = DAP_LOG_HISTORY_STR_SIZE;
        ilen -= DAP_LOG_HISTORY_STR_SIZE;
      }
      else {
        log_history[ logh_outindex ].len = ilen;
        ilen = 0;
      }

      ++ logh_outindex; 
      logh_outindex &= DAP_LOG_HISTORY_M;
      if ( logh_total < DAP_LOG_HISTORY_MAX_STRINGS )
        ++ logh_total;

    } while( ilen );
  }

  pthread_mutex_unlock( &s_list_logs_mutex );
  return;
}

uint32_t logh_since( time_t t )
{
  uint32_t li = (logh_outindex - 1) & DAP_LOG_HISTORY_M;
  uint32_t count = logh_total;
  uint32_t fi = 0;
  uint32_t si = 0;

  if ( log_history[li].t < t ) // no new logs
    return 0xFFFFFFFF;

  if (logh_total >= DAP_LOG_HISTORY_MAX_STRINGS )
    fi = logh_outindex;

  if ( log_history[fi].t >= t ) // all logs is new
    return fi;

  do {

    if ( log_history[li].t < t ) { 
      si = li;
      break;
    }

    li = (li - 1) & DAP_LOG_HISTORY_M;

  } while ( --count );

  return (si + 1) & DAP_LOG_HISTORY_M;
}

/*
 * Get logs from list
 */
char *dap_log_get_item( time_t a_start_time, int a_limit )
{
  uint32_t l_count;
  uint32_t si;
  char *res, *out;

  pthread_mutex_lock( &s_list_logs_mutex );

  l_count = logh_total;

  if ( l_count > (uint32_t)a_limit )
    l_count = a_limit;

  if ( !l_count ) {
    pthread_mutex_unlock( &s_list_logs_mutex );
    return NULL;
  }

  si = logh_since( a_start_time );
  if ( si == 0xFFFFFFFF || log_history[ si ].t < a_start_time ) {// no new logs
    pthread_mutex_unlock( &s_list_logs_mutex );
    return NULL;
  }

  out = res = (char *)malloc( l_count * DAP_LOG_HISTORY_STR_SIZE + 1 );
  if ( !res ) {
    pthread_mutex_unlock( &s_list_logs_mutex );
    return NULL;
  }

  do {

    memcpy( out, log_history[ si ].str, log_history[ si ].len );
    out += log_history[ si ].len;

    si = (si + 1) & DAP_LOG_HISTORY_M;
    if ( si == logh_outindex || log_history[ si ].t < a_start_time )
      break;

  } while ( --l_count );

  *out = 0;
  pthread_mutex_unlock( &s_list_logs_mutex );

  return res;
}

#if 0
// save log to list
static void log_add_to_list(time_t a_t, const char *a_time_str, const char * a_log_tag, enum dap_log_level a_ll,
        const char * a_format, va_list a_ap)
{
//    pthread_mutex_lock(&s_list_logs_mutex);
//    dap_string_t *l_string = dap_string_new("");
//
//    dap_string_append_printf(l_string, "[%s]\t", a_time_str);

//    l_string = dap_string_append(l_string, log_level_tag[a_ll] );

/**
    if(a_ll == L_DEBUG) {
        l_string = dap_string_append(l_string, "[DBG]\t");
    } else if(a_ll == L_INFO) {
        l_string = dap_string_append(l_string, "[INF]\t");
    } else if(a_ll == L_NOTICE) {
        l_string = dap_string_append(l_string, "[ * ]\t");
    } else if(a_ll == L_WARNING) {
        l_string = dap_string_append(l_string, "[WRN]\t");
    } else if(a_ll == L_ERROR) {
        l_string = dap_string_append(l_string, "[ERR]\t");
    } else if(a_ll == L_CRITICAL) {
        l_string = dap_string_append(l_string, "[!!!]\t");
    }
**/

/**

    if(a_log_tag != NULL) {
        dap_string_append_printf(l_string, log_tag_fmt_str, a_log_tag);
    }
    dap_string_append_vprintf(l_string, a_format, a_ap);

    dap_list_logs_item_t *l_item = DAP_NEW(dap_list_logs_item_t);
    l_item->t = a_t;

    l_item->str = dap_string_free(l_string, false);
    s_list_logs = dap_list_append(s_list_logs, l_item);

    // remove old items
    unsigned int l_count = dap_list_length(s_list_logs);
    if(l_count > s_max_items) {
        // remove items from the beginning
        for(unsigned int i = 0; i < l_count - s_max_items; i++) {
            s_list_logs = dap_list_remove(s_list_logs, s_list_logs->data);
        }
    }

    pthread_mutex_unlock(&s_list_logs_mutex);
**/
}
#endif

/**
 * @brief _log_it Writes information to the log
 * @param[in] log_tag Tag
 * @param[in] ll Log level
 * @param[in] format
 */

void _log_it( const char *log_tag, enum dap_log_level ll, const char *fmt,... )
{
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  uint8_t   *buf0 = temp_buffer;
  uint32_t  len, tmp,
            time_offset,
            tag_offset,
            msg_offset;

  if ( ll < dap_log_level || ll >= 16 || !log_tag )
    return;

  time_t t = time( NULL );
  pthread_mutex_lock( &mutex );

  memcpy( buf0, ansi_seq_color[ll], ansi_seq_color_len[ll] );
  time_offset = ansi_seq_color_len[ll];

  struct tm *tmptime = localtime( &t );
  len = strftime( (char *)(buf0 + time_offset), 65536, "[%x-%X]", tmptime );
  tag_offset = time_offset + len;

  memcpy( buf0 + tag_offset, log_level_tag[ll], 8 );
  memcpy( buf0 + tag_offset + 8, log_level_tag[ll], 8 );

  msg_offset = tag_offset + 8;

  while ( *log_tag )
    buf0[ msg_offset ++ ] = *log_tag ++;

  buf0[ msg_offset ++ ] = ']';
  buf0[ msg_offset ++ ] = ' ';
  //  buf0[ msg_offset ++ ] = 9;

  va_list va;
  va_start( va, fmt );

  len = dap_vsprintf( (char * __restrict )(buf0 + msg_offset), fmt, va );
  va_end( va );

  len += msg_offset;

  #ifdef DAP_OS_ANDROID
    buf2[ len ] = 0;
    __android_log_write( ANDROID_LOG_INFO, DAP_BRAND, buf0 + msg_offset );
  #endif

  buf0[ len++ ] = 10;
  if ( s_log_file )
    fwrite( buf0 + time_offset, len - time_offset, 1, s_log_file );

  //  buf0[ len++ ] = 0;
  log_log( (char *)(buf0 + time_offset), len - time_offset, t );

  #ifdef _WIN32
  //    if ( !bUseANSIEscapeSequences )
    SetConsoleTextAttribute( hWin32ConOut, log_level_colors[ll] );
  //  WriteConsole( hWin32ConOut, buf0 + time_offset, len - time_offset, &tmp, NULL );
  //  fwrite( buf0 + time_offset, len - time_offset, 1, stdout );
    WriteFile( hWin32ConOut, buf0 + time_offset, len - time_offset, (LPDWORD)&tmp, NULL );
  #else
    fwrite( buf0, len, 1, stdout );
  #endif

//    printf("\x1b[0m\n");

  pthread_mutex_unlock( &mutex );
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

// !!!!!!!!!!!!!!!!!!!

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

// !!!!!!!!!!!!!!!!!!!

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


#if 0
/*!
 * \brief Execute shell command silently
 * \param a_cmd command line
 * \return 0 if success, -1 otherwise
 */
int exec_silent(const char * a_cmd) {

    PROCESS_INFORMATION p_info;
    STARTUPINFOA s_info;

    memzero(&s_info, sizeof(s_info));
    memzero(&p_info, sizeof(p_info));

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
}
#endif
