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
#include <stdatomic.h>

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

unsigned int l_sys_dir_path_len = 0;
char s_sys_dir_path[MAX_PATH] = {'\0'};


static char s_last_error[LAST_ERROR_MAX] = {0};
static enum dap_log_level dap_log_level = L_DEBUG;
static FILE *s_log_file = NULL;
static char *s_log_file_path = NULL;
static char s_log_tag_fmt_str[10]={0};

static size_t s_ansi_seq_color_len[ 16 ];

#ifdef DAP_LOG_HISTORY
static pthread_mutex_t s_list_logs_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t logh_total    = 0; // log history size
static uint32_t logh_outindex = 0;
static uint8_t *s_logh_buffer  = NULL;
static size_t s_logh_buffer_size = 0;
static uint8_t *s_temp_buffer = NULL;
static size_t s_temp_buffer_size = 0;
static uint8_t *s_end_of_logh_buffer = NULL;
static dap_log_history_str_t *s_log_history = NULL;
static size_t s_log_history_size = 0;
#endif

#if DAP_LOG_USE_SPINLOCK
    static dap_spinlock_t log_spinlock;
#else
    static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
pthread_cond_t s_log_cond = PTHREAD_COND_INITIALIZER;


typedef struct dap_log_str_s {

  time_t    t;
  uint8_t   *str;
  uint32_t  len;
  uint8_t   tag;

} dap_log_str_t;

#define DAP_LOG_STR_SIZE    128
#define DAP_LOG_MAX_STRINGS 32768
#define DAP_LOG_BUFFER_SIZE (DAP_LOG_STR_SIZE * DAP_LOG_MAX_STRINGS)

static volatile uint32_t s_log_outindex = 0;
static uint8_t *s_log_buffer = NULL;
static size_t s_log_buffer_size =0;

static dap_log_str_t *s_log_strs = NULL;
static size_t s_log_strs_size = 0;
static pthread_t s_log_thread = 0;
static bool s_log_term_signal = false;
static uint32_t s_log_page = 0;

static time_t s_start_time = 0;
static volatile time_t s_time = 0;
static bool s_overflow = false;
static char s_cur_datatime_str[ 200];

static void  *log_thread_proc( void *arg );

DAP_STATIC_INLINE void s_update_log_time()
{
    time_t t = time( NULL );
    struct tm *tmptime = localtime( &t );
    strftime( s_cur_datatime_str, sizeof(s_cur_datatime_str), "[%x-%X]", tmptime );

//		printf("Time updated %s page %u\n", (char *)&cdatatime[lp*32], log_page );
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

  // construct new log_tag_fmt_str
    dap_snprintf(s_log_tag_fmt_str,sizeof (s_log_tag_fmt_str), "[%%%zds]\t",a_width);
}

/**
 * @brief dap_common_init initialise
 * @param[in] a_log_file
 * @return
 */
int dap_common_init( const char *a_console_title, const char *a_log_file )
{
    srand( (unsigned int)time(NULL) );

    /*
    #ifdef _WIN32
        SetupConsole( a_console_title, L"Lucida Console", 12, 20 );
    #endif
    */

    s_start_time = time( NULL );

    // init default log tag 8 width
    strncpy( s_log_tag_fmt_str, "[%8s]\t",sizeof (s_log_tag_fmt_str));

    #if DAP_LOG_HISTORY
        s_logh_buffer_size = DAP_LOG_HISTORY_BUFFER_SIZE;
        s_logh_buffer = DAP_NEW_Z_SIZE(uint8_t, s_logh_buffer_size);
        if ( !s_logh_buffer )
            goto err;

        s_end_of_logh_buffer = s_logh_buffer + s_logh_buffer_size;

        s_log_history_size =  DAP_LOG_HISTORY_MAX_STRINGS * sizeof(dap_log_history_str_t);
        s_log_history =  DAP_NEW_Z_SIZE(dap_log_history_str_t,s_log_history_size);

        if ( !s_log_history )
            goto err;

        for ( uint32_t i = 0; i < DAP_LOG_HISTORY_MAX_STRINGS; ++ i ) {
            s_log_history[ i ].t   = 0;
            s_log_history[ i ].str = s_logh_buffer + DAP_LOG_HISTORY_STR_SIZE * i;
        }
    #endif

    s_log_buffer_size= DAP_LOG_BUFFER_SIZE * 2 ;
    s_log_buffer = DAP_NEW_Z_SIZE(uint8_t, s_log_buffer_size);
    if ( !s_log_buffer )
        goto err;

    s_log_strs_size = DAP_LOG_MAX_STRINGS * 2 * sizeof(dap_log_str_t);
    s_log_strs = DAP_NEW_Z_SIZE(dap_log_str_t, s_log_strs_size);
    if ( !s_log_strs )
        goto err;

    for ( uint32_t i = 0; i < DAP_LOG_MAX_STRINGS * 2; ++ i ) {
        s_log_strs[ i ].str = s_log_buffer + DAP_LOG_STR_SIZE * i;
    }

    s_temp_buffer_size = 65536;
    s_temp_buffer = DAP_NEW_Z_SIZE(uint8_t,s_temp_buffer_size);
    if ( !s_logh_buffer )
        goto err;

    for ( uint32_t i = 0; i < 16; ++ i )
        s_ansi_seq_color_len[ i ] = strlen( s_ansi_seq_color[i] );

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
    if ( s_log_file == NULL ) {
        dap_fprintf( stderr, "Can't open log file %s to append\n", a_log_file );
        return -1;
    }
    if(s_log_file_path)
        DAP_DELETE(s_log_file_path);
    s_log_file_path = dap_strdup(a_log_file);

    s_log_page = 0;
    s_log_outindex = 0;
    s_update_log_time();

    s_log_term_signal = false;
    pthread_create( &s_log_thread, NULL, log_thread_proc, NULL );

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

    s_log_term_signal = true;
    pthread_join( s_log_thread, NULL );

    if ( s_log_file )
        fclose( s_log_file );

    if(s_log_file_path){
        DAP_DELETE(s_log_file_path);
        s_log_file_path = NULL;
    }

    if ( s_temp_buffer )
        DAP_FREE( s_temp_buffer );

    if ( s_log_strs )
        DAP_FREE( s_log_strs );

    if ( s_log_buffer )
        DAP_FREE( s_log_buffer );

#if DAP_LOG_HISTORY
    if ( s_log_history )
        DAP_FREE( s_log_history );

    if ( s_logh_buffer )
        DAP_FREE( s_logh_buffer );
#endif
}

#if DAP_LOG_HISTORY
void log_log( char *str, uint32_t len, time_t t )
{
    pthread_mutex_lock( &s_list_logs_mutex );

    while( len ) {

        uint8_t   *out = s_log_history[ logh_outindex ].str;
        uint32_t  ilen = len;

        if ( out + len >= s_end_of_logh_buffer )
            ilen = s_end_of_logh_buffer - out;

        memcpy( out, str, ilen );
        len -= ilen;

        do {

            s_log_history[ logh_outindex ].t = t;

            if ( ilen >= DAP_LOG_HISTORY_STR_SIZE ) {
                s_log_history[ logh_outindex ].len = DAP_LOG_HISTORY_STR_SIZE;
                ilen -= DAP_LOG_HISTORY_STR_SIZE;
            }
            else {
                s_log_history[ logh_outindex ].len = ilen;
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
    uint32_t bi = 0;
    uint32_t si = logh_total >> 1;
    uint32_t li = (logh_outindex - 1) & DAP_LOG_HISTORY_M;

    if ( s_log_history[li].t < t ) // no new logs
        return 0xFFFFFFFF;

    if (logh_total >= DAP_LOG_HISTORY_MAX_STRINGS )
        bi = logh_outindex;

    if ( s_log_history[bi].t >= t )  // all logs is new
        return bi;

    while( si ) {

        if ( s_log_history[(bi + si) & DAP_LOG_HISTORY_M].t < t )
            bi += si;

        si >>= 1;
    }

    return (bi + si + 1) & DAP_LOG_HISTORY_M;
}

/**
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
**/
#endif

/*
 * Get logs from list
 */
char *dap_log_get_item( time_t a_time, int a_limit )
{
#if !DAP_LOG_HISTORY

    char *res = (char *)DAP_MALLOC( 64 );
    if ( !res ) 
        return res;

    strcpy( res, "DAP_LOG_HISTORY is disabled" );
    return res;

#else
    uint32_t l_count;
    uint32_t si;
    char *res, *out;
    time_t  a_start_time;

    a_start_time = time( NULL );

    if ( a_time > a_start_time )
        a_start_time = 0;
    else
        a_start_time -= a_time;

    pthread_mutex_lock( &s_list_logs_mutex );

    l_count = logh_total;

    if ( l_count > (uint32_t)a_limit )
        l_count = a_limit;

    if ( !l_count ) {
        pthread_mutex_unlock( &s_list_logs_mutex );
        return NULL;
    }

    si = logh_since( a_start_time );
    if ( si == 0xFFFFFFFF || s_log_history[ si ].t < a_start_time ) {// no new logs
        pthread_mutex_unlock( &s_list_logs_mutex );
        return NULL;
    }

    out = res = (char *)DAP_MALLOC( l_count * DAP_LOG_HISTORY_STR_SIZE + 1 );
    if ( !res ) {
        pthread_mutex_unlock( &s_list_logs_mutex );
        return NULL;
    }

    do {

        memcpy( out, s_log_history[ si ].str, s_log_history[ si ].len );
        out += s_log_history[ si ].len;

        si = (si + 1) & DAP_LOG_HISTORY_M;
        if ( si == logh_outindex || s_log_history[ si ].t < a_start_time )
            break;

    } while ( --l_count );

    *out = 0;
    pthread_mutex_unlock( &s_list_logs_mutex );

    return res;
#endif
}

static void  *log_thread_proc( void *arg )
{
    int32_t l_outlogstrs = 0, tmp, n;
    dap_log_str_t *l_logstr;

    while ( !s_log_term_signal ) {

        s_update_log_time( );

        #if DAP_LOG_USE_SPINLOCK
            DAP_AtomicLock( &log_spinlock );
        #else
            pthread_mutex_lock( &s_log_mutex );
        #endif
        if ( !s_log_outindex ) {
                s_log_page ^= 1;
            #if DAP_LOG_USE_SPINLOCK
                DAP_AtomicUnlock( &log_spinlock );
            #else
                pthread_mutex_unlock( &s_log_mutex );
            #endif
//            printf("log_thread_proc: nothing to log. Sleeping...\n" );
            dap_sleep( 10 );
            continue;
        }

        n = l_outlogstrs =(int32_t) s_log_outindex;
        s_log_outindex = 0;
        l_logstr = &s_log_strs[ s_log_page * DAP_LOG_MAX_STRINGS ];
        s_log_page ^= 1;

        #if DAP_LOG_USE_SPINLOCK
            DAP_AtomicUnlock( &log_spinlock );
        #else
            pthread_mutex_unlock( &s_log_mutex );
        #endif

//        printf("log_thread_proc: outlogstrs: %u\n", outlogstrs );

        do {

            #ifdef DAP_OS_ANDROID
                buf2[ len ] = 0;
                __android_log_write( ANDROID_LOG_INFO, DAP_BRAND, buf0 + msg_offset );
            #endif

            #if 1
            #ifdef _WIN32
//                if ( !bUseANSIEscapeSequences )
                SetConsoleTextAttribute( hWin32ConOut, log_level_colors[l_logstr->tag] );
          //  WriteConsole( hWin32ConOut, buf0 + time_offset, len - time_offset, &tmp, NULL );
          //  fwrite( buf0 + time_offset, len - time_offset, 1, stdout );
                WriteFile( hWin32ConOut, l_logstr->str, l_logstr->len, (LPDWORD)&tmp, NULL );
            #else
                fwrite( s_ansi_seq_color[l_logstr->tag], 10, 1, stdout );
                fwrite( l_logstr->str, l_logstr->len, 1, stdout );
            #endif
            #endif
            if(s_log_file) {
                if(!dap_file_test(s_log_file_path)) {
                    fclose(s_log_file);
                    s_log_file = fopen(s_log_file_path, "a");
                }
                if(s_log_file) {
                    fwrite(l_logstr->str, l_logstr->len, 1, s_log_file);
                    fflush(s_log_file);
                }
            }

//            fwrite( "1234567890", 5, 1, stdout );

            uint32_t al = ROUNDUP(l_logstr->len, 128 ) >> 7;

            l_logstr += al;
            n -= al;

        } while ( n > 0 );

        if ( l_outlogstrs < 1024 ) {
            dap_sleep( 10 );
        }
    }

//    printf("log_thread_proc Finished! Overflows? = %u\n", bOverflow );

    return NULL;
}

DAP_STATIC_INLINE void _log_enqueue( const char *log_tag, uint32_t taglen, uint8_t *msg, uint32_t len , uint32_t ll )
{
    uint32_t total_len = len + 19 + 8 + taglen + 3;
    uint32_t al = ROUNDUP( total_len, 128 ) >> 7;

    if ( !al ) 
        return;

//[07/27/19-03:22:45] [INF] [db_cdb] 

    #if DAP_LOG_USE_SPINLOCK
        DAP_AtomicLock( &log_spinlock );
    #else
        pthread_mutex_lock( &s_log_mutex );
    #endif

    if ( s_log_outindex + (al-1) >= DAP_LOG_MAX_STRINGS ) {
        if ( !s_overflow ) {
            s_overflow = true;
            printf("Overflow!!!\n");
        }
        #if DAP_LOG_USE_SPINLOCK
            DAP_AtomicUnlock( &log_spinlock );
        #else
            pthread_mutex_unlock( &s_log_mutex );
        #endif
        return;
    }

    dap_log_str_t *logstr = &s_log_strs[ s_log_page * DAP_LOG_MAX_STRINGS + s_log_outindex ];
    uint8_t *out = logstr->str;

    memcpy( out, &s_cur_datatime_str[s_log_page*32], 19 );
    out += 19;
    memcpy( out, log_level_tag[ll], 8 );
    out += 8;
    memcpy( out, log_tag, taglen );
    out += taglen;
    *out ++ = ']';
    *out ++ = ' ';
    memcpy( out, msg, len );
    out += len;
    *out = 10;

    logstr->t = s_time;
    logstr->len = total_len;
    logstr->tag = ll;

    s_log_outindex += al;

    #if DAP_LOG_USE_SPINLOCK
        DAP_AtomicUnlock( &log_spinlock );
    #else
        pthread_mutex_unlock( &s_log_mutex );
    #endif
}

void _log_it( const char *log_tag, uint32_t taglen, enum dap_log_level ll, const char *fmt,... )
{
    DAP_ALIGNED(32) uint8_t buf0[ 16384 ];
    uint32_t  len;

    if ( ll < dap_log_level || ll >= 16 || !log_tag )
        return;

    va_list va;
    va_start( va, fmt );

    len = dap_vsprintf( (char *)&buf0[0], fmt, va );
    va_end( va );

    _log_enqueue( log_tag, taglen, &buf0[0], len, ll );

    return;
}


/**
 * @brief _log_it Writes information to the log
 * @param[in] log_tag Tag
 * @param[in] ll Log level
 * @param[in] format
 */

void _log_it2( const char *log_tag, enum dap_log_level ll, const char *fmt,... )
{
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  uint8_t   *buf0 = s_temp_buffer;
  uint32_t  len, tmp,
            time_offset,
            tag_offset,
            msg_offset;

  if ( ll < dap_log_level || ll >= 16 || !log_tag )
    return;

//  time_t t = time( NULL ) - g_start_time;
  time_t t = time( NULL );

  pthread_mutex_lock( &mutex );

  memcpy( buf0, s_ansi_seq_color[ll], s_ansi_seq_color_len[ll] );
  time_offset = s_ansi_seq_color_len[ll];

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

#ifdef _WIN32
//                if ( !bUseANSIEscapeSequences )
    SetConsoleTextAttribute( hWin32ConOut, log_level_colors[ll] );
//  WriteConsole( hWin32ConOut, buf0 + time_offset, len - time_offset, &tmp, NULL );
//  fwrite( buf0 + time_offset, len - time_offset, 1, stdout );
    WriteFile( hWin32ConOut, buf0 + time_offset, len - time_offset, (LPDWORD)&tmp, NULL );
#else
    fwrite( s_ansi_seq_color[ll], 10, 1, stdout );
    fwrite( buf0+time_offset, len-time_offset, 1, stdout );
#endif

  //  buf0[ len++ ] = 0;
  log_log( (char *)(buf0 + time_offset), len - time_offset, t );

//    printf("\x1b[0m\n");

  pthread_mutex_unlock( &mutex );
}

void dap_sleep( uint32_t ms )
{
#ifdef _WIN32
    Sleep( ms );
#else
    int was_error;
    struct timespec elapsed, tv;

    elapsed.tv_sec = ms / 1000;
    elapsed.tv_nsec = (ms % 1000) * 1000000;

    do {
        errno = 0;
        tv.tv_sec = elapsed.tv_sec;
        tv.tv_nsec = elapsed.tv_nsec;
        was_error = nanosleep( &tv, &elapsed );
    } while( was_error && (errno == EINTR) );
#endif
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
