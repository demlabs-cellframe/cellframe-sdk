/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
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

#ifdef DAP_OS_ANDROID
#include <android/log.h>
#endif

#ifndef _WIN32
#include <pthread.h>
#include <syslog.h>


// Quick and dirty, I'm not sure but afair somewhere it was in UNIX systems too
#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

#else
#include <stdlib.h>
#include <windows.h>
#include <process.h>
typedef HANDLE pthread_mutex_t;
#define popen _popen
#define pclose _pclose
#define pipe(pfds) _pipe(pfds, 4096, 0x8000)
#define PTHREAD_MUTEX_INITIALIZER 0
int pthread_mutex_lock(HANDLE **obj)
{
    return (( *obj = (HANDLE) CreateMutex(0, 1, 0) ) == NULL) ? 0 : 1;
}
int pthread_mutex_unlock(HANDLE *obj) {
    return (ReleaseMutex(obj) == 0) ? 0 : 1;
}
#endif
#include <time.h> /* 'nanosleep' */
#include <unistd.h> /* 'pipe', 'read', 'write' */
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#define LAST_ERROR_MAX 255

#define LOG_TAG "dap_common"

static char last_error[LAST_ERROR_MAX] = {0};
static enum log_level log_level = L_DEBUG;
static FILE * s_log_file = NULL;

static char log_tag_fmt_str[10];

/**
 * @brief set_log_level Sets the logging level
 * @param[in] ll logging level
 */
void set_log_level(enum log_level ll) {
    log_level = ll;
}

/**
 * @brief dap_set_log_tag_width Sets the length of the label
 * @param[in] width Length not more than 99
 */
void dap_set_log_tag_width(size_t width) {
    if (width > 99) {
        fprintf(stderr,"Can't set width %zd", width);
        return;
    }

    // construct new log_tag_fmt_str
    strcpy(log_tag_fmt_str, "[%");
    strcat(log_tag_fmt_str, dap_itoa((int)width));
    strcat(log_tag_fmt_str, "s]\t");
}

/**
 * @brief dap_common_init initialise
 * @param[in] a_log_file
 * @return
 */
int dap_common_init(const char * a_log_file)
{
    srand((unsigned int)time(NULL));
    // init default log tag 8 width
    strcpy(log_tag_fmt_str, "[%8s]\t");

    if (a_log_file) {
        s_log_file = fopen(a_log_file , "a");
        if(s_log_file == NULL) {
            fprintf(stderr,"Can't open log file %s to append\n", a_log_file);
            return -1;
        }
    }
    return 0;
}

/**
 * @brief dap_common_deinit Deinitialise
 */
void dap_common_deinit()
{
    if(s_log_file) fclose(s_log_file);
}

// list of logs
static dap_list_t *s_list_logs = NULL;
// for separate access to logs
static pthread_mutex_t s_list_logs_mutex = PTHREAD_MUTEX_INITIALIZER;

// get logs from list
char *log_get_item(time_t a_start_time, int limit)
{
    int l_count = 0;
    pthread_mutex_lock(&s_list_logs_mutex);
    dap_list_t *l_list = s_list_logs;

    l_list = dap_list_last(l_list);
    // find first item
    while(l_list) {
        dap_list_logs_item_t *l_item = (dap_list_logs_item_t*) l_list->data;
        if(a_start_time > l_item->t) {
            l_list = dap_list_next(l_list);
            break;
        }
        l_count++;
        l_list = dap_list_previous(l_list);
    }
    // no new logs
    if(!l_count){
        pthread_mutex_unlock(&s_list_logs_mutex);
        return NULL;
    }
    // if need all list
    if(!l_list)
        l_list = s_list_logs;

    // create return string
    dap_string_t *l_string = dap_string_new("");
    l_count = 0;
    while(l_list && limit > l_count) {
        dap_list_logs_item_t *l_item = (dap_list_logs_item_t*) l_list->data;
        dap_string_append_printf(l_string, "%lld;%s\n", (int64_t) l_item->t, l_item->str);
        l_list = dap_list_next(l_list);
        l_count++;
    }
    pthread_mutex_unlock(&s_list_logs_mutex);

    char *l_ret_str = dap_string_free(l_string, false);
    return l_ret_str;
}

// save log to list
static void log_add_to_list(time_t a_t, const char *a_time_str, const char * a_log_tag, enum log_level a_ll,
        const char * a_format, va_list a_ap)
{
    pthread_mutex_lock(&s_list_logs_mutex);
    dap_string_t *l_string = dap_string_new("");
    dap_string_append_printf(l_string, "[%s] ", a_time_str);
    if(a_ll == L_DEBUG) {
        l_string = dap_string_append(l_string, "[DBG] ");
    } else if(a_ll == L_INFO) {
        l_string = dap_string_append(l_string, "[INF] ");
    } else if(a_ll == L_NOTICE) {
        l_string = dap_string_append(l_string, "[ * ] ");
    } else if(a_ll == L_WARNING) {
        l_string = dap_string_append(l_string, "[WRN] ");
    } else if(a_ll == L_ERROR) {
        l_string = dap_string_append(l_string, "[ERR] ");
    } else if(a_ll == L_CRITICAL) {
        l_string = dap_string_append(l_string, "[!!!] ");
    }

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
    if(l_count > DAP_LIST_LOG_MAX) {
        // remove items from the beginning
        for(unsigned int i = 0; i < l_count - DAP_LIST_LOG_MAX; i++) {
            s_list_logs = dap_list_remove(s_list_logs, s_list_logs->data);
        }
    }
    pthread_mutex_unlock(&s_list_logs_mutex);
}

/**
 * @brief _log_it Writes information to the log
 * @param[in] log_tag Tag
 * @param[in] ll Log level
 * @param[in] format
 */
void _log_it(const char * log_tag,enum log_level ll, const char * format,...)
{
    if(ll<log_level)
        return;

    va_list ap;

    va_start(ap,format);
    _vlog_it(log_tag,ll, format,ap);
    va_end(ap);
}

void _vlog_it(const char * log_tag,enum log_level ll, const char * format,va_list ap)
{
    va_list ap2,ap3;

    static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&mutex);
#ifdef DAP_OS_ANDROID
    char buf[4096];
    vsnprintf(buf,sizeof(buf),format,ap);
    switch (ll) {
    case L_INFO:
        __android_log_write(ANDROID_LOG_INFO,DAP_BRAND,buf);
        break;
    case L_WARNING:
        __android_log_write(ANDROID_LOG_WARN,DAP_BRAND,buf);
        break;
    case L_ERROR:
        __android_log_write(ANDROID_LOG_ERROR,DAP_BRAND,buf);
        break;
    case L_CRITICAL:
        __android_log_write(ANDROID_LOG_FATAL,DAP_BRAND,buf);
        abort();
        break;
    case L_DEBUG:
    default:
        __android_log_write(ANDROID_LOG_DEBUG,DAP_BRAND,buf);
    }
#endif


    va_copy(ap2,ap);
    va_copy(ap3,ap);
    time_t t=time(NULL);
    struct tm* tmp=localtime(&t);
    static char s_time[1024]={0};
    strftime(s_time,sizeof(s_time),"%x-%X",tmp);

    if (s_log_file ) fprintf(s_log_file,"[%s] ",s_time);
    printf("[%s] ",s_time);

    if(ll==L_DEBUG){
        if (s_log_file ) fprintf(s_log_file,"[DBG] ");
        printf(	"\x1b[37;2m[DBG] ");
    }else if(ll==L_INFO){
        if (s_log_file ) fprintf(s_log_file,"[INF] ");
        printf("\x1b[32;2m[INF] ");
    }else if(ll==L_NOTICE){
        if (s_log_file ) fprintf(s_log_file,"[ * ] ");
        printf("\x1b[32m[ * ] ");
    }else if(ll==L_WARNING){
        if (s_log_file ) fprintf(s_log_file,"[WRN] ");
        printf("\x1b[31;2m[WRN] ");
    }else if(ll==L_ERROR){
        if (s_log_file ) fprintf(s_log_file,"[ERR] ");
        printf("\x1b[31m[ERR] ");
    }else if(ll==L_CRITICAL){
        if (s_log_file ) fprintf(s_log_file,"[!!!] ");
        printf("\x1b[1;5;31m[!!!] ");
    }
    if(log_tag != NULL) {
        if (s_log_file ) fprintf(s_log_file,log_tag_fmt_str,log_tag);
        printf(log_tag_fmt_str,log_tag);
    }
    if (s_log_file ) vfprintf(s_log_file,format,ap);
    vprintf(format,ap2);
    if (s_log_file ) fprintf(s_log_file,"\n");
    printf("\x1b[0m\n");
    va_end(ap2);

    // save log to list
    log_add_to_list(t, s_time, log_tag, ll, format, ap3);
    va_end(ap3);

    if (s_log_file ) fflush(s_log_file);
    fflush(stdout);
    pthread_mutex_unlock(&mutex);
}

/**
 * @brief log_error Error log
 * @return
 */
const char * log_error()
{
    return last_error;
}


#define INT_DIGITS 19		/* enough for 64 bit integer */

/**
 * @brief itoa  The function converts an integer num to a string equivalent and places the result in a string
 * @param[in] i number
 * @return
 */
char *dap_itoa(int i)
{
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char *p = buf + INT_DIGITS + 1;	/* points to terminating '\0' */
    if (i >= 0) {
        do {
            *--p = '0' + (i % 10);
            i /= 10;
        } while (i != 0);
        return p;
    }
    else {			/* i < 0 */
        do {
            *--p = '0' - (i % 10);
            i /= 10;
        } while (i != 0);
        *--p = '-';
    }
    return p;
}


/**
 * @brief time_to_rfc822 Convert time_t to string with RFC822 formatted date and time
 * @param[out] out Output buffer
 * @param[out] out_size_mac Maximum size of output buffer
 * @param[in] t UNIX time
 * @return Length of resulting string if ok or lesser than zero if not
 */
int time_to_rfc822(char * out, size_t out_size_max, time_t t)
{
    struct tm *tmp;
    tmp=localtime(&t);
    if(tmp== NULL){
        log_it(L_ERROR,"Can't convert data from unix fromat to structured one");
        return -2;
    }else{
        int ret;
        ret=strftime(out, out_size_max,"%a, %d %b %y %T %z",tmp);
        //free(tmp);
        if(ret>0){
            return ret;
        }else{
            log_it(L_ERROR,"Can't print formatted time in string");
            return -1;
        }
    }
}

static int breaker_set[2] = { -1, -1 };
static int initialized = 0;
static struct timespec break_latency = {0, 1 * 1000 * 1000 };

int get_select_breaker()
{
    if (!initialized)
    {
        if (pipe(breaker_set) < 0) return -1;
        else initialized = 1;
    }

    return breaker_set[0];
}
int send_select_break()
{
    if (!initialized) return -1;
    char buffer[1];
    if (write(breaker_set[1], "\0", 1) <= 0) return -1;
    nanosleep(&break_latency, NULL);
    if (read(breaker_set[0], buffer, 1) <= 0 || buffer[0] != '\0') return -1;
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
    char * ret = (char*) malloc(a_length+1);
    size_t i;
    for(i=0; i<a_length; ++i) {
        int index = rand() % (sizeof(l_possible_chars)-1);
        ret[i] = l_possible_chars[index];
    }
    return ret;
}


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

/**
 * Convert binary data to binhex encoded data.
 *
 * out output buffer, must be twice the number of bytes to encode.
 * len is the size of the data in the in[] buffer to encode.
 * return the number of bytes encoded, or -1 on error.
 */
size_t dap_bin2hex0(char *a_out, const void *a_in, size_t a_len)
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
size_t dap_hex2bin0(uint8_t *a_out, const char *a_in, size_t a_len)
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
    }
    else {
        val = strtoull(num_str, NULL, 10);
    }
    // for LITTLE_ENDIAN (Intel), do nothing, otherwise swap bytes
    val = le64toh(val);
    memset(raw, 0, raw_len);
    memcpy(raw, &val, min(raw_len, sizeof(uint64_t)));
}


#ifdef __MINGW32__
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
