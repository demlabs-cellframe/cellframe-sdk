#ifdef _WIN32
#include <windows.h>
#include <sys/time.h>
#endif
#include <errno.h>
#include <string.h>
#include <time.h>

#include "dap_common.h"
#include "dap_time.h"
#include "dap_strfuncs.h"

#define LOG_TAG "dap_common"

#ifdef _WIN32

/* Identifier for system-wide realtime clock.  */
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME              0

#ifndef clockid_t
typedef int clockid_t;
#endif

struct timespec {
    uint64_t tv_sec; // seconds
    uint64_t tv_nsec;// nanoseconds
};

int clock_gettime(clockid_t clock_id, struct timespec *spec)
{
//    __int64 wintime;
//    GetSystemTimeAsFileTime((FILETIME*) &wintime);
//    spec->tv_sec = wintime / 10000000i64; //seconds
//    spec->tv_nsec = wintime % 10000000i64 * 100; //nano-seconds
//    return 0;
    uint64_t ft;
    GetSystemTimeAsFileTime(FILETIME*)&ft); //return the number of 100-nanosecond intervals since January 1, 1601 (UTC)
    // from 1 jan 1601 to 1 jan 1970
    ft -= 116444736000000000i64;
    spec->tv_sec = ft / 10000000i64; //seconds
    spec->tv_nsec = ft % 10000000i64 * 100; //nano-seconds
    return 0;
}
#endif
#endif


// Create time from second
dap_gdb_time_t dap_gdb_time_from_sec(dap_time_t a_time)
{
    return (dap_gdb_time_t)a_time << 32;
}

// Get seconds from time
dap_time_t dap_gdb_time_to_sec(dap_gdb_time_t a_time)
{
    return a_time >> 32;
}

/**
 * @brief dap_chain_time_now Get current time in seconds since January 1, 1970 (UTC)
 * @return Returns current UTC time in seconds.
 */
dap_time_t dap_time_now(void)
{
    time_t l_time = time(NULL);
    return (dap_time_t)l_time;
}

/**
 * @brief dap_chain_time_now Get current time in nanoseconds since January 1, 1970 (UTC)
 * @return Returns current UTC time in nanoseconds.
 */
dap_gdb_time_t dap_gdb_time_now(void)
{
    dap_gdb_time_t l_time_nsec;
    struct timespec cur_time;
    clock_gettime(CLOCK_REALTIME, &cur_time);
    l_time_nsec = ((dap_gdb_time_t)cur_time.tv_sec << 32) + cur_time.tv_nsec;
    return l_time_nsec;
}

/**
 * dap_usleep:
 * @a_microseconds: number of microseconds to pause
 *
 * Pauses the current thread for the given number of microseconds.
 */
void dap_usleep(dap_time_t a_microseconds)
{
#ifdef DAP_OS_WINDOWS
    Sleep (a_microseconds / 1000);
#else
    struct timespec l_request, l_remaining;
    l_request.tv_sec = a_microseconds / DAP_USEC_PER_SEC;
    l_request.tv_nsec = 1000 * (a_microseconds % DAP_USEC_PER_SEC);
    while(nanosleep(&l_request, &l_remaining) == -1 && errno == EINTR)
        l_request = l_remaining;
#endif
}

/**
 * @brief Calculate diff of two struct timespec
 * @param[in] a_start - first time
 * @param[in] a_stop - second time
 * @param[out] a_result -  diff time, may be NULL
 * @return diff time in millisecond
 */
int timespec_diff(struct timespec *a_start, struct timespec *a_stop, struct timespec *a_result)
{
    if(!a_start || !a_stop)
        return 0;
    if(!a_result) {
        struct timespec l_time_tmp = { 0 };
        a_result = &l_time_tmp;
    }
    if((a_stop->tv_nsec - a_start->tv_nsec) < 0) {
        a_result->tv_sec = a_stop->tv_sec - a_start->tv_sec - 1;
        a_result->tv_nsec = a_stop->tv_nsec - a_start->tv_nsec + 1000000000;
    } else {
        a_result->tv_sec = a_stop->tv_sec - a_start->tv_sec;
        a_result->tv_nsec = a_stop->tv_nsec - a_start->tv_nsec;
    }

    return (a_result->tv_sec * 1000 + a_result->tv_nsec / 1000000);
}

/**
 * @brief time_to_rfc822 Convert time_t to string with RFC822 formatted date and time
 * @param[out] out Output buffer
 * @param[out] out_size_mac Maximum size of output buffer
 * @param[in] t UNIX time
 * @return Length of resulting string if ok or lesser than zero if not
 */
int dap_time_to_str_rfc822(char * a_out, size_t a_out_size_max, dap_time_t a_t)
{
  struct tm *l_tmp;
  time_t l_time = (time_t)a_t;
  l_tmp = localtime(&l_time);

  if ( l_tmp == NULL ) {
    log_it( L_ERROR, "Can't convert data from unix fromat to structured one" );
    return -2;
  }

  int l_ret;
  #ifndef _WIN32
	l_ret = strftime( a_out, a_out_size_max, "%a, %d %b %y %T %z", l_tmp);
  #else
    l_ret = strftime( a_out, a_out_size_max, "%a, %d %b %y %H:%M:%S", l_tmp );
  #endif

  if ( !l_ret ) {
    log_it( L_ERROR, "Can't print formatted time in string" );
    return -1;
  }

  return l_ret;
}

/**
 * @brief Get time_t from string with RFC822 formatted
 * @brief (not WIN32) "%a, %d %b %y %T %z" == "Tue, 02 Aug 22 19:50:41 +0300"
 * @brief (WIN32) !DOES NOT WORK! please, use dap_time_from_str_simplified()
 * @param[out] a_time_str
 * @return time from string or 0 if bad time format
 */
dap_time_t dap_time_from_str_rfc822(const char *a_time_str)
{
	dap_time_t l_time = 0;
    if(!a_time_str) {
        return l_time;
    }
    struct tm l_tm;
    memset(&l_tm, 0, sizeof(struct tm));
	
#ifndef _WIN32
	strptime(a_time_str, "%a, %d %b %y %T %z", &l_tm);
#else
	strptime(a_time_str, "%y%m%d%H%M%S", &l_tm);// <<--- TODO: _!-DOES NOT WORK-!_ { need rework strptime() in dap_strfuncs.c } | in the meantime please use --> dap_time_from_str_simplified()
#endif

    time_t tmp = mktime(&l_tm);
    l_time = (tmp <= 0) ? 0 : tmp;
    return l_time;
}

#ifdef _WIN32
static void tmp_strptime(const char *buff, struct tm *tm)
{
	char tbuff[15];
	uint8_t year;
	uint8_t mon;
	uint8_t day;
	uint8_t len = dap_strlen(buff);

	if (len > 12)
		return;

	memcpy(tbuff, buff, len);

	day = atoi(&tbuff[4]);
	tbuff[4] = '\0';
    if (day > 0)
        day--;

	mon = atoi(&tbuff[2]);
	if (mon > 0)
		mon--;
	tbuff[2] = '\0';

	year = atoi(tbuff);
    if (year < 69)
		year += 100;

	tm->tm_year = year;
	tm->tm_mon = mon;
	tm->tm_mday = day;
	tm->tm_hour = 0;
	tm->tm_min = 0;
	tm->tm_sec = 0;
}
#endif

/**
 * @brief Get time_t from string simplified formatted [%y%m%d = 220610 = 10 june 2022 00:00]
 * @param[out] a_time_str
 * @return time from string or 0 if bad time format
 */
dap_time_t dap_time_from_str_simplified(const char *a_time_str)
{
    dap_time_t l_time = 0;
    if(!a_time_str) {
        return l_time;
    }
    struct tm l_tm;
    memset(&l_tm, 0, sizeof(struct tm));

#ifndef _WIN32
	strptime(a_time_str, "%y%m%d", &l_tm);
#else
	tmp_strptime(a_time_str, &l_tm);
#endif
    l_tm.tm_sec++;
    time_t tmp = mktime(&l_tm);
    l_time = (tmp <= 0) ? 0 : tmp;
    return l_time;
}

/**
 * @brief time_to_rfc822 Convert dap_chain_time_t to string with RFC822 formatted date and time
 * @param[out] out Output buffer
 * @param[out] out_size_mac Maximum size of output buffer
 * @param[in] t UNIX time
 * @return Length of resulting string if ok or lesser than zero if not
 */
int dap_gbd_time_to_str_rfc822(char *a_out, size_t a_out_size_max, dap_gdb_time_t a_chain_time)
{
    time_t l_time = dap_gdb_time_to_sec(a_chain_time);
    return dap_time_to_str_rfc822(a_out, a_out_size_max, l_time);
}

/**
 * @brief dap_ctime_r This function does the same as ctime_r, but if it returns (null), a line break is added.
 * @param a_time
 * @param a_buf The minimum buffer size is 26 elements.
 * @return
 */
char* dap_ctime_r(dap_time_t *a_time, char* a_buf)
{
    char *l_fail_ret = "(null)\r\n";
    if (!a_buf)
        return l_fail_ret;
    if(!a_time || *a_time > DAP_END_OF_DAYS) {
        strcpy(a_buf, l_fail_ret);
        return l_fail_ret;
    }
    struct tm l_time;
#ifdef DAP_OS_WINDOWS
    errno_t l_errno;
    l_errno = localtime_s(&l_time, (time_t *)a_time);
    if (!l_errno)
        l_errno = asctime_s(a_buf, sizeof(l_time), &l_time);
    if (!l_errno)
        return a_buf;
    else {
        strcpy(a_buf, l_fail_ret);
        return l_fail_ret;
    }
#else
    localtime_r((time_t*)a_time, &l_time);
    char *l_str_time = asctime_r(&l_time, a_buf);
    if (l_str_time)
        return  l_str_time;
    else {
        strcpy(a_buf, l_fail_ret);
        return l_fail_ret;
    }
#endif
}

/**
 * @brief dap_chain_ctime_r This function does the same as ctime_r, but if it returns (null), a line break is added.
 * @param a_time
 * @param a_buf The minimum buffer size is 26 elements.
 * @return
 */
char* dap_gdb_ctime_r(dap_gdb_time_t *a_chain_time, char* a_buf){
    dap_time_t l_time = dap_gdb_time_to_sec(*a_chain_time);
    return dap_ctime_r(&l_time, a_buf);
}

