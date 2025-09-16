#pragma once
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef DAP_OS_WINDOWS
#define localtime_r(a, b) localtime_s((b), (a))
#endif

#define DAP_TIME_STR_SIZE 32

#define DAP_END_OF_DAYS 4102444799
// Constant to convert seconds to nanoseconds
#define DAP_NSEC_PER_SEC 1000000000
// Constant to convert seconds to microseconds
#define DAP_USEC_PER_SEC 1000000
// Seconds per day
#define DAP_SEC_PER_DAY 86400

// time in seconds
typedef uint64_t dap_time_t;
// time in nanoseconds
typedef uint64_t dap_nanotime_t;

// Create nanotime from second
dap_nanotime_t dap_nanotime_from_sec(dap_time_t a_time);
// Get seconds from nanotime
dap_time_t dap_nanotime_to_sec(dap_nanotime_t a_time);

/**
 * @brief dap_chain_time_now Get current time in seconds since January 1, 1970 (UTC)
 * @return Returns current UTC time in seconds.
 */
dap_time_t dap_time_now(void);
/**
 * @brief dap_clock_gettime Get current time in nanoseconds since January 1, 1970 (UTC)
 * @return Returns current UTC time in nanoseconds.
 */
dap_nanotime_t dap_nanotime_now(void);


// crossplatform usleep
void dap_usleep(uint64_t a_microseconds);


char* dap_nanotime_to_str(dap_nanotime_t *a_time, char* a_buf);

/**
 * @brief dap_time_to_str_rfc822 This function converts time to stirng format.
 * @param a_time
 * @param a_buf
 * @return 0 if success, overwise returns a error code
 */
int dap_time_to_str_rfc822(char * out, size_t out_size_max, dap_time_t a_time);
dap_time_t dap_time_from_str_rfc822(const char *a_time_str);
int dap_nanotime_to_str_rfc822(char *a_out, size_t a_out_size_max, dap_nanotime_t a_chain_time);
int timespec_diff(struct timespec *a_start, struct timespec *a_stop, struct timespec *a_result);

dap_time_t dap_time_from_str_simplified(const char *a_time_str);

