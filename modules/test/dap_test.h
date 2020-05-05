#pragma once
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define TEXT_COLOR_RED   "\x1B[31m"
#define TEXT_COLOR_GRN   "\x1B[32m"
#define TEXT_COLOR_YEL   "\x1B[33m"
#define TEXT_COLOR_BLU   "\x1B[34m"
#define TEXT_COLOR_MAG   "\x1B[35m"
#define TEXT_COLOR_CYN   "\x1B[36m"
#define TEXT_COLOR_WHT   "\x1B[37m"
#define TEXT_COLOR_RESET "\x1B[0m"

/* Can be used like debug info during write test*/
/**
 * @brief Can be used like debug info during write test
 */
#define dap_test_msg(...) { \
    printf("\t%s", TEXT_COLOR_WHT); \
    printf(__VA_ARGS__); \
    printf("%s\n", TEXT_COLOR_RESET); \
    fflush(stdout); }

#define dap_fail(msg) {\
    printf("\t%s%s!%s\n", TEXT_COLOR_RED, msg, TEXT_COLOR_RESET); \
    abort();}

/* PIF - print if failed. For checking value in loop, for don't repeat output */
/**
 * @brief PIF - print if failed. For checking value in loop, for don't repeat output
 */
#define dap_assert_PIF(expr, msg) { \
    if(expr) {} \
    else { \
    printf("\t%s%s FAILED!%s\n", TEXT_COLOR_RED, msg, TEXT_COLOR_RESET); \
    abort(); } }

/**
 * @brief
*/
#define dap_assert(expr, testname) { \
    if(expr) { \
        printf("\t%s%s PASS.%s\n", TEXT_COLOR_GRN, testname, TEXT_COLOR_RESET); \
        fflush(stdout); \
    } else { \
    printf("\t%s%s FAILED!%s\n", TEXT_COLOR_RED, testname, TEXT_COLOR_RESET); \
    abort(); } } \

/**
 * @brief Display the name test
*/
#define dap_pass_msg(testname) { \
    printf("\t%s%s PASS.%s\n", TEXT_COLOR_GRN, testname, TEXT_COLOR_RESET); \
    fflush(stdout); } \

/**
 * @brief Display the name of the test module
*/
#define dap_print_module_name(module_name) { \
    printf("%s%s passing the tests... %s\n", TEXT_COLOR_CYN, module_name, TEXT_COLOR_RESET); \
    fflush(stdout); }

#define dap_str_equals(str1, str2) strcmp(str1, str2) == 0
#define dap_strn_equals(str1, str2, count) strncmp(str1, str2, count) == 0
int get_cur_time_msec(void);

/*
 How to use benchmark_xxx() functions:

 void mytest_func()
 {
 // doing something ...
 }

 // Repeat mytest_func() 5 time
 int dt = benchmark_test_time(mytest_func, 5);
 // Display result, sample 'Encode and decode PASS. (4 msec.)'
 benchmark_mgs_time("Encode and decode", dt);

 // Repeat mytest_func() within 2 second
 float rate = benchmark_test_rate(mytest_func, 2);
 // Display result, sample 'Encode and decode PASS. (703 times/sec.)'
 benchmark_mgs_rate("Encode and decode", rate);

 */

/**
 * Display time in the format 'x.xx sec.' or 'xx msec.'
 */
void benchmark_mgs_time(const char *text, int dt);

/**
 * Display rate in the format 'xx times/sec.'
 */
void benchmark_mgs_rate(const char *test_name, float rate);
/**
 * Calculate the runtime of a function that repeat several times
 * @func_name function for repeats
 * @repeat how many times repeats
 * @return time in milliseconds
 */
int benchmark_test_time(void (*func_name)(void), int repeat);
/**
 * Calculate the rate of a function that repeat at a minimum specified number of seconds
 * @func_name function for repeats
 * @repeat how many times repeats
 * @return function rate, i.e. count per second
 */
float benchmark_test_rate(void (*func_name)(void), float sec);
