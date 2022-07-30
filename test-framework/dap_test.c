#include "dap_test.h"

#include <sys/time.h>

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

#define dap_pass_msg_benchmark(testname, benchmark_text) \
    printf("\t%s%s PASS. %s%s\n", TEXT_COLOR_GRN, testname, benchmark_text, TEXT_COLOR_RESET); \
    fflush(stdout); \

/**
 * Display time in the format 'x.xx sec.' or 'xx msec.'
 */
void benchmark_mgs_time(const char *test_name, int dt)
{
    char buf[120];
    if(abs(dt) >= 1000) {
        snprintf(buf, 120, "(%.3lf sec.)", dt * 1. / 1000);
    }
    else {

        snprintf(buf, 120, "(%d msec.)", dt);
    }
    dap_pass_msg_benchmark(test_name, buf);
}

/**
 * Display rate in the format 'xx times/sec.'
 */
void benchmark_mgs_rate(const char *test_name, float rate)
{
    char buf[120];
    if(rate > 100) {
        snprintf(buf, 120, "(%.0lf times/sec.)", rate);
    }
    else if(rate > 10) {
        snprintf(buf, 120, "%.1lf times/sec.", rate);
    }
    else {
        snprintf(buf, 120, "%.2lf times/sec.", rate);
    }
    dap_pass_msg_benchmark(test_name, buf);
}

/**
 * @return current time in milliseconds
 */
int get_cur_time_msec(void)
{
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    int msec = time.tv_sec * 1000 + (time.tv_nsec + 500000) / 1000000;
    return msec;
}

/**
 * Calculate the runtime of a function that repeat several times
 * @func_name function for repeats
 * @repeat how many times repeats
 * @return time in milliseconds
 */
int benchmark_test_time(void (*func_name)(void), int repeat)
{
    int t1 = get_cur_time_msec();
    for(int i = 0; i < repeat; i++)
        func_name();
    int t2 = get_cur_time_msec();
    return t2 - t1;
}

/**
 * Calculate the rate of a function that repeat at a minimum specified number of seconds
 * @func_name function for repeats
 * @repeat how many times repeats
 * @return function rate, i.e. count per second
 */
float benchmark_test_rate(void (*func_name)(void), float sec)
{
    if(sec < 0.1f) {
        dap_test_msg("undefined times/sec.");
        return 0;
    }
    int t1 = get_cur_time_msec();
    int repeat = 0, dt;
    do {
        func_name();
        dt = (get_cur_time_msec() - t1);
        repeat++;
    }
    while(dt < sec * 1000);
    float rate = repeat * 1000.f / dt;
    return rate;
}

