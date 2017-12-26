/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <syslog.h>
#include <libconfig.h>
#include <unistd.h>
#include "common.h"
#include "config.h"
#define LAST_ERROR_MAX 255

#define LOG_TAG "common"

char last_error[LAST_ERROR_MAX]={0};
enum log_level log_level=DEBUG;
FILE * lf=NULL;

int common_init()
{
    const char * fn = (my_config.log_file)? my_config.log_file : DEF_LOG ;
    lf=fopen(fn, "a");
    if(lf==NULL){
        fprintf(stderr,"Can't open log file %s to append\n", fn);
        lf=stdout;
        return -1;
    }

	//printf("Common init\n");
    //    lf=fopen("/dev/stdout","a");
	//lf=stdout;
	//strcpy(last_error,"undefined");
    log_it(INFO,"Common modules init (%s)", fn);
	return 0;
}

void common_deinit()
{
	if(lf) fclose(lf);
}

void _log_it(const char * log_tag,enum log_level ll, const char * format,...)
{
// branch predictor optimization
#if defined(__GNUC__)||defined(__GNUG__)||defined(__clang__)
        if (__builtin_expect(!lf,0))
#else
        if (!lf)
#endif
        common_init();

    va_list ap,ap2;

    static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;

    if(ll<log_level)
        return;

    pthread_mutex_lock(&mutex);
    time_t t=time(NULL);
    struct tm* tmp=localtime(&t);
    static char s_time[1024]={0};
    strftime(s_time,sizeof(s_time),"%x-%X",tmp);
        
	va_start(ap,format);
	va_copy(ap2,ap);
        fprintf(lf,"[%s] ",s_time);
        printf("[%s] ",s_time);
	/*if(ll>=ERROR){
		vsnprintf(last_error,LAST_ERROR_MAX,format,ap);
	}*/
	if(ll==DEBUG){
		fprintf(lf,"[DBG] ");
		printf(	"\x1b[37;2m[DBG] ");
	}else if(ll==INFO){
		fprintf(lf,"[   ] ");
		printf("\x1b[32;2m[   ] ");
	}else if(ll==NOTICE){
		fprintf(lf,"[ * ] ");
		printf("\x1b[32m[ * ] ");
	}else if(ll==WARNING){
		fprintf(lf,"[WRN] ");
		printf("\x1b[31;2m[WRN] ");
	}else if(ll==ERROR){
		fprintf(lf,"[ERR] ");
        printf("\x1b[31m[ERR] ");
	}else if(ll==CRITICAL){
		fprintf(lf,"[!!!] ");
		printf("\x1b[1;5;31m[!!!] ");
        }
    fprintf(lf,"[%8s]\t",log_tag);
    printf("[%8s]\t",log_tag);

	vfprintf(lf,format,ap);
	vprintf(format,ap2);
	fprintf(lf,"\n");
	printf("\x1b[0m\n");
	va_end(ap);
	va_end(ap2);
        fflush(lf);
	fflush(stdout);
        pthread_mutex_unlock(&mutex);
}

const char * log_error()
{
	return last_error;
}

#define INT_DIGITS 19		/* enough for 64 bit integer */

char *itoa(int i)
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
 * @param out Output buffer
 * @param out_size_mac Maximum size of output buffer
 * @param t UNIX time
 * @return Length of resulting string if ok or lesser than zero if not
 */
int time_to_rfc822(char * out, size_t out_size_max, time_t t)
{
    struct tm *tmp;
    tmp=localtime(&t);
    if(tmp== NULL){
        log_it(ERROR,"Can't convert data from unix fromat to structured one");
        return -2;
    }else{
        int ret;
        ret=strftime(out, out_size_max,"%a, %d %b %y %T %z",tmp);
        //free(tmp);
        if(ret>0){
            return ret;
        }else{
            log_it(ERROR,"Can't print formatted time in string");
            return -1;
        }
    }
}

/**
 * @brief get_select_breaker
 * @return
 */
static int breaker_set[2] = { -1, -1 };
static int initialized = 0;
static struct timespec break_latency = { tv_sec: 0, tv_nsec: 1 * 1000 * 1000 };
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


void hexdump(const void* data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
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
}

/**
* @brief get_utc_date_time
* @param buf_out ( not less 20 bytes )
* @return example: 2017-08-12 13:28:36
*/
void get_utc_date_time(char buf_out[])
{
    struct tm *local;
    time_t t = time(NULL);
    local = gmtime(&t);
    strftime(buf_out, 20, "%Y-%m-%d %H:%M:%S", local);
}
