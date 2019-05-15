/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * Anatolii Kurotych <akurotych@gmail.com>
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
#pragma once
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define DAP_NEW(a)    ( (a*) malloc(sizeof(a)))
#define DAP_NEW_SIZE(a,b)    ( (a*) malloc(b))
#define DAP_NEW_Z(a) ( (a*) calloc(1,sizeof(a)))
#define DAP_NEW_Z_SIZE(a,b) ( (a*) calloc(1,b))
#define DAP_REALLOC(a,b) (realloc(a,b))

#define DAP_DELETE(a)   free(a)
#define DAP_DUP(a) (__typeof(a) ret = memcpy(ret,a,sizeof(*a)) )

#define DAP_PROTOCOL_VERSION 22

#if defined(__GNUC__) ||defined (__clang__)
#define DAP_ALIGN_PACKED  __attribute__((aligned(1),packed))
#else
#define DAP_ALIGN_PACKED  __attribute__((aligned(1),packed))
#endif

/**
 * @brief The log_level enum
 */
enum log_level{L_CRITICAL=5,L_ERROR=4, L_WARNING=3,L_NOTICE=2,L_INFO=1,L_DEBUG=0};

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DAP_ASCII_ALNUM = 1 << 0,
    DAP_ASCII_ALPHA = 1 << 1,
    DAP_ASCII_CNTRL = 1 << 2,
    DAP_ASCII_DIGIT = 1 << 3,
    DAP_ASCII_GRAPH = 1 << 4,
    DAP_ASCII_LOWER = 1 << 5,
    DAP_ASCII_PRINT = 1 << 6,
    DAP_ASCII_PUNCT = 1 << 7,
    DAP_ASCII_SPACE = 1 << 8,
    DAP_ASCII_UPPER = 1 << 9,
    DAP_ASCII_XDIGIT = 1 << 10
} DapAsciiType;

static const uint16_t s_ascii_table_data[256] = {
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004,
    0x004, 0x104, 0x104, 0x004, 0x104, 0x104, 0x004, 0x004,
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004,
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004,
    0x140, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x459, 0x459, 0x459, 0x459, 0x459, 0x459, 0x459, 0x459,
    0x459, 0x459, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x0d0, 0x653, 0x653, 0x653, 0x653, 0x653, 0x653, 0x253,
    0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253,
    0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253,
    0x253, 0x253, 0x253, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x0d0, 0x473, 0x473, 0x473, 0x473, 0x473, 0x473, 0x073,
    0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073,
    0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073,
    0x073, 0x073, 0x073, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x004
/* the upper 128 are all zeroes */
};

//const uint16_t * const c_dap_ascii_table = s_ascii_table_data;

#define dap_ascii_isspace(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_SPACE) != 0
#define dap_ascii_isalpha(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_ALPHA) != 0

int dap_common_init( const char * a_log_file );
void dap_common_deinit(void);

// list of logs
typedef struct dap_list_logs_item{
    time_t t;
    char *str;
} dap_list_logs_item_t;

// set max items in log list
void dap_log_set_max_item(unsigned int a_max);
// get logs from list
char *dap_log_get_item(time_t a_start_time, int a_limit);

void _log_it(const char * log_tag, enum log_level, const char * format,...);
void _vlog_it(const char * log_tag, enum log_level, const char * format, va_list ap );
#define log_it(_log_level,...) _log_it(LOG_TAG,_log_level,##__VA_ARGS__)
#define vlog_it(a_log_level,a_format,a_ap) _vlog_it(LOG_TAG,a_log_level,a_format,a_ap)

const char * log_error(void);
void set_log_level(enum log_level ll);
void dap_set_log_tag_width(size_t width);

char *dap_itoa(int i);

int time_to_rfc822(char * out, size_t out_size_max, time_t t);

int get_select_breaker(void);
int send_select_break(void);
char * exec_with_ret(const char * a_cmd);
char * exec_with_ret_multistring(const char * a_cmd);
char * dap_random_string_create_alloc(size_t a_length);
void dap_random_string_fill(char *str, size_t length);
void *memzero(void *mem, size_t n);
void dap_dump_hex(const void* data, size_t size);

size_t dap_hex2bin(uint8_t *a_out, const char *a_in, size_t a_len);
size_t dap_bin2hex(char *a_out, const void *a_in, size_t a_len);
void dap_digit_from_string(const char *num_str, uint8_t *raw, size_t raw_len);


#ifdef __MINGW32__
int exec_silent(const char *a_cmd);
#endif

#ifdef __cplusplus
}
#endif
