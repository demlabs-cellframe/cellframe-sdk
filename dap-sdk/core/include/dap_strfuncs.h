/* DAP String Functions */

#pragma once

#include <sys/types.h>

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "dap_math_ops.h"
#include "dap_fnmatch.h"

#define dap_return_if_fail(expr)            {if(!(expr)) {return;}}
#define dap_return_val_if_fail(expr,val)    {if(!(expr)) {return (val);}}

#define POINTER_TO_INT(p)   ((int)   (p))
#define POINTER_TO_UINT(p)  ((unsigned int)  (p))

#define INT_TO_POINTER(i)   ((void*)  (i))
#define UINT_TO_POINTER(u)  ((void*)  (u))

#undef  max
#define max(a, b)  (((a) > (b)) ? (a) : (b))

#undef  min
#define min(a, b)  (((a) < (b)) ? (a) : (b))

#undef  abs
#define abs(a)     (((a) < 0) ? -(a) : (a))

#undef  clamp
#define clamp(x, low, high)  (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
char *strptime( char *buff, const char *fmt, struct tm *tm );
#endif

bool dap_isstralnum(const char *c);
char* dap_strcat2(const char* s1, const char* s2);
size_t dap_strlen(const char *a_str);
// compare a_str1 and a_str2
int dap_strcmp(const char *a_str1, const char *a_str2);
// compare a_n characters of a_str1 and a_str2
int dap_strncmp(const char *a_str1, const char *a_str2, size_t a_n);
// duplicates a string
char* dap_strdup(const char *a_str);
char* dap_strdup_vprintf(const char *a_format, va_list a_args);
char* dap_strdup_printf(const char *a_format, ...);

char* dap_stpcpy(char *a_dest, const char *a_src);
char* dap_strstr_len(const char *a_haystack, ssize_t a_haystack_len, const char *a_needle);
// concatenates all of str_array's strings, sliding in an optional separator, the returned string is newly allocated.
char* dap_strjoinv(const char *a_separator, char **a_str_array);
char* dap_strjoin(const char *a_separator, ...);
// split up string into max_tokens tokens at delimiter and return a newly allocated string array
char** dap_strsplit(const char *a_string, const char *a_delimiter, int a_max_tokens);
size_t dap_str_countv(char **a_str_array);
size_t dap_str_symbol_count(const char *a_str, char a_sym);
bool dap_str_remove_spaces(char *a_str);
// copies a NULL-terminated array of strings
char** dap_strdupv(const char **a_str_array);
// frees the array itself and all of its strings.
void dap_strfreev(char **a_str_array);

// removes leading spaces
char* dap_strchug(char *a_string);
// removes trailing spaces
char* dap_strchomp(char *a_string);
// removes leading & trailing spaces 
#define dap_strstrip( a_string )    dap_strchomp (dap_strchug (a_string))

// Converts all lower case ASCII letters to upper case ASCII letters.
char* dap_strup(const char *a_str, ssize_t a_len);
// Converts a string to lower case.
char* dap_strdown(const char *a_str, ssize_t a_len);
char* dap_strreverse(char *a_string);

#ifdef DAP_GLOBAL_IS_INT128
uint128_t dap_strtou128(const char *p, char **endp, int base);
int128_t dap_strtoi128(const char *p, char **endp, int base);


/**
 * @brief atoi128
 * @param p
 * @return
 */
static inline int128_t dap_atoi128(const char *p) {
    return dap_strtoi128(p, (char**)NULL, 10);
}


/**
 * @brief atou128
 * @param p
 * @return
 */
static inline uint128_t dap_atou128(const char *p) {
    return dap_strtou128(p, (char**)NULL, 10);
}

char *dap_utoa128(char *dest, uint128_t v, int base);
char *dap_itoa128(char *a_str, int128_t a_value, int a_base);

#endif


#ifdef _WIN32
#ifdef HAVE_STRNDUP
#define strndup(s, l) _strndup(s, l)
#endif
char *_strndup(const char *str, unsigned long len);
#endif


typedef uint32_t unichar;
typedef uint16_t unichar2;

/**
 * Converts a single character to UTF-8.
 * @c: a Unicode character code
 * @outbuf: (out caller-allocates) (optional): output buffer, must have at
 *       least 6 bytes of space. If %NULL, the length will be computed and
 *       returned and nothing will be written to @outbuf.
  * Returns: number of bytes written
 */
int dap_unichar_to_utf8 (unichar c, char   *outbuf);

/**
 * Convert a string from UTF-16 to UTF-8. The result will be
 * terminated with a 0 byte.
 * @str: a UTF-16 encoded string
 * @len: the maximum length (number of #gunichar2) of @str to use.
 *     If @len < 0, then the string is nul-terminated.
 * @items_read: (out) (optional): location to store number of
 *     words read, or %NULL. If %NULL, then %G_CONVERT_ERROR_PARTIAL_INPUT will
 *     be returned in case @str contains a trailing partial character. If
 *     an error occurs then the index of the invalid input is stored here.
 *     It’s guaranteed to be non-negative.
 * @items_written: (out) (optional): location to store number
 *     of bytes written, or %NULL. The value stored here does not include the
 *     trailing 0 byte. It’s guaranteed to be non-negative.
 *
 * Returns: (transfer full): a pointer to a newly allocated UTF-8 string.
 *     This value must be freed with g_free(). If an error occurs,
 *     %NULL will be returned and @error set.
 **/
char* dap_utf16_to_utf8(const unichar2 *str, long len, long *items_read, long *items_written);

#ifdef __cplusplus
}
#endif
