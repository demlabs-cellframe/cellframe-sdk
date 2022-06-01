/* DAP String Functions */
#ifdef _WIN32
//#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#endif
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_strfuncs.h"

#define LOG_TAG "dap_strfunc"

/**
 * @brief dap_isstralnum
 * check if string contains digits and alphabetical symbols
 * @param c
 * @return
 */
bool dap_isstralnum(const char *c)
{ 
    size_t str_len = strlen(c);

    for (size_t i = 0; i < str_len; i++)
    {
        if (!isalnum(c[i]) && c[i] != '_' && c[i] != '-')
            return false;
    }

    return true;
}

/**
 * @brief strcat two strings with new char array in result
 * 
 * @param s1 preallocated buffer with char string
 * @param s2 char string
 * @return char* 
 */
char* dap_strcat2(const char* s1, const char* s2)
{
  size_t size1 = 0;
  size_t size2 = 0;
  if (!s1)
    size1 = 0;
  else
    size1 = strlen(s1);
  if (!s2)
    size2 = 0;
  else
    size2 = strlen(s2);
    
  char* result = malloc(size1 + size2 + 1);

  if(result == NULL) 
  {
    exit(EXIT_FAILURE);
  }

  memcpy(result, s1, size1);
  memcpy(result+size1, s2, size2);
  free((void*)s1);
  result[size1 + size2] = '\0';
  return result;
}

/**
 * @brief s_strdigit
 * @param c
 * @return
 */
static int s_strdigit(char c)
{
    /* This is ASCII / UTF-8 specific, would not work for EBCDIC */
    return (c >= '0' && c <= '9') ? c - '0'
        :  (c >= 'a' && c <= 'z') ? c - 'a' + 10
        :  (c >= 'A' && c <= 'Z') ? c - 'A' + 10
        :  255;
}

#ifdef DAP_GLOBAL_IS_INT128

/**
 * @brief s_strtou128
 * @param p
 * @param endp
 * @param base
 * @return
 */
static uint128_t s_strtou128(const char *p, char **endp, int base)
{
    uint128_t v = 0;
    int digit;

    if (base == 0) {    /* handle octal and hexadecimal syntax */
        base = 10;
        if (*p == '0') {
            base = 8;
            if ((p[1] == 'x' || p[1] == 'X') && s_strdigit(p[2]) < 16) {
                p += 2;
                base = 16;
            }
        }
    }
    if (base < 2 || base > 36) {
        errno = EINVAL;
    } else
    if ((digit = s_strdigit(*p)) < base) {
        v = digit;
        /* convert to unsigned 128 bit with overflow control */
        while ((digit = s_strdigit(*++p)) < base) {
            uint128_t v0 = v;
            v = v * base + digit;
            if (v < v0) {
                v = ~(uint128_t)0;
                errno = ERANGE;
            }
        }
        if (endp) {
            *endp = (char *)p;
        }
    }
    return v;
}

/**
 * @brief dap_strtou128
 * @param p
 * @param endp
 * @param base
 * @return
 */
uint128_t dap_strtou128(const char *p, char **endp, int base)
{
    if (endp) {
        *endp = (char *)p;
    }
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '-') {
        p++;
        return -s_strtou128(p, endp, base);
    } else {
        if (*p == '+')
            p++;
        return s_strtou128(p, endp, base);
    }
}

/**
 * @brief dap_strtoi128
 * @param p
 * @param endp
 * @param base
 * @return
 */
int128_t dap_strtoi128(const char *p, char **endp, int base)
{
    uint128_t v;

    if (endp) {
        *endp = (char *)p;
    }
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '-') {
        p++;
        v = s_strtou128(p, endp, base);
        if (v >= (uint128_t)1 << 127) {
            if (v > (uint128_t)1 << 127)
                errno = ERANGE;
            return -(int128_t)(((uint128_t)1 << 127) - 1) - 1;
        }
        return -(int128_t)v;
    } else {
        if (*p == '+')
            p++;
        v = s_strtou128(p, endp, base);
        if (v >= (uint128_t)1 << 127) {
            errno = ERANGE;
            return (int128_t)(((uint128_t)1 << 127) - 1);
        }
        return (int128_t)v;
    }
}
/**
 * @brief dap_utoa128 convert unsigned integer to ASCII 
 * @param dest
 * @param v
 * @param base
 * @return
 */
char *dap_utoa128(char *dest, uint128_t v, int base)
{
    char buf[129];
    char *p = buf + 128;
    const char *digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    *p = '\0';
    if (base >= 2 && base <= 36) {
        while (v > (unsigned)base - 1) {
            *--p = digits[v % base];
            v /= base;
        }
        *--p = digits[v];
    }
    return strcpy(dest, p);
}

/**
 * @brief dap_itoa128
 * 
 * @param a_str 
 * @param a_value 
 * @param a_base 
 * @return char* 
 */
char *dap_itoa128(char *a_str, int128_t a_value, int a_base)
{
    char *p = a_str;
    uint128_t uv = (uint128_t)a_value;
    if (a_value < 0) {
        *p++ = '-';
        uv = -uv;
    }
    if (a_base == 10)
        dap_utoa128(p, uv, 10);
    else
    if (a_base == 16)
        dap_utoa128(p, uv, 16);
    else
        dap_utoa128(p, uv, a_base);
    return a_str;
}
#endif

/**
 * dap_strlen:
 * @a_str: (nullable): the string
 *
 * If @a_str is %NULL it returns 0
 *
 * Returns: length of the string
 */

/**
 * @brief dap_strlen get length of the string
 * 
 * @param a_str pointer to string
 * @return size_t 
 */

size_t dap_strlen(const char *a_str)
{
    size_t l_length = 0;

    if(a_str) {
        l_length = strlen(a_str);
    }
    return l_length;
}

/**
 * @brief dap_strcmp a_str1 and a_str2
 * 
 * @param a_str1 (nullable): the string
 * @param a_str2 (nullable): the string
 * @return int 
 */

int dap_strcmp(const char *a_str1, const char *a_str2)
{
    if(a_str1 && a_str2) {
        return strcmp(a_str1, a_str2);
    }
    return -1;
}

/**
 * @brief dap_strcmp
 * 
 * @param a_str1  (nullable): the string
 * @param a_str2  (nullable): the string
 * @param a_n Compare a_n characters of a_str1 and a_str2
 * @return int 
 */

int dap_strncmp(const char *a_str1, const char *a_str2, size_t a_n)
{
    if(a_str1 && a_str2) {
        return strncmp(a_str1, a_str2, a_n);
    }
    return -1;
}


/**
 * @brief dap_strdup:
 * Duplicates a string. If @a_str is %NULL it returns %NULL.
 * The returned string should be freed
 * when no longer needed.
 *
 * @param a_str (nullable): the string to duplicate
 * @return char* duplicated string
 */

char* dap_strdup(const char *a_str)
{
    char *l_new_str;

    if(a_str){
        size_t l_length = (size_t) (strlen(a_str) + 1);
        if(l_length){
            l_new_str = DAP_NEW_SIZE(char, l_length);
            if (l_new_str)
                memcpy(l_new_str, a_str, l_length);
        }else
            l_new_str = NULL;
    }
    else
        l_new_str = NULL;

    return l_new_str;
}

/**
 * @brief dap_strdup_vprintf
 * 
 * Similar to the standard C vsprintf() function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed with DAP_DELETE()
 * when no longer needed.
 *
 * Returns: a newly-allocated string holding the result
 * 
 * @param a_format  a standard printf() format string, but notice
 *     [string precision pitfalls][string-precision]
 * @param a_args the list of parameters to insert into the format string
 * @return char* 
 */

char* dap_strdup_vprintf(const char *a_format, va_list a_args)
{
    char *l_string = NULL;
    int len = dap_vasprintf(&l_string, a_format, a_args);
    if(len < 0)
        l_string = NULL;
    return l_string;
}

/**
 * @brief dap_strdup_printf:
 * 
 *  * Similar to the standard C sprintf() function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed with DAP_DELETE()
 * when no longer needed.
 * 
 * @param a_format a standard printf() format string
 * @param ... 
 * @return char* a newly-allocated string holding the result
 */

DAP_PRINTF_ATTR(1,2) char *dap_strdup_printf(const char *a_format, ...)
{
    char *l_buffer;
    va_list l_args;

    va_start(l_args, a_format);
    l_buffer = dap_strdup_vprintf(a_format, l_args);
    va_end(l_args);

    return l_buffer;
}

/*
 // alternative version
 char* dap_strdup_printf2(const char *a_format, ...)
 {
 size_t l_buffer_size = 0;
 char *l_buffer = NULL;
 va_list l_args;

 va_start(l_args, a_format);
 l_buffer_size += vsnprintf(l_buffer, 0, a_format, l_args);
 va_end(l_args);

 if(!l_buffer_size)
 return NULL;
 l_buffer = DAP_NEW_SIZE(char, l_buffer_size + 1);

 va_start(l_args, a_format);
 vsnprintf(l_buffer, l_buffer_size + 1, a_format, l_args);
 va_end(l_args);

 return l_buffer;
 }*/

/**
 * dap_stpcpy:
 * @a_dest: destination buffer.
 * @a_src: source string.
 *
 * Copies a null-terminated string into the dest buffer, include the
 * trailing null, and return a pointer to the trailing null byte.
 * This is useful for concatenating multiple strings together
 * without having to repeatedly scan for the end.
 *
 * Returns: a pointer to trailing null byte.
 **/
char* dap_stpcpy(char *a_dest, const char *a_src)
{
    char *l_d = a_dest;
    const char *l_s = a_src;

    dap_return_val_if_fail(a_dest != NULL, NULL);
    dap_return_val_if_fail(a_src != NULL, NULL);
    do
        *l_d++ = *l_s;
    while(*l_s++ != '\0');

    return l_d - 1;
}

/**
 * dap_strstr_len:
 * @a_haystack: a string
 * @a_haystack_len: the maximum length of @a_haystack. Note that -1 is
 *     a valid length, if @a_haystack is null-terminated, meaning it will
 *     search through the whole string.
 * @a_needle: the string to search for
 *
 * Searches the string @a_haystack for the first occurrence
 * of the string @a_needle, limiting the length of the search
 * to @a_haystack_len.
 *
 * Returns: a pointer to the found occurrence, or
 *    %NULL if not found.
 */
char* dap_strstr_len(const char *a_haystack, ssize_t a_haystack_len, const char *a_needle)
{
    dap_return_val_if_fail(a_haystack != NULL, NULL);
    dap_return_val_if_fail(a_needle != NULL, NULL);

    if(a_haystack_len < 0)
        return strstr(a_haystack, a_needle);
    else
    {
        const char *l_p = a_haystack;
        ssize_t l_needle_len = (ssize_t) strlen(a_needle);
        const char *l_end;
        ssize_t l_i;

        if(l_needle_len == 0)
            return (char *) a_haystack;

        if(a_haystack_len < l_needle_len)
            return NULL;

        l_end = a_haystack + a_haystack_len - l_needle_len;

        while(l_p <= l_end && *l_p)
        {
            for(l_i = 0; l_i < l_needle_len; l_i++)
                if(l_p[l_i] != a_needle[l_i])
                    goto next;

            return (char *) l_p;

            next:
            l_p++;
        }

        return NULL;
    }
}

/**
 * dap_strjoinv:
 * @a_separator: (allow-none): a string to insert between each of the
 *     strings, or %NULL
 * @a_str_array: a %NULL-terminated array of strings to join
 *
 * Joins a number of strings together to form one long string, with the
 * optional @separator inserted between each of them. The returned string
 * should be freed.
 *
 * If @str_array has no items, the return value will be an
 * empty string. If @a_str_array contains a single item, @a_separator will not
 * appear in the resulting string.
 *
 * Returns: a newly-allocated string containing all of the strings joined
 *     together, with @a_separator between them
 */
char* dap_strjoinv(const char *a_separator, char **a_str_array)
{
    char *l_string;
    char *l_ptr;

    dap_return_val_if_fail(a_str_array != NULL, NULL);

    if(a_separator == NULL)
        a_separator = "";

    if(*a_str_array)
    {
        int l_i;
        size_t l_len;
        size_t l_separator_len;

        l_separator_len = strlen(a_separator);
        /* First part, getting length */
        l_len = 1 + strlen(a_str_array[0]);
        for(l_i = 1; a_str_array[l_i] != NULL; l_i++)
            l_len += strlen(a_str_array[l_i]);
        l_len += l_separator_len * (l_i - 1);

        /* Second part, building string */
        l_string = DAP_NEW_SIZE(char, l_len);
        l_ptr = dap_stpcpy(l_string, *a_str_array);
        for(l_i = 1; a_str_array[l_i] != NULL; l_i++)
                {
            l_ptr = dap_stpcpy(l_ptr, a_separator);
            l_ptr = dap_stpcpy(l_ptr, a_str_array[l_i]);
        }
    }
    else
        l_string = dap_strdup("");

    return l_string;
}

/**
 * dap_strjoin:
 * @a_separator: (allow-none): a string to insert between each of the
 *     strings, or %NULL
 * @...: a %NULL-terminated list of strings to join
 *
 * Joins a number of strings together to form one long string, with the
 * optional @a_separator inserted between each of them. The returned string
 * should be freed.
 *
 * Returns: a newly-allocated string containing all of the strings joined
 *     together, with @a_separator between them
 */
char* dap_strjoin(const char *a_separator, ...)
{
    char *string, *l_s;
    va_list l_args;
    size_t l_len;
    size_t l_separator_len;
    char *l_ptr;

    if(a_separator == NULL)
        a_separator = "";

    l_separator_len = strlen(a_separator);

    va_start(l_args, a_separator);

    l_s = va_arg(l_args, char*);

    if(l_s)
    {
        /* First part, getting length */
        l_len = 1 + strlen(l_s);

        l_s = va_arg(l_args, char*);
        while(l_s)
        {
            l_len += l_separator_len + strlen(l_s);
            l_s = va_arg(l_args, char*);
        }
        va_end(l_args);

        /* Second part, building string */
        string = DAP_NEW_SIZE(char, l_len);

        va_start(l_args, a_separator);

        l_s = va_arg(l_args, char*);
        l_ptr = dap_stpcpy(string, l_s);

        l_s = va_arg(l_args, char*);
        while(l_s)
        {
            l_ptr = dap_stpcpy(l_ptr, a_separator);
            l_ptr = dap_stpcpy(l_ptr, l_s);
            l_s = va_arg(l_args, char*);
        }
    }
    else
        string = dap_strdup("");

    va_end(l_args);

    return string;
}

typedef struct _dap_slist dap_slist;

struct _dap_slist
{
    void* data;
    dap_slist *next;
};

static dap_slist* dap_slist_prepend(dap_slist *a_list, void* a_data)
{
    dap_slist *l_new_list;

    l_new_list = DAP_NEW_Z(dap_slist);
    l_new_list->data = a_data;
    l_new_list->next = a_list;

    return l_new_list;
}

static void dap_slist_free(dap_slist *a_list)
{
    if(a_list)
    {
        dap_slist *l_cur_node;
        dap_slist *l_last_node = a_list;
        while(l_last_node)
        {
            l_cur_node = l_last_node;
            l_last_node = l_last_node->next;
            DAP_DELETE(l_cur_node);
        }
    }
}

/**
 * dap_strsplit:
 * @a_string: a string to split
 * @a_delimiter: a string which specifies the places at which to split
 *     the string. The delimiter is not included in any of the resulting
 *     strings, unless @a_max_tokens is reached.
 * @a_max_tokens: the maximum number of pieces to split @a_string into.
 *     If this is less than 1, the string is split completely.
 *
 * Splits a string into a maximum of @a_max_tokens pieces, using the given
 * @a_delimiter. If @a_max_tokens is reached, the remainder of @a_string is
 * appended to the last token.
 *
 * As an example, the result of dap_strsplit (":a:bc::d:", ":", -1) is a
 * %NULL-terminated vector containing the six strings "", "a", "bc", "", "d"
 * and "".
 *
 * As a special case, the result of splitting the empty string "" is an empty
 * vector, not a vector containing a single string. The reason for this
 * special case is that being able to represent a empty vector is typically
 * more useful than consistent handling of empty elements. If you do need
 * to represent empty elements, you'll need to check for the empty string
 * before calling dap_strsplit().
 *
 * Returns: a newly-allocated %NULL-terminated array of strings.
 * Use dap_strfreev() to free it.
 */
char** dap_strsplit(const char *a_string, const char *a_delimiter, int a_max_tokens)
{
    dap_slist *l_string_list = NULL, *l_slist;
    char **l_str_array, *l_s;
    uint32_t l_n = 1;

    dap_return_val_if_fail(a_string != NULL, NULL);
    dap_return_val_if_fail(a_delimiter != NULL, NULL);

    if(a_max_tokens < 1)
        a_max_tokens = INT_MAX;

    l_s = strstr(a_string, a_delimiter);
    if(l_s)
    {
        uint32_t delimiter_len = (uint32_t) strlen(a_delimiter);

        do
        {
            uint32_t len;
            char *new_string;

            len = (uint32_t) (l_s - a_string);
            new_string = DAP_NEW_SIZE(char, len + 1);
            strncpy(new_string, a_string, len);
            new_string[len] = 0;
            l_string_list = dap_slist_prepend(l_string_list, new_string);
            l_n++;
            a_string = l_s + delimiter_len;
            l_s = strstr(a_string, a_delimiter);
        }
        while(--a_max_tokens && l_s);
    }
    l_string_list = dap_slist_prepend(l_string_list, dap_strdup(a_string));

    l_str_array = DAP_NEW_SIZE(char*, (l_n + 1) * sizeof(char*));

    l_str_array[l_n--] = NULL;
    for(l_slist = l_string_list; l_slist; l_slist = l_slist->next)
        l_str_array[l_n--] = l_slist->data;

    dap_slist_free(l_string_list);

    return l_str_array;
}

/**
 * @brief  dap_str_countv
 * 
 * @param a_str_array 
 * @return size_t 
 */

size_t dap_str_countv(char **a_str_array)
{
    size_t l_i = 0;
    if(a_str_array)
    {
        for(l_i = 0; a_str_array[l_i] != NULL; l_i++)
            ;
    }
    return l_i;
}

size_t dap_str_symbol_count(const char *a_str, char a_sym)
{
    const char *p = a_str;
    uint32_t l_count = 0;

    while (*p)
        if (*p++ == a_sym)
            l_count++;
    return l_count;
}

/**
 * @brief  dap_strdupv:
 * 
 * @param a_str_array (nullable): a %NULL-terminated array of strings
 * Copies %NULL-terminated array of strings. The copy is a deep copy;
 * the new array should be freed by first freeing each string, then
 * the array itself. g_strfreev() does this for you. If called
 * on a %NULL value, g_strdupv() simply returns %NULL.
 *
 * Returns: (nullable): a new %NULL-terminated array of strings.
 *
 * @return char** 
 */

char** dap_strdupv(const char **a_str_array)
{
    if(a_str_array)
    {
        int l_i;
        char **l_retval;

        l_i = 0;
        while(a_str_array[l_i])
            ++l_i;

        l_retval = DAP_NEW_SIZE(char*, (l_i + 1) * sizeof(char*));

        l_i = 0;
        while(a_str_array[l_i])
        {
            l_retval[l_i] = dap_strdup(a_str_array[l_i]);
            ++l_i;
        }
        l_retval[l_i] = NULL;

        return l_retval;
    }
    else
        return NULL;
}

/**
 * @brief dap_strfreev:
 * 
 * Frees a %NULL-terminated array of strings, as well as each
 * string it contains.
 *
 * If @a_str_array is %NULL, this function simply returns.
 *
 * @param a_str_array (nullable): a %NULL-terminated array of strings to free
 */

void dap_strfreev(char **a_str_array)
{
    if(a_str_array)
    {
        int l_i;
        for(l_i = 0; a_str_array[l_i] != NULL; l_i++)
            DAP_DELETE(a_str_array[l_i]);

        DAP_DELETE(a_str_array);
    }
}

/**
 * @brief dap_strchug:
 * 
 * Removes leading whitespace from a string, by moving the rest
 * of the characters forward.
 *
 * This function doesn't allocate or reallocate any memory;
 * it modifies @a_string in place. Therefore, it cannot be used on
 * statically allocated strings.
 *
 * The pointer to @a_string is returned to allow the nesting of functions.
 * Returns: @a_string
 * 
 * @param a_string a string to remove the leading whitespace from
 * @return char* 
 */

char* dap_strchug(char *a_string)
{
    unsigned char *l_start;

    dap_return_val_if_fail(a_string != NULL, NULL);

    for(l_start = (unsigned char*) a_string; *l_start && dap_ascii_isspace(*l_start); l_start++)
        ;

    memmove(a_string, l_start, strlen((char *) l_start) + 1);

    return a_string;
}

/**
 * dap_strchomp:
 * @a_string: a string to remove the trailing whitespace from
 *
 * Removes trailing whitespace from a string.
 *
 * This function doesn't allocate or reallocate any memory;
 * it modifies @a_string in place. Therefore, it cannot be used
 * on statically allocated strings.
 *
 * The pointer to @a_string is returned to allow the nesting of functions.
 *
 * Returns: @a_string
 */
char* dap_strchomp(char *a_string)
{
    size_t l_len;

    dap_return_val_if_fail(a_string != NULL, NULL);

    l_len = (size_t) strlen(a_string);
    while(l_len--)
    {
        if(dap_ascii_isspace((unsigned char ) a_string[l_len]))
            a_string[l_len] = '\0';
        else
            break;
    }
    return a_string;
}

/**
 * @brief dap_strup
 * 
 * Converts all lower case ASCII letters to upper case ASCII letters.
 *
 * Returns: a newly allocated string, with all the lower case
 *     characters in @a_str converted to upper case
 * 
 * @param a_str a string
 * @param a_len  length of @a_str in bytes, or -1 if @a_str is nul-terminated
 * @return char* 
 */

char* dap_strup(const char *a_str, ssize_t a_len)
{
    char *l_result, *l_s;

    dap_return_val_if_fail(a_str != NULL, NULL);

    if(a_len < 0)
        a_len = strlen(a_str);

    l_result = strndup(a_str, a_len);
    for(l_s = l_result; *l_s; l_s++)
        *l_s = toupper(*l_s);

    return l_result;
}

/**
 * @brief  dap_strdown
 *  Converts all upper case ASCII letters to lower case ASCII letters.
 *
 * Returns: a newly-allocated string, with all the upper case
 *     characters in @a_str converted to lower case
 * 
 * @param a_str a string
 * @param a_len length of @a_str in bytes, or -1 if @a_str is nul-terminated
 * @return char* 
 */

char* dap_strdown(const char *a_str, ssize_t a_len)
{
    char *l_result, *l_s;

    dap_return_val_if_fail(a_str != NULL, NULL);

    if(a_len < 0)
        a_len = strlen(a_str);

    l_result = strndup(a_str, a_len);
    for(l_s = l_result; *l_s; l_s++)
        *l_s = tolower(*l_s);

    return l_result;
}


/**
 * @brief dap_strreverse
 * Reverses all of the bytes in a string. For example,
 * `dap_strreverse("abcdef")` will result in "fedcba".
 *
 * Note that g_strreverse() doesn't work on UTF-8 strings
 * containing multibyte characters.
 *
 * Returns: the same pointer passed in as @a_string
 *
 * @param a_string  the string to reverse
 * @return char* 
 */

char* dap_strreverse(char *a_string)
{
    dap_return_val_if_fail(a_string != NULL, NULL);

    if(*a_string)
    {
        register char *l_h, *l_t;

        l_h = a_string;
        l_t = a_string + strlen(a_string) - 1;

        while(l_h < l_t)
        {
            register char l_c;

            l_c = *l_h;
            *l_h = *l_t;
            l_h++;
            *l_t = l_c;
            l_t--;
        }
    }

    return a_string;
}

#ifdef _WIN32
char *strptime( char *buff, const char *fmt, struct tm *tm ) {
  uint32_t len = strlen( buff );
  dap_sscanf( buff,"%u.%u.%u_%u.%u.%u",&tm->tm_year, &tm->tm_mon, &tm->tm_mday, &tm->tm_hour, &tm->tm_min, &tm->tm_sec );
  tm->tm_year += 2000;
  return buff + len;
}

/**
 * @brief _strndup
 * 
 * @param str 
 * @param len 
 * @return char* 
 */

char *_strndup(const char *str, unsigned long len) {
    char *buf = (char*)memchr(str, '\0', len);
    if (buf)
        len = buf - str;
    buf = (char*)malloc(len + 1);
    memcpy(buf, str, len);
    buf[len] = '\0';
    return buf;
}
#endif

#define SURROGATE_VALUE(h,l) (((h) - 0xd800) * 0x400 + (l) - 0xdc00 + 0x10000)

#define UTF8_LENGTH(char)              \
  ((char) < 0x80 ? 1 :                 \
   ((char) < 0x800 ? 2 :               \
    ((char) < 0x10000 ? 3 :            \
     ((char) < 0x200000 ? 4 :          \
      ((char) < 0x4000000 ? 5 : 6)))))

/**
 * dap_unichar_to_utf8:
 * @c: a Unicode character code
 * @outbuf: (out caller-allocates) (optional): output buffer, must have at
 *       least 6 bytes of space. If %NULL, the length will be computed and
 *       returned and nothing will be written to @outbuf.
 *
 * Converts a single character to UTF-8.
 *
 * Returns: number of bytes written
 */
int dap_unichar_to_utf8 (unichar c, char   *outbuf)
{
  int len = 0;
  int first;
  int i;

  if (c < 0x80)
    {
      first = 0;
      len = 1;
    }
  else if (c < 0x800)
    {
      first = 0xc0;
      len = 2;
    }
  else if (c < 0x10000)
    {
      first = 0xe0;
      len = 3;
    }
   else if (c < 0x200000)
    {
      first = 0xf0;
      len = 4;
    }
  else if (c < 0x4000000)
    {
      first = 0xf8;
      len = 5;
    }
  else
    {
      first = 0xfc;
      len = 6;
    }

  if (outbuf)
    {
      for (i = len - 1; i > 0; --i)
    {
      outbuf[i] = (c & 0x3f) | 0x80;
      c >>= 6;
    }
      outbuf[0] = c | first;
    }

  return len;
}

/**
 * dap_utf16_to_utf8:
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
 * Convert a string from UTF-16 to UTF-8. The result will be
 * terminated with a 0 byte.
 *
 * Note that the input is expected to be already in native endianness,
 * an initial byte-order-mark character is not handled specially.
 * g_convert() can be used to convert a byte buffer of UTF-16 data of
 * ambiguous endianness.
 *
 * Further note that this function does not validate the result
 * string; it may e.g. include embedded NUL characters. The only
 * validation done by this function is to ensure that the input can
 * be correctly interpreted as UTF-16, i.e. it doesn't contain
 * unpaired surrogates or partial character sequences.
 *
 * Returns: (transfer full): a pointer to a newly allocated UTF-8 string.
 *     This value must be freed with g_free(). If an error occurs,
 *     %NULL will be returned and @error set.
 **/
char* dap_utf16_to_utf8(const unichar2 *str, long len, long *items_read, long *items_written)
{
    const unichar2 *in;
    char *out;
    char *result = NULL;
    int n_bytes;
    unichar high_surrogate;

    dap_return_val_if_fail(str != NULL, NULL);

    n_bytes = 0;
    in = str;
    high_surrogate = 0;
    while((len < 0 || in - str < len) && *in)
    {
        unichar2 c = *in;
        unichar wc;

        if(c >= 0xdc00 && c < 0xe000) /* low surrogate */
        {
            if(high_surrogate)
            {
                wc = SURROGATE_VALUE(high_surrogate, c);
                high_surrogate = 0;
            }
            else
            {
                // Invalid sequence in conversion input
                goto err_out;
            }
        }
        else
        {
            if(high_surrogate)
            {
                // Invalid sequence in conversion input
                goto err_out;
            }

            if(c >= 0xd800 && c < 0xdc00) // high surrogate
                    {
                high_surrogate = c;
                goto next1;
            }
            else
                wc = c;
        }

        /********** DIFFERENT for UTF8/UCS4 **********/
        n_bytes += UTF8_LENGTH(wc);

        next1:
        in++;
    }

    if(high_surrogate && !items_read)
            {
        // Partial character sequence at end of input
        goto err_out;
    }

    /* At this point, everything is valid, and we just need to convert
     */
    /********** DIFFERENT for UTF8/UCS4 **********/
    result = DAP_NEW_SIZE(char, n_bytes + 1);
    if(result == NULL)
        goto err_out;

    high_surrogate = 0;
    out = result;
    in = str;
    while(out < result + n_bytes)
    {
        unichar2 c = *in;
        unichar wc;

        if(c >= 0xdc00 && c < 0xe000) /* low surrogate */
        {
            wc = SURROGATE_VALUE(high_surrogate, c);
            high_surrogate = 0;
        }
        else if(c >= 0xd800 && c < 0xdc00) /* high surrogate */
        {
            high_surrogate = c;
            goto next2;
        }
        else
            wc = c;

        /********** DIFFERENT for UTF8/UCS4 **********/
        out += dap_unichar_to_utf8(wc, out);

        next2:
        in++;
    }

    /********** DIFFERENT for UTF8/UCS4 **********/
    *out = '\0';

    if(items_written)
        /********** DIFFERENT for UTF8/UCS4 **********/
        *items_written = out - result;

    err_out:
    if(items_read)
        *items_read = in - str;

    return result;
}
