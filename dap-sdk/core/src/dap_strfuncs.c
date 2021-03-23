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
 * @brief dap_utoa128
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
size_t dap_strlen(const char *a_str)
{
    size_t l_length = 0;

    if(a_str) {
        l_length = strlen(a_str);
    }
    return l_length;
}

/**
 * dap_strcmp:
 * @a_str1: (nullable): the string
 * @a_str2: (nullable): the string
 *
 * Compare a_str1 and a_str2
 */
int dap_strcmp(const char *a_str1, const char *a_str2)
{
    if(a_str1 && a_str2) {
        return strcmp(a_str1, a_str2);
    }
    return -1;
}

/**
 * dap_strcmp:
 * @a_str1: (nullable): the string
 * @a_str2: (nullable): the string
 *
 * Compare a_n characters of a_str1 and a_str2
 */
int dap_strncmp(const char *a_str1, const char *a_str2, size_t a_n)
{
    if(a_str1 && a_str2) {
        return strncmp(a_str1, a_str2, a_n);
    }
    return -1;
}

/**
 * dap_strdup:
 * @a_str: (nullable): the string to duplicate
 *
 * Duplicates a string. If @a_str is %NULL it returns %NULL.
 * The returned string should be freed
 * when no longer needed.
 *
 * Returns: a newly-allocated copy of @a_str
 */
char* dap_strdup(const char *a_str)
{
    char *l_new_str;

    if(a_str){
        size_t l_length = (size_t) (strlen(a_str) + 1);
        if(l_length){
            l_new_str = DAP_NEW_SIZE(char, l_length);
	    if(l_new_str)
        	memcpy(l_new_str, a_str, l_length);
        }else
            l_new_str = NULL;
    }
    else
        l_new_str = NULL;

    return l_new_str;
}

/**
 * dap_strdup_vprintf:
 * @a_format: a standard printf() format string, but notice
 *     [string precision pitfalls][string-precision]
 * @a_args: the list of parameters to insert into the format string
 *
 * Similar to the standard C vsprintf() function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed with DAP_DELETE()
 * when no longer needed.
 *
 * Returns: a newly-allocated string holding the result
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
 * dap_strdup_printf:
 * @a_format: a standard printf() format string
 *
 * Similar to the standard C sprintf() function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed with DAP_DELETE()
 * when no longer needed.
 *
 * Returns: a newly-allocated string holding the result
 */
char* dap_strdup_printf(const char *a_format, ...)
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

/**
 * dap_strdupv:
 * @a_str_array: (nullable): a %NULL-terminated array of strings
 *
 * Copies %NULL-terminated array of strings. The copy is a deep copy;
 * the new array should be freed by first freeing each string, then
 * the array itself. g_strfreev() does this for you. If called
 * on a %NULL value, g_strdupv() simply returns %NULL.
 *
 * Returns: (nullable): a new %NULL-terminated array of strings.
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
 * dap_strfreev:
 * @a_str_array: (nullable): a %NULL-terminated array of strings to free
 *
 * Frees a %NULL-terminated array of strings, as well as each
 * string it contains.
 *
 * If @a_str_array is %NULL, this function simply returns.
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
 * dap_strchug:
 * @a_string: a string to remove the leading whitespace from
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
 * dap_strup:
 * @a_str: a string
 * @a_len: length of @a_str in bytes, or -1 if @a_str is nul-terminated
 *
 * Converts all lower case ASCII letters to upper case ASCII letters.
 *
 * Returns: a newly allocated string, with all the lower case
 *     characters in @a_str converted to upper case
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
 * dap_strdown:
 * @a_str: a string
 * @a_len: length of @a_str in bytes, or -1 if @a_str is nul-terminated
 *
 * Converts all upper case ASCII letters to lower case ASCII letters.
 *
 * Returns: a newly-allocated string, with all the upper case
 *     characters in @a_str converted to lower case
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
 * dap_strreverse:
 * @a_string: the string to reverse
 *
 * Reverses all of the bytes in a string. For example,
 * `dap_strreverse("abcdef")` will result in "fedcba".
 *
 * Note that g_strreverse() doesn't work on UTF-8 strings
 * containing multibyte characters.
 *
 * Returns: the same pointer passed in as @a_string
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

