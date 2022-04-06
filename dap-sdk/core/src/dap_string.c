// dap_string_t is an object that handles the memory management of a C string for you.

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"

#define MY_MAXSIZE ((size_t)-1)

static inline size_t nearest_power(size_t a_base, size_t a_num)
{
    if(a_num > MY_MAXSIZE / 2) {
        return MY_MAXSIZE;
    }
    else {
        size_t l_n = a_base;

        while(l_n < a_num)
            l_n <<= 1;

        return l_n;
    }
}

static void dap_string_maybe_expand(dap_string_t *a_string, size_t a_len)
{
size_t  l_len;
void    *l_str;

    if ( !(a_string->len + a_len >= a_string->allocated_len) )              /* Is there free space in the current area */
        return;                                                             /* Nothing to do - just return */

    l_len = nearest_power(1, a_string->len + a_len + 1);                    /* Compute a size of the new memory area */
    l_str = DAP_REALLOC(a_string->str, l_len );                             /* Try to realloc" */

    if ( !l_str )                                                           /* In case of error - don't touch an original descriptor */
        return;

    a_string->str = l_str;                                                  /* Update <string> descriptor with actual data */
    a_string->allocated_len = l_len;

}

/**
 * dap_string_sized_new:
 * @a_a_dfl_size: the default size of the space allocated to
 *     hold the string
 *
 * Creates a new #dap_string_t, with enough space for @a_a_dfl_size
 * bytes. This is useful if you are going to add a lot of
 * text to the string and don't want it to be reallocated
 * too often.
 *
 * Returns: the new #dap_string_t
 */
dap_string_t * dap_string_sized_new(size_t a_dfl_size)
{
    dap_string_t *l_string = DAP_NEW(dap_string_t);

    l_string->allocated_len = 0;
    l_string->len = 0;
    l_string->str = NULL;

    dap_string_maybe_expand(l_string, max(a_dfl_size, 2));
    l_string->str[0] = 0;

    return l_string;
}

/**
 * dap_string_new:
 * @a_a_init: (nullable): the initial text to copy into the string, or %NULL to
 * start with an empty string
 *
 * Creates a new #dap_string_t, initialized with the given string.
 *
 * Returns: the new #dap_string_t
 */
dap_string_t* dap_string_new(const char *a_init)
{
    dap_string_t *l_string;

    if(a_init == NULL || *a_init == '\0')
        l_string = dap_string_sized_new(2);
    else
    {
        int len;

        len = strlen(a_init);
        l_string = dap_string_sized_new(len + 2);

        dap_string_append_len(l_string, a_init, len);
    }

    return l_string;
}

/**
 * dap_string_new_len:
 * @a_init: initial contents of the string
 * @a_len: length of @a_init to use
 *
 * Creates a new #dap_string_t with @a_len bytes of the @a_init buffer.
 * Because a length is provided, @a_init need not be nul-terminated,
 * and can contain embedded nul bytes.
 *
 * Since this function does not stop at nul bytes, it is the caller's
 * responsibility to ensure that @a_init has at least @a_len addressable
 * bytes.
 *
 * Returns: a new #dap_string_t
 */
dap_string_t* dap_string_new_len(const char *a_init, ssize_t a_len)
{
    dap_string_t *l_string;

    if(a_len < 0)
        return dap_string_new(a_init);
    else
    {
        l_string = dap_string_sized_new(a_len);

        if(a_init)
            dap_string_append_len(l_string, a_init, a_len);

        return l_string;
    }
}

/**
 * dap_string_free:
 * @a_string: (transfer full): a #dap_string_t
 * @a_free_segment: if %true, the actual character data is freed as well
 *
 * Frees the memory allocated for the #dap_string_t.
 * If @a_free_segment is %true it also frees the character data.  If
 * it's %false, the caller gains ownership of the buffer and must
 * free it after use with dap_free().
 *
 * Returns: (nullable): the character data of @a_string
 *          (i.e. %NULL if @a_free_segment is %true)
 */
char* dap_string_free(dap_string_t *a_string, bool a_free_segment)
{
    char *l_segment;

    dap_return_val_if_fail(a_string != NULL, NULL);

    if(a_free_segment)
    {
        DAP_DELETE(a_string->str);
        l_segment = NULL;
    }
    else
        l_segment = a_string->str;

    DAP_DELETE(a_string);

    return l_segment;
}

/**
 * dap_string_equal:
 * @a_v: a #dap_string_t
 * @a_v2: another #dap_string_t
 *
 * Compares two strings for equality, returning %true if they are equal.
 * For use with #GHashTable.
 *
 * Returns: %true if the strings are the same length and contain the
 *     same bytes
 */
bool dap_string_equal(const dap_string_t *a_v, const dap_string_t *a_v2)
{
    char *p, *q;
    dap_string_t *l_string1 = (dap_string_t *) a_v;
    dap_string_t *l_string2 = (dap_string_t *) a_v2;
    size_t i = l_string1->len;

    if(i != l_string2->len)
        return false;

    p = l_string1->str;
    q = l_string2->str;
    while(i)
    {
        if(*p != *q)
            return false;
        p++;
        q++;
        i--;
    }
    return true;
}

/**
 * dap_string_hash:
 * @a_str: a string to hash
 *
 * Creates a hash code for @a_str
 *
 * Returns: hash code for @a_str
 */
unsigned int dap_string_hash(const dap_string_t *a_str)
{
    const char *p = a_str->str;
    size_t n = a_str->len;
    unsigned int h = 0;

    /* 31 bit hash function */
    while(n--)
    {
        h = (h << 5) - h + *p;
        p++;
    }

    return h;
}

/**
 * dap_string_assign:
 * @a_string: the destination #dap_string_t. Its current contents
 *          are destroyed.
 * @a_rval: the string to copy into @a_string
 *
 * Copies the bytes from a string into a #dap_string_t,
 * destroying any previous contents. It is rather like
 * the standard strcpy() function, except that you do not
 * have to worry about having enough space to copy the string.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_assign(dap_string_t *a_string, const char *a_rval)
{
    dap_return_val_if_fail(a_string != NULL, NULL);
    dap_return_val_if_fail(a_rval != NULL, a_string);

    /* Make sure assigning to itself doesn't corrupt the string. */
    if(a_string->str != a_rval)
            {
        /* Assigning from substring should be ok, since
         * dap_string_truncate() does not reallocate.
         */
        dap_string_truncate(a_string, 0);
        dap_string_append(a_string, a_rval);
    }

    return a_string;
}

/**
 * dap_string_truncate:
 * @a_string: a #dap_string_t
 * @a_len: the new size of @a_string
 *
 * Cuts off the end of the dap_string_t, leaving the first @a_len bytes.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_truncate(dap_string_t *string, size_t len)
{
    dap_return_val_if_fail(string != NULL, NULL);

    string->len = min(len, string->len);
    string->str[string->len] = 0;

    return string;
}

/**
 * dap_string_set_size:
 * @a_string: a #dap_string_t
 * @a_len: the new length
 *
 * Sets the length of a #dap_string_t. If the length is less than
 * the current length, the string will be truncated. If the
 * length is greater than the current length, the contents
 * of the newly added area are undefined. (However, as
 * always, string->str[string->len] will be a nul byte.)
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_set_size(dap_string_t *string, size_t len)
{
    dap_return_val_if_fail(string != NULL, NULL);

    if(len >= string->allocated_len)
        dap_string_maybe_expand(string, len - string->len);

    string->len = len;
    string->str[len] = 0;

    return string;
}

/**
 * dap_string_insert_len:
 * @a_string: a #dap_string_t
 * @a_pos: position in @a_string where insertion should
 *       happen, or -1 for at the end
 * @a_val: bytes to insert
 * @a_len: number of bytes of @a_val to insert
 *
 * Inserts @a_len bytes of @a_val into @a_string at @a_pos.
 * Because @a_len is provided, @a_val may contain embedded
 * nuls and need not be nul-terminated. If @a_pos is -1,
 * bytes are inserted at the end of the string.
 *
 * Since this function does not stop at nul bytes, it is
 * the caller's responsibility to ensure that @a_val has at
 * least @a_len addressable bytes.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_insert_len(dap_string_t *string, ssize_t pos, const char *val, ssize_t len)
{
    dap_return_val_if_fail(string != NULL, NULL);
    dap_return_val_if_fail(len == 0 || val != NULL, string);

    if(len == 0)
        return string;

    if(len < 0)
        len = strlen(val);

    if(pos < 0)
        pos = string->len;
    else
        dap_return_val_if_fail((size_t )pos <= string->len, string);

    /* Check whether val represents a substring of string.
     * This test probably violates chapter and verse of the C standards,
     * since ">=" and "<=" are only valid when val really is a substring.
     * In practice, it will work on modern archs.
     */
    if(val >= string->str && val <= string->str + string->len)
            {
        size_t offset = val - string->str;
        size_t precount = 0;

        dap_string_maybe_expand(string, len);
        val = string->str + offset;
        /* At this point, val is valid again.  */

        /* Open up space where we are going to insert.  */
        if((size_t) pos < string->len)
            memmove(string->str + pos + len, string->str + pos, string->len - pos);

        /* Move the source part before the gap, if any.  */
        if(offset < (size_t) pos) {
            precount = min(len, pos - (ssize_t )offset);
            memcpy(string->str + pos, val, precount);
        }

        /* Move the source part after the gap, if any.  */
        if((size_t) len > precount)
            memcpy(string->str + pos + precount,
                    val + /* Already moved: */precount + /* Space opened up: */len,
                    len - precount);
    }
    else
    {
        dap_string_maybe_expand(string, len);

        /* If we aren't appending at the end, move a hunk
         * of the old string to the end, opening up space
         */
        if((size_t) pos < string->len)
            memmove(string->str + pos + len, string->str + pos, string->len - pos);

        /* insert the new string */
        if(len == 1)
            string->str[pos] = *val;
        else
            memcpy(string->str + pos, val, len);
    }

    string->len += len;

    string->str[string->len] = 0;

    return string;
}

/**
 * dap_string_append:
 * @a_string: a #dap_string_t
 * @a_val: the string to append onto the end of @a_string
 *
 * Adds a string onto the end of a #dap_string_t, expanding
 * it if necessary.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_append(dap_string_t *string, const char *val)
{
    return dap_string_insert_len(string, -1, val, -1);
}

/**
 * dap_string_append_len:
 * @a_string: a #dap_string_t
 * @a_val: bytes to append
 * @a_len: number of bytes of @a_val to use
 *
 * Appends @a_len bytes of @a_val to @a_string. Because @a_len is
 * provided, @a_val may contain embedded nuls and need not
 * be nul-terminated.
 *
 * Since this function does not stop at nul bytes, it is
 * the caller's responsibility to ensure that @a_val has at
 * least @a_len addressable bytes.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_append_len(dap_string_t *string, const char *val, ssize_t len)
{
    return dap_string_insert_len(string, -1, val, len);
}

/**
 * dap_string_append_c:
 * @a_string: a #dap_string_t
 * @a_c: the byte to append onto the end of @a_string
 *
 * Adds a byte onto the end of a #dap_string_t, expanding
 * it if necessary.
 *
 * Returns: (transfer none): @a_string
 */
#undef dap_string_append_c
dap_string_t* dap_string_append_c(dap_string_t *string, char c)
{
    dap_return_val_if_fail(string != NULL, NULL);

    return dap_string_insert_c(string, -1, c);
}

/**
 * dap_string_append_unichar:
 * @a_string: a #dap_string_t
 * @a_wc: a Unicode character
 *
 * Converts a Unicode character into UTF-8, and appends it
 * to the string.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_append_unichar(dap_string_t *string, uint32_t wc)
{
    dap_return_val_if_fail(string != NULL, NULL);

    return dap_string_insert_unichar(string, -1, wc);
}

/**
 * dap_string_prepend:
 * @a_string: a #dap_string_t
 * @a_val: the string to prepend on the start of @a_string
 *
 * Adds a string on to the start of a #dap_string_t,
 * expanding it if necessary.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_prepend(dap_string_t *string, const char *val)
{
    return dap_string_insert_len(string, 0, val, -1);
}

/**
 * dap_string_prepend_len:
 * @a_string: a #dap_string_t
 * @a_val: bytes to prepend
 * @a_len: number of bytes in @a_val to prepend
 *
 * Prepends @a_len bytes of @a_val to @a_string.
 * Because @a_len is provided, @a_val may contain
 * embedded nuls and need not be nul-terminated.
 *
 * Since this function does not stop at nul bytes,
 * it is the caller's responsibility to ensure that
 * @a_val has at least @a_len addressable bytes.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_prepend_len(dap_string_t *string, const char *val, ssize_t len)
{
    return dap_string_insert_len(string, 0, val, len);
}

/**
 * dap_string_prepend_c:
 * @a_string: a #dap_string_t
 * @a_c: the byte to prepend on the start of the #dap_string_t
 *
 * Adds a byte onto the start of a #dap_string_t,
 * expanding it if necessary.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_prepend_c(dap_string_t *string, char c)
{
    dap_return_val_if_fail(string != NULL, NULL);

    return dap_string_insert_c(string, 0, c);
}

/**
 * dap_string_prepend_unichar:
 * @a_string: a #dap_string_t
 * @a_wc: a Unicode character
 *
 * Converts a Unicode character into UTF-8, and prepends it
 * to the string.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_prepend_unichar(dap_string_t *string, uint32_t wc)
{
    dap_return_val_if_fail(string != NULL, NULL);

    return dap_string_insert_unichar(string, 0, wc);
}

/**
 * dap_string_insert:
 * @a_string: a #dap_string_t
 * @a_pos: the position to insert the copy of the string
 * @a_val: the string to insert
 *
 * Inserts a copy of a string into a #dap_string_t,
 * expanding it if necessary.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_insert(dap_string_t *string, ssize_t pos, const char *val)
{
    return dap_string_insert_len(string, pos, val, -1);
}

/**
 * dap_string_insert_c:
 * @a_string: a #dap_string_t
 * @a_pos: the position to insert the byte
 * @a_c: the byte to insert
 *
 * Inserts a byte into a #dap_string_t, expanding it if necessary.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_insert_c(dap_string_t *string, ssize_t pos, char c)
{
    dap_return_val_if_fail(string != NULL, NULL);

    dap_string_maybe_expand(string, 1);

    if(pos < 0)
        pos = string->len;
    else
        dap_return_val_if_fail((size_t )pos <= string->len, string);

    /* If not just an append, move the old stuff */
    if((size_t) pos < string->len)
        memmove(string->str + pos + 1, string->str + pos, string->len - pos);

    string->str[pos] = c;

    string->len += 1;

    string->str[string->len] = 0;

    return string;
}

/**
 * dap_string_insert_unichar:
 * @a_string: a #dap_string_t
 * @a_pos: the position at which to insert character, or -1
 *     to append at the end of the string
 * @a_wc: a Unicode character
 *
 * Converts a Unicode character into UTF-8, and insert it
 * into the string at the given position.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_insert_unichar(dap_string_t *string, ssize_t pos, uint32_t wc)
{
    int charlen, first, i;
    char *dest;

    dap_return_val_if_fail(string != NULL, NULL);

    /* Code copied from dap_unichar_to_utf() */
    if(wc < 0x80)
            {
        first = 0;
        charlen = 1;
    }
    else if(wc < 0x800)
            {
        first = 0xc0;
        charlen = 2;
    }
    else if(wc < 0x10000)
            {
        first = 0xe0;
        charlen = 3;
    }
    else if(wc < 0x200000)
            {
        first = 0xf0;
        charlen = 4;
    }
    else if(wc < 0x4000000)
            {
        first = 0xf8;
        charlen = 5;
    }
    else
    {
        first = 0xfc;
        charlen = 6;
    }
    /* End of copied code */

    dap_string_maybe_expand(string, charlen);

    if(pos < 0)
        pos = string->len;
    else
        dap_return_val_if_fail((size_t )pos <= string->len, string);

    /* If not just an append, move the old stuff */
    if((size_t) pos < string->len)
        memmove(string->str + pos + charlen, string->str + pos, string->len - pos);

    dest = string->str + pos;
    /* Code copied from dap_unichar_to_utf() */
    for(i = charlen - 1; i > 0; --i)
            {
        dest[i] = (wc & 0x3f) | 0x80;
        wc >>= 6;
    }
    dest[0] = wc | first;
    /* End of copied code */

    string->len += charlen;

    string->str[string->len] = 0;

    return string;
}

/**
 * dap_string_overwrite:
 * @a_string: a #dap_string_t
 * @a_pos: the position at which to start overwriting
 * @a_val: the string that will overwrite the @a_string starting at @a_pos
 *
 * Overwrites part of a string, lengthening it if necessary.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_overwrite(dap_string_t *string, size_t pos, const char *val)
{
    dap_return_val_if_fail(val != NULL, string);
    return dap_string_overwrite_len(string, pos, val, strlen(val));
}

/**
 * dap_string_overwrite_len:
 * @a_string: a #dap_string_t
 * @a_pos: the position at which to start overwriting
 * @a_val: the string that will overwrite the @a_string starting at @a_pos
 * @a_len: the number of bytes to write from @a_val
 *
 * Overwrites part of a string, lengthening it if necessary.
 * This function will work with embedded nuls.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_overwrite_len(dap_string_t *string, size_t pos, const char *val, ssize_t len)
{
    size_t end;

    dap_return_val_if_fail(string != NULL, NULL);

    if(!len)
        return string;

    dap_return_val_if_fail(val != NULL, string);
    dap_return_val_if_fail(pos <= string->len, string);

    if(len < 0)
        len = strlen(val);

    end = pos + len;

    if(end > string->len)
        dap_string_maybe_expand(string, end - string->len);

    memcpy(string->str + pos, val, len);

    if(end > string->len)
            {
        string->str[end] = '\0';
        string->len = end;
    }

    return string;
}

/**
 * dap_string_erase:
 * @a_string: a #dap_string_t
 * @a_pos: the position of the content to remove
 * @a_len: the number of bytes to remove, or -1 to remove all
 *       following bytes
 *
 * Removes @a_len bytes from a #dap_string_t, starting at position @a_pos.
 * The rest of the #dap_string_t is shifted down to fill the gap.
 *
 * Returns: (transfer none): @a_string
 */
dap_string_t* dap_string_erase(dap_string_t *string, ssize_t pos, ssize_t len)
{
    dap_return_val_if_fail(string != NULL, NULL);
    dap_return_val_if_fail(pos >= 0, string);
    dap_return_val_if_fail((size_t )pos <= string->len, string);

    if(len < 0)
        len = string->len - pos;
    else
    {
        dap_return_val_if_fail((size_t )(pos + len) <= string->len, string);

        if((size_t) (pos + len) < string->len)
            memmove(string->str + pos, string->str + pos + len, string->len - (pos + len));
    }

    string->len -= len;

    string->str[string->len] = 0;

    return string;
}

/**
 * dap_string_down:
 * @a_string: a #dap_string_t
 *
 * Converts a #dap_string_t to lowercase.
 *
 * Returns: (transfer none): the #dap_string_t
 *
 * Deprecated:2.2: This function uses the locale-specific
 *     tolower() function, which is almost never the right thing.
 *     Use dap_string_ascii_down() or dap_utf8_strdown() instead.
 */
dap_string_t* dap_string_down(dap_string_t *string)
{
    uint8_t *s;
    long n;

    dap_return_val_if_fail(string != NULL, NULL);

    n = string->len;
    s = (uint8_t *) string->str;

    while(n)
    {
        if(isupper(*s))
            *s = tolower(*s);
        s++;
        n--;
    }

    return string;
}

/**
 * dap_string_up:
 * @a_string: a #dap_string_t
 *
 * Converts a #dap_string_t to uppercase.
 *
 * Returns: (transfer none): @a_string
 *
 * Deprecated:2.2: This function uses the locale-specific
 *     toupper() function, which is almost never the right thing.
 *     Use dap_string_ascii_up() or dap_utf8_strup() instead.
 */
dap_string_t* dap_string_up(dap_string_t *string)
{
    uint8_t *s;
    long n;

    dap_return_val_if_fail(string != NULL, NULL);

    n = string->len;
    s = (uint8_t *) string->str;

    while(n)
    {
        if(islower(*s))
            *s = toupper(*s);
        s++;
        n--;
    }

    return string;
}

/**
 * dap_string_append_vprintf:
 * @a_string: a #dap_string_t
 * @a_format: the string format. See the printf() documentation
 * @a_args: the list of arguments to insert in the output
 *
 * Appends a formatted string onto the end of a #dap_string_t.
 * This function is similar to dap_string_append_printf()
 * except that the arguments to the format string are passed
 * as a va_list.
 */
void dap_string_append_vprintf(dap_string_t *string, const char *format, va_list args)
{
    const char l_oom [] = { "Out of memory@%s!" };
    char *buf, l_buf[128];
    size_t len;

    dap_return_if_fail(string != NULL);
    dap_return_if_fail(format != NULL);

    len = dap_vasprintf(&buf, format, args);
    if ( (ssize_t)len < 0 )                    /* Got negative/error ? Return to caller */
        return;

    dap_string_maybe_expand(string, len);                                   /* Try to expand an area for new append */

    if ( (string->allocated_len - string->len) < len )                      /* Is there real space for new append ? */
        return;

    if (string->str) {
        memcpy(string->str + string->len, buf, len + 1);
        string->len += len;
    } else {
        len = dap_sprintf(l_buf, l_oom, __func__ );
        if ( (string->str = DAP_NEW_SIZE(char, sizeof(l_buf ))) )
            memcpy(string->str, l_buf , len);
    }

    DAP_DELETE(buf);
}

/**
 * dap_string_vprintf:
 * @a_string: a #dap_string_t
 * @a_format: the string format. See the printf() documentation
 * @a_args: the parameters to insert into the format string
 *
 * Writes a formatted string into a #dap_string_t.
 * This function is similar to dap_string_printf() except that
 * the arguments to the format string are passed as a va_list.
 */
void dap_string_vprintf(dap_string_t *string, const char *format, va_list args)
{
    dap_string_truncate(string, 0);
    dap_string_append_vprintf(string, format, args);
}

/*
 * dap_string_sprintf:
 * @a_string: a #dap_string_t
 * @a_format: the string format. See the sprintf() documentation
 * @...: the parameters to insert into the format string
 *
 * Writes a formatted string into a #dap_string_t.
 * This is similar to the standard sprintf() function,
 * except that the #dap_string_t buffer automatically expands
 * to contain the results. The previous contents of the
 * #dap_string_t are destroyed.
 *
 * Deprecated: This function has been renamed to dap_string_printf().
 */

/**
 * dap_string_printf:
 * @a_string: a #dap_string_t
 * @a_format: the string format. See the printf() documentation
 * @...: the parameters to insert into the format string
 *
 * Writes a formatted string into a #dap_string_t.
 * This is similar to the standard sprintf() function,
 * except that the #dap_string_t buffer automatically expands
 * to contain the results. The previous contents of the
 * #dap_string_t are destroyed.
 */
void dap_string_printf(dap_string_t *string, const char *format, ...)
{
    va_list args;

    dap_string_truncate(string, 0);

    va_start(args, format);
    dap_string_append_vprintf(string, format, args);
    va_end(args);
}

/**
 * dap_string_append_printf:
 * @a_string: a #dap_string_t
 * @a_format: the string format. See the printf() documentation
 * @...: the parameters to insert into the format string
 *
 * Appends a formatted string onto the end of a #dap_string_t.
 * This function is similar to dap_string_printf() except
 * that the text is appended to the #dap_string_t.
 */
void dap_string_append_printf(dap_string_t *string, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    dap_string_append_vprintf(string, format, args);
    va_end(args);
}
