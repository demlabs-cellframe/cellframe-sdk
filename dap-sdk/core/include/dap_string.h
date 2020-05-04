// dap_string_t is an object that handles the memory management of a C string for you.

#ifndef __DAP_STRING_H__
#define __DAP_STRING_H__

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct _dap_string dap_string_t;

struct _dap_string
{
    char *str;
    size_t len;
    size_t allocated_len;
};

dap_string_t* dap_string_new(const char *init);
dap_string_t* dap_string_new_len(const char *init, ssize_t len);
dap_string_t * dap_string_sized_new(size_t a_dfl_size);
char* dap_string_free(dap_string_t *string, bool free_segment);

bool dap_string_equal(const dap_string_t *v, const dap_string_t *v2);

unsigned int dap_string_hash(const dap_string_t *str);


dap_string_t* dap_string_assign(dap_string_t *string, const char *rval);

dap_string_t* dap_string_truncate(dap_string_t *string, size_t len);

dap_string_t* dap_string_set_size(dap_string_t *string, size_t len);

dap_string_t* dap_string_insert_len(dap_string_t *string, ssize_t pos, const char *val, ssize_t len);

dap_string_t* dap_string_append(dap_string_t *string, const char *val);

dap_string_t* dap_string_append_len(dap_string_t *string, const char *val, ssize_t len);

dap_string_t* dap_string_append_c(dap_string_t *string, char a_c);

dap_string_t* dap_string_append_unichar(dap_string_t *string, uint32_t wc);

dap_string_t* dap_string_prepend(dap_string_t *string, const char *val);

dap_string_t* dap_string_prepend_c(dap_string_t *string, char a_c);

dap_string_t* dap_string_prepend_unichar(dap_string_t *string, uint32_t wc);

dap_string_t* dap_string_prepend_len(dap_string_t *string, const char *val, ssize_t len);

dap_string_t* dap_string_insert(dap_string_t *string, ssize_t pos, const char *val);

dap_string_t* dap_string_insert_c(dap_string_t *string, ssize_t pos, char a_c);

dap_string_t* dap_string_insert_unichar(dap_string_t *string, ssize_t pos, uint32_t wc);

dap_string_t* dap_string_overwrite(dap_string_t *string, size_t pos, const char *val);

dap_string_t* dap_string_overwrite_len(dap_string_t *string, size_t pos, const char *val, ssize_t len);

dap_string_t* dap_string_erase(dap_string_t *string, ssize_t pos, ssize_t len);

void dap_string_vprintf(dap_string_t *string, const char *format, va_list args);
void dap_string_printf(dap_string_t *string, const char *format, ...);
void dap_string_append_vprintf(dap_string_t *string, const char *format, va_list args);
void dap_string_append_printf(dap_string_t *string, const char *format, ...);

/* -- optimize dap_strig_append_c --- */
#ifdef G_CAN_INLINE
static inline dap_string_t* dap_string_append_c_inline(dap_string_t *a_string, char a_c)
{
    if(a_string->len + 1 < a_string->allocated_len)
    {
        a_string->str[a_string->len++] = a_c;
        a_string->str[a_string->len] = 0;
    }
    else
    dap_string_insert_c(a_string, -1, a_c);
    return a_string;
}
#define dap_string_append_c(a_string,a_c)       dap_string_append_c_inline (a_string, a_c)
#endif /* G_CAN_INLINE */

dap_string_t *dap_string_down(dap_string_t *string);

dap_string_t *dap_string_up(dap_string_t *string);

#ifndef G_DISABLE_DEPRECATED
#define  dap_string_sprintf  dap_string_printf
#define  dap_string_sprintfa dap_string_append_printf
#endif

#endif /* __DAP_STRING_H__ */
