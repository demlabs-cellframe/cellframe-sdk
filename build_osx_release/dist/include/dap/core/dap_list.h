/*
 * Doubly-Linked Lists — linked lists that can be iterated over in both directions
 *
 * Nano API for Simple linked list - by BadAss SysMan
 * Attention!!! No internaly locking is performed !
 *
 *  MODIFICATION HISTORY:
 *      17-MAY-2022 RRL Added description for the SLIST's routines;
 *                      renaming arguments to be relevant to the Dem Labs coding style. :-)
 *
 */

#ifndef __DAP_LIST_H__
#define __DAP_LIST_H__

#include    <errno.h>                                                       /* <errno> codes */

#include    "dap_common.h"                                                  /* DAP_ALLOC, DAP_FREE */
#include "utlist.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __dap_list__ {
    void *data;
    struct __dap_list__ *next, *prev;
} dap_list_t;

typedef void (*dap_callback_destroyed_t)(void *a_free_func);
typedef int (*dap_callback_compare_t)(dap_list_t *a_list1, dap_list_t *a_list2);
typedef void *(*dap_callback_copy_t)(const void *a_data, void *a_user_arg);

/* Doubly linked lists
 */
void dap_list_free(dap_list_t*);
void dap_list_free_full(dap_list_t*, dap_callback_destroyed_t);
dap_list_t* dap_list_append(dap_list_t*, void*);
dap_list_t* dap_list_prepend(dap_list_t*, void*);
dap_list_t* dap_list_insert(dap_list_t*, void*, uint64_t);
dap_list_t* dap_list_insert_sorted(dap_list_t*, void*, dap_callback_compare_t);
dap_list_t* dap_list_concat(dap_list_t*, dap_list_t*);
dap_list_t* dap_list_remove(dap_list_t*, const void*);
dap_list_t* dap_list_remove_all(dap_list_t*, const void*);
dap_list_t* dap_list_remove_link(dap_list_t*, dap_list_t*);
dap_list_t* dap_list_delete_link(dap_list_t*, dap_list_t*);
dap_list_t* dap_list_copy(dap_list_t*);

dap_list_t* dap_list_copy_deep(dap_list_t*, dap_callback_copy_t, void*);

dap_list_t* dap_list_nth(dap_list_t*, uint64_t);
/**
 * dap_list_nth_prev:
 * @list: a DapList
 * @n: the position of the element, counting from 0
 *
 * Gets the element @n places before @list.
 *
 * Returns: the element, or %NULL if the position is
 *     off the end of the DapList
 */
DAP_STATIC_INLINE dap_list_t *dap_list_nth_prev(dap_list_t *a_list, uint64_t n)
{
    return dap_list_nth(a_list, n)->prev;
}

/**
 * dap_list_nth_data:
 * @list: a DapList, this must point to the top of the list
 * @n: the position of the element
 *
 * Gets the data of the element at the given position.
 *
 * Returns: the element's data, or %NULL if the position
 *     is off the end of the DapList
 */
DAP_STATIC_INLINE void *dap_list_nth_data(dap_list_t *a_list, uint64_t n)
{
    return dap_list_nth(a_list, n)->data;
}
dap_list_t* dap_list_find(dap_list_t*, const void*, dap_callback_compare_t);
int dap_list_position(dap_list_t*, dap_list_t*);
int dap_list_index(dap_list_t*, const void*);
dap_list_t* dap_list_last(dap_list_t*);
dap_list_t* dap_list_first(dap_list_t*);
uint64_t dap_list_length(dap_list_t*);
dap_list_t* dap_list_sort(dap_list_t*, dap_callback_compare_t);
dap_list_t *dap_list_shuffle(dap_list_t *a_list);

#define dap_list_prev(list) ((dap_list_t*)(list))->prev
#define dap_list_next(list)	((dap_list_t*)(list))->next

#ifdef __cplusplus
}
#endif

#endif /* __DAP_LIST_H__ */
