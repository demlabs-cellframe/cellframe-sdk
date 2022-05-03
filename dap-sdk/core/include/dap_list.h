/*
 * Doubly-Linked Lists — linked lists that can be iterated over in both directions
 *
 * Nano API for Simple Linked List - by BadAss SysMan
 * Attention!!! No internaly locking is performed !
 */

#ifndef __DAP_LIST_H__
#define __DAP_LIST_H__

#include    <errno.h>                                                       /* <errno> codes */
#include    "dap_common.h"                                                  /* DAP_ALLOC, DAP_FREE */


#ifdef __cplusplus
extern "C" {
#endif


typedef struct __dap_slist_elm__ {
    struct __dap_slist_elm__ *flink;                                        /* Forward link */
                    void    *data;                                          /* Pointer to carried data area */
                    size_t     datasz;                                      /* A data portion size */
} dap_slist_elm_t;

typedef struct __dap_slist__ {
            dap_slist_elm_t   *head,                                        /* An address of first element */
                            *tail;                                          /* An address of last element */
                    int     nr;                                             /* A number of elements in list  */
} dap_slist_t;

/**
 * @brief dap_slist_add2tail Insert new eleemnt at the tail of the list
 *  Internaly allocate a memory for a new SLIST's element, form it, append to the tail.
 *  Be advised that no any locking logic is used internaly. If u need to maintain a data consistency in
 *  concurrent multithreading environment - use locking provided by the u platform.
 *
 * @param a_q       An address of the SLIST context
 * @param a_data    An address of the data area
 * @param a_datasz  A size of the data area
 * @return
 *  0 - no error, new element is inserted
 *  -ENOMEM - no memory for new element
 */
static inline int    dap_slist_add2tail    ( dap_slist_t *a_q, void *a_data, int a_datasz)
{
dap_slist_elm_t *l_elm;

    if ( !(l_elm = (dap_slist_elm_t*)DAP_MALLOC(sizeof(dap_slist_elm_t))) ) /* Allocate memory for new element */
        return  -ENOMEM;

    l_elm->flink = NULL;                                                    /* This element is terminal */
    l_elm->data  = a_data;                                                  /* Store pointer to carried data */
    l_elm->datasz= a_datasz;                                                /* A size of daa metric */

    if ( a_q->tail )                                                        /* Queue is not empty ? */
        (a_q->tail)->flink = l_elm;                                         /* Correct forward link of "previous last" element
                                                                               to point to new element */

    a_q->tail = l_elm;                                                      /* Point list's tail to new element also */

    if ( !a_q->head )                                                       /* This is a first element in the list  ? */
        a_q->head = l_elm;                                                  /* point head to the new element */

    a_q->nr++;                                                              /* Adjust entries counter */

    return  0;
}

/**
 * @brief dap_slist_get4head Retrive an element from head of the simple list.
 *  Remove element from the head, release unused memory.
 *  Be advised that no any locking logic is used internaly. If u need to maintain a data consistency in
 *  concurrent multithreading environment - use locking provided by the u platform.
 *
 * @param a_q       An address of the SLIST context
 * @param a_data    A pointer to accept an address of the data area
 * @param a_datasz  A pointer to variable to accept data area size
 * @return
 *  0 - no error
 *  -ENOENT - SLIST is empty, no element
 */

static inline int    dap_slist_get4head    ( dap_slist_t *a_q, void **a_data, size_t *a_datasz)
{
dap_slist_elm_t *l_elm;

    if ( !(l_elm = a_q->head) )                                             /* Queue is empty - just return error code */
        return -ENOENT;

    if ( !(a_q->head = l_elm->flink) )                                      /* Last element in the queue ? */
        a_q->tail = NULL;                                                   /* Reset tail to NULL */

    *a_data = l_elm->data;
    *a_datasz = l_elm->datasz;

    DAP_FREE(l_elm);                                                        /* Release memory has been allocated for the queue's element */

    a_q->nr--;                                                              /* Adjust entries counter */

    return  0;
}


typedef void (*dap_callback_destroyed_t)(void* data);
typedef void (*dap_callback_t)(void* data, void* user_data);
typedef void* (*dap_callback_copy_t)(const void * src, void* data);
typedef int (*dap_callback_compare_t)(const void * a, const void * b);
typedef int (*dap_callback_compare_data_t)(const void * a, const void * b, void* user_data);

typedef struct _dap_list dap_list_t;

struct _dap_list
{
    void* data;
    dap_list_t *next;
    dap_list_t *prev;
};

/* Doubly linked lists
 */
dap_list_t* dap_list_alloc(void);
void dap_list_free(dap_list_t *list);
void dap_list_free1(dap_list_t *list);
void dap_list_free_full(dap_list_t *a_list, dap_callback_destroyed_t free_func);
dap_list_t* dap_list_append(dap_list_t *list, void* data);
dap_list_t* dap_list_prepend(dap_list_t *list, void* data);
dap_list_t* dap_list_insert(dap_list_t *list, void* data, int position);
dap_list_t* dap_list_insert_sorted(dap_list_t *list, void* data, dap_callback_compare_data_t func);
dap_list_t* dap_list_insert_sorted_with_data(dap_list_t *list, void* data, dap_callback_compare_data_t func, void* user_data);
dap_list_t* dap_list_insert_before(dap_list_t *list, dap_list_t *sibling, void* data);
dap_list_t* dap_list_concat(dap_list_t *list1, dap_list_t *list2);
dap_list_t* dap_list_remove(dap_list_t *list, const void * data);
dap_list_t* dap_list_remove_all(dap_list_t *list, const void * data);
dap_list_t* dap_list_remove_link(dap_list_t *list, dap_list_t *llink);
dap_list_t* dap_list_delete_link(dap_list_t *list, dap_list_t *link_);
dap_list_t* dap_list_reverse(dap_list_t *list);
dap_list_t* dap_list_copy(dap_list_t *list);

dap_list_t* dap_list_copy_deep(dap_list_t *list, dap_callback_copy_t func, void* user_data);

dap_list_t* dap_list_nth(dap_list_t *list, unsigned int n);
dap_list_t* dap_list_nth_prev(dap_list_t *list, unsigned int n);
dap_list_t* dap_list_find(dap_list_t *list, const void * data);
dap_list_t* dap_list_find_custom(dap_list_t *list, const void * data, dap_callback_compare_t func);
int dap_list_position(dap_list_t *list, dap_list_t *llink);
int dap_list_index(dap_list_t *list, const void * data);
dap_list_t* dap_list_last(dap_list_t *list);
dap_list_t* dap_list_first(dap_list_t *list);
unsigned int dap_list_length(dap_list_t *list);
void dap_list_foreach(dap_list_t *list, dap_callback_t func, void* user_data);
dap_list_t* dap_list_sort(dap_list_t *list, dap_callback_compare_data_t compare_func);
dap_list_t* dap_list_sort_with_data(dap_list_t *list, dap_callback_compare_data_t compare_func, void* user_data);
void* dap_list_nth_data(dap_list_t *list, unsigned int n);

#define dap_list_previous(list)	        ((list) ? (((dap_list_t *)(list))->prev) : NULL)
#define dap_list_next(list)	        ((list) ? (((dap_list_t *)(list))->next) : NULL)

#ifdef __cplusplus
}
#endif

#endif /* __DAP_LIST_H__ */
