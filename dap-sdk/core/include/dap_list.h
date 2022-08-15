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

#define     $DAP_SLIST_INITALIZER {NULL, NULL, 0}

/*
 *  DESCRIPTION: Form and add new element into the list with data.
 *
 *  INPUTS:
 *      a_slist:    An address of the SLIST context
 *      a_data:     An address of the data block to be carried as an element of the list
 *      a_datasz:   A size of the data block
 *
 *  OUTPUTS:
 *      NONE
 *
 *  RETURNS:
 *      0       - SUCCESS
 *      -ENOMEM - Cannot add new element
 */

DAP_STATIC_INLINE int dap_slist_add2tail(dap_slist_t *a_slist, void *a_data, int a_datasz)
{
dap_slist_elm_t *l_elm;

    if ( !(l_elm = (dap_slist_elm_t*)DAP_MALLOC(sizeof(dap_slist_elm_t))) ) /* Allocate memory for new element */
        return  -ENOMEM;

    l_elm->flink = NULL;                                                    /* This element is terminal */
    l_elm->data  = a_data;                                                  /* Store pointer to carried data */
    l_elm->datasz= a_datasz;                                                /* A size of daa metric */

    if ( a_slist->tail )                                                    /* Queue is not empty ? */
        (a_slist->tail)->flink = l_elm;                                     /* Correct forward link of "previous last" element
                                                                               to point to new element */

    a_slist->tail = l_elm;                                                  /* Point list's tail to new element also */

    if ( !a_slist->head )                                                   /* This is a first element in the list  ? */
        a_slist->head = l_elm;                                              /* point head to the new element */

    a_slist->nr++;                                                          /* Adjust entries counter */
    return  0;
}


/*
 *  DESCRIPTION: Get the data block has been carried by SLIST's element from the head of the list.
 *
 *  INPUTS:
 *      a_slist:    An address of the SLIST context
 *
 *  OUTPUTS:
 *      a_data:     An address of the data block, by reference
 *      a_datasz:   A size of the data block, by reference
 *
 *  RETURNS:
 *      0       - SUCCESS
 *      -ENOENT - List is empty
 */

DAP_STATIC_INLINE int dap_slist_get4head(dap_slist_t *a_slist, void **a_data, size_t *a_datasz)
{
dap_slist_elm_t *l_elm;

    if ( !(l_elm = a_slist->head) )                                         /* Queue is empty - just return error code */
        return -ENOENT;

    if ( !(a_slist->head = l_elm->flink) )                                  /* Last element in the queue ? */
        a_slist->tail = NULL;                                               /* Reset tail to NULL */

    a_slist->nr--;                                                          /* Adjust entries counter */

    if (a_data)
        *a_data = l_elm->data;

    if ( a_datasz )
        *a_datasz = l_elm->datasz;

    DAP_FREE(l_elm);                                                        /* Release memory has been allocated for the queue's element */

    return  0;
}

typedef void (*dap_callback_destroyed_t)(void* data);
typedef void (*dap_callback_t)(void* data, void* user_data);
typedef void* (*dap_callback_copy_t)(const void * src, void* data);
typedef int (*dap_callback_compare_t)(const void * a, const void * b);
typedef int (*dap_callback_compare_data_t)(const void * a, const void * b, void* user_data);

/*typedef struct _dap_list dap_list_t;*/

typedef struct __dap_list__
{
    void* data;
    struct __dap_list__* next, * prev;
}dap_list_t;

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
