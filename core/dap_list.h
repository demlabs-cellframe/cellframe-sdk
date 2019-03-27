/*
 * Doubly-Linked Lists — linked lists that can be iterated over in both directions
 */

#ifndef __DAP_LIST_H__
#define __DAP_LIST_H__

typedef void (*DapDestroyNotify)(void* data);
typedef void (*DapFunc)(void* data, void* user_data);
typedef void* (*DapCopyFunc)(const void * src, void* data);
typedef int (*DapCompareFunc)(const void * a, const void * b);
typedef int (*DapCompareDataFunc)(const void * a, const void * b, void* user_data);

typedef struct _DapList DapList;

struct _DapList
{
    void* data;
    DapList *next;
    DapList *prev;
};

/* Doubly linked lists
 */
DapList* dap_list_alloc(void);
void dap_list_free(DapList *list);
void dap_list_free1(DapList *list);
void dap_list_free_full(DapList *list, DapDestroyNotify free_func);
DapList* dap_list_append(DapList *list, void* data);
DapList* dap_list_prepend(DapList *list, void* data);
DapList* dap_list_insert(DapList *list, void* data, int position);
DapList* dap_list_insert_sorted(DapList *list, void* data, DapCompareFunc func);
DapList* dap_list_insert_sorted_with_data(DapList *list, void* data, DapCompareDataFunc func, void* user_data);
DapList* dap_list_insert_before(DapList *list, DapList *sibling, void* data);
DapList* dap_list_concat(DapList *list1, DapList *list2);
DapList* dap_list_remove(DapList *list, const void * data);
DapList* dap_list_remove_all(DapList *list, const void * data);
DapList* dap_list_remove_link(DapList *list, DapList *llink);
DapList* dap_list_delete_link(DapList *list, DapList *link_);
DapList* dap_list_reverse(DapList *list);
DapList* dap_list_copy(DapList *list);

DapList* dap_list_copy_deep(DapList *list, DapCopyFunc func, void* user_data);

DapList* dap_list_nth(DapList *list, unsigned int n);
DapList* dap_list_nth_prev(DapList *list, unsigned int n);
DapList* dap_list_find(DapList *list, const void * data);
DapList* dap_list_find_custom(DapList *list, const void * data, DapCompareFunc func);
int dap_list_position(DapList *list, DapList *llink);
int dap_list_index(DapList *list, const void * data);
DapList* dap_list_last(DapList *list);
DapList* dap_list_first(DapList *list);
unsigned int dap_list_length(DapList *list);
void dap_list_foreach(DapList *list, DapFunc func, void* user_data);
DapList* dap_list_sort(DapList *list, DapCompareFunc compare_func);
DapList* dap_list_sort_with_data(DapList *list, DapCompareDataFunc compare_func, void* user_data);
void* dap_list_nth_data(DapList *list, unsigned int n);

#define dap_list_previous(list)	        ((list) ? (((DapList *)(list))->prev) : NULL)
#define dap_list_next(list)	        ((list) ? (((DapList *)(list))->next) : NULL)

#endif /* __DAP_LIST_H__ */
