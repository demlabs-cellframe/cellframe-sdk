/*
 * Doubly-Linked Lists — linked lists that can be iterated over in both directions
 */

#include <stddef.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"


#define LOG_TAG "dap_list"

/**
 * dap_list_alloc:
 * Returns: a pointer to the newly-allocated DapList element
 **/
dap_list_t *dap_list_alloc_no_z(void)
{
    dap_list_t *list = DAP_NEW(dap_list_t);
    return list;
}

dap_list_t *dap_list_alloc(void)
{
    dap_list_t *list = DAP_NEW_Z(dap_list_t);
    return list;
}

/**
 * dap_list_free:
 * Frees all of the memory used by a DapList.
 * The freed elements are returned to the slice allocator.
 * If list elements contain dynamically-allocated memory, you should
 * either use dap_list_free_full() or free them manually first.
 */
void dap_list_free(dap_list_t *list)
{
    while(list)
    {
        dap_list_t *next = list->next;
        DAP_DELETE(list);
        list = next;
    }
}

/**
 * dap_list_free_1:
 *
 * Frees one DapList element.
 * It is usually used after dap_list_remove_link().
 */
void dap_list_free1(dap_list_t *list)
{
    DAP_DELETE(list);
}

/**
 * dap_list_free_full:
 * @list: a pointer to a DapList
 * @free_func: the function to be called to free each element's data
 *
 * Convenience method, which frees all the memory used by a DapList,
 * and calls @free_func on every element's data.
 */
void dap_list_free_full(dap_list_t *list, dap_callback_destroyed_t free_func)
{
    dap_list_foreach(list, (dap_callback_t) free_func, NULL);
    dap_list_free(list);
}

/**
 * dap_list_append:
 * @list: a pointer to a DapList
 * @data: the data for the new element
 *
 * Adds a new element on to the end of the list.
 *
 * Note that the return value is the new start of the list,
 * if @list was empty; make sure you store the new value.
 *
 * dap_list_append() has to traverse the entire list to find the end,
 * which is inefficient when adding multiple elements. A common idiom
 * to avoid the inefficiency is to use dap_list_prepend() and reverse
 * the list with dap_list_reverse() when all elements have been added.
 *
 * |[<!-- language="C" -->
 * // Notice that these are initialized to the empty list.
 * DapList *string_list = NULL, *number_list = NULL;
 *
 * // This is a list of strings.
 * string_list = dap_list_append (string_list, "first");
 * string_list = dap_list_append (string_list, "second");
 * 
 * // This is a list of integers.
 * number_list = dap_list_append (number_list, INT_TO_POINTER (27));
 * number_list = dap_list_append (number_list, INT_TO_POINTER (14));
 * ]|
 *
 * Returns: either @list or the new start of the DapList if @list was %NULL
 */
dap_list_t * dap_list_append(dap_list_t *list, void* data)
{
    dap_list_t *new_list;
    dap_list_t *last;

    new_list = dap_list_alloc();
    if( !new_list) // Out of memory
        return list;
    new_list->data = data;
    new_list->next = NULL;

    if(list)
    {
        last = dap_list_last(list);
        /* assert (last != NULL); */
        last->next = new_list;
        new_list->prev = last;

        return list;
    }
    else
    {
        new_list->prev = NULL;
        return new_list;
    }
}

/**
 * dap_list_prepend:
 * @list: a pointer to a DapList, this must point to the top of the list
 * @data: the data for the new element
 *
 * Prepends a new element on to the start of the list.
 *
 * Note that the return value is the new start of the list,
 * which will have changed, so make sure you store the new value. 
 *
 * |[<!-- language="C" -->
 * // Notice that it is initialized to the empty list.
 * DapList *list = NULL;
 *
 * list = dap_list_prepend (list, "last");
 * list = dap_list_prepend (list, "first");
 * ]|
 *
 * Do not use this function to prepend a new element to a different
 * element than the start of the list. Use dap_list_insert_before() instead.
 *
 * Returns: a pointer to the newly prepended element, which is the new 
 *     start of the DapList
 */
dap_list_t *dap_list_prepend(dap_list_t *list, void* data)
{
    dap_list_t *new_list;

    new_list = dap_list_alloc();
    new_list->data = data;
    new_list->next = list;

    if(list)
    {
        new_list->prev = list->prev;
        if(list->prev)
            list->prev->next = new_list;
        list->prev = new_list;
    }
    else
        new_list->prev = NULL;

    return new_list;
}

/**
 * dap_list_insert:
 * @list: a pointer to a DapList, this must point to the top of the list
 * @data: the data for the new element
 * @position: the position to insert the element. If this is 
 *     negative, or is larger than the number of elements in the 
 *     list, the new element is added on to the end of the list.
 * 
 * Inserts a new element into the list at the given position.
 *
 * Returns: the (possibly changed) start of the DapList
 */
dap_list_t *dap_list_insert(dap_list_t *list, void* data, int position)
{
    dap_list_t *new_list;
    dap_list_t *tmp_list;

    if(position < 0)
        return dap_list_append(list, data);
    else if(position == 0)
        return dap_list_prepend(list, data);

    tmp_list = dap_list_nth(list,(unsigned int) position);
    if(!tmp_list)
        return dap_list_append(list, data);

    new_list = dap_list_alloc();
    new_list->data = data;
    new_list->prev = tmp_list->prev;
    tmp_list->prev->next = new_list;
    new_list->next = tmp_list;
    tmp_list->prev = new_list;

    return list;
}

/**
 * dap_list_insert_before:
 * @list: a pointer to a DapList, this must point to the top of the list
 * @sibling: the list element before which the new element 
 *     is inserted or %NULL to insert at the end of the list
 * @data: the data for the new element
 *
 * Inserts a new element into the list before the given position.
 *
 * Returns: the (possibly changed) start of the DapList
 */
dap_list_t *dap_list_insert_before(dap_list_t *list, dap_list_t *sibling, void* data)
{
    if(!list)
    {
        list = dap_list_alloc();
        list->data = data;
        dap_return_val_if_fail(sibling == NULL, list);
        return list;
    }
    else if(sibling)
    {
        dap_list_t *node;

        node = dap_list_alloc();
        node->data = data;
        node->prev = sibling->prev;
        node->next = sibling;
        sibling->prev = node;
        if(node->prev)
        {
            node->prev->next = node;
            return list;
        }
        else
        {
            dap_return_val_if_fail(sibling == list, node);
            return node;
        }
    }
    else
    {
        dap_list_t *last;

        last = list;
        while(last->next)
            last = last->next;

        last->next = dap_list_alloc();
        last->next->data = data;
        last->next->prev = last;
        last->next->next = NULL;

        return list;
    }
}

/**
 * dap_list_concat:
 * @list1: a DapList, this must point to the top of the list
 * @list2: the DapList to add to the end of the first DapList,
 *     this must point  to the top of the list
 *
 * Adds the second DapList onto the end of the first DapList.
 * Note that the elements of the second DapList are not copied.
 * They are used directly.
 *
 * This function is for example used to move an element in the list.
 * The following example moves an element to the top of the list:
 * |[<!-- language="C" -->
 * list = dap_list_remove_link (list, llink);
 * list = dap_list_concat (llink, list);
 * ]|
 *
 * Returns: the start of the new DapList, which equals @list1 if not %NULL
 */
dap_list_t *dap_list_concat(dap_list_t *list1, dap_list_t *list2)
{
    dap_list_t *tmp_list;

    if(list2)
    {
        tmp_list = dap_list_last(list1);
        if(tmp_list)
            tmp_list->next = list2;
        else
            list1 = list2;
        list2->prev = tmp_list;
    }

    return list1;
}

static inline dap_list_t * _dap_list_remove_link(dap_list_t *list, dap_list_t *link)
{
    if(link == NULL)
        return list;

    if(link->prev)
    {
        if(link->prev->next == link)
            link->prev->next = link->next;
        else
            log_it(L_ERROR, "corrupted double-linked list detected");
    }
    if(link->next)
    {
        if(link->next->prev == link)
            link->next->prev = link->prev;
        else
            log_it(L_ERROR, "corrupted double-linked list detected");
    }

    if(link == list)
        list = list->next;

    link->next = NULL;
    link->prev = NULL;

    return list;
}

/**
 * dap_list_remove:
 * @list: a DapList, this must point to the top of the list
 * @data: the data of the element to remove
 *
 * Removes an element from a DapList.
 * If two elements contain the same data, only the first is removed.
 * If none of the elements contain the data, the DapList is unchanged.
 *
 * Returns: the (possibly changed) start of the DapList
 */
dap_list_t *dap_list_remove(dap_list_t *list, const void * data)
{
    dap_list_t *tmp;

    tmp = list;
    while(tmp)
    {
        if(tmp->data != data)
            tmp = tmp->next;
        else
        {
            if (list == tmp){
                _dap_list_remove_link(list, tmp);
                list = NULL;
                tmp = NULL;
            }else {
                list = _dap_list_remove_link(list, tmp);
                dap_list_free1(tmp);
            }
            break;
        }
    }
    return list;
}

/**
 * dap_list_remove_all:
 * @list: a DapList, this must point to the top of the list
 * @data: data to remove
 *
 * Removes all list nodes with data equal to @data.
 * Returns the new head of the list. Contrast with
 * dap_list_remove() which removes only the first node
 * matching the given data.
 *
 * Returns: the (possibly changed) start of the DapList
 */
dap_list_t *dap_list_remove_all(dap_list_t *list, const void * data)
{
    dap_list_t *tmp = list;

    while(tmp)
    {
        if(tmp->data != data)
            tmp = tmp->next;
        else
        {
            dap_list_t *next = tmp->next;

            if(tmp->prev)
                tmp->prev->next = next;
            else
                list = next;
            if(next)
                next->prev = tmp->prev;

            if (tmp == list)
                list = NULL;
            dap_list_free1(tmp);
            tmp = next;
        }
    }
    return list;
}

/**
 * dap_list_remove_link:
 * @list: a DapList, this must point to the top of the list
 * @llink: an element in the DapList
 *
 * Removes an element from a DapList, without freeing the element.
 * The removed element's prev and next links are set to %NULL, so 
 * that it becomes a self-contained list with one element.
 *
 * This function is for example used to move an element in the list
 * (see the example for dap_list_concat()) or to remove an element in
 * the list before freeing its data:
 * |[<!-- language="C" --> 
 * list = dap_list_remove_link (list, llink);
 * free_some_data_that_may_access_the_list_again (llink->data);
 * dap_list_free (llink);
 * ]|
 *
 * Returns: the (possibly changed) start of the DapList
 */
dap_list_t *dap_list_remove_link(dap_list_t *list, dap_list_t *llink)
{
    return _dap_list_remove_link(list, llink);
}

/**
 * dap_list_delete_link:
 * @list: a DapList, this must point to the top of the list
 * @link_: node to delete from @list
 *
 * Removes the node link_ from the list and frees it. 
 * Compare this to dap_list_remove_link() which removes the node
 * without freeing it.
 *
 * Returns: the (possibly changed) start of the DapList
 */
dap_list_t *dap_list_delete_link(dap_list_t *list, dap_list_t *link_)
{
    list = _dap_list_remove_link(list, link_);
    dap_list_free1(link_);

    return list;
}

/**
 * dap_list_copy:
 * @list: a DapList, this must point to the top of the list
 *
 * Copies a DapList.
 *
 * Note that this is a "shallow" copy. If the list elements 
 * consist of pointers to data, the pointers are copied but 
 * the actual data is not. See dap_list_copy_deep() if you need
 * to copy the data as well.
 *
 * Returns: the start of the new list that holds the same data as @list
 */
dap_list_t *dap_list_copy(dap_list_t *list)
{
    return dap_list_copy_deep(list, NULL, NULL);
}

/**
 * dap_list_copy_deep:
 * @list: a DapList, this must point to the top of the list
 * @func: a copy function used to copy every element in the list
 * @user_data: user data passed to the copy function @func, or %NULL
 *
 * Makes a full (deep) copy of a DapList.
 *
 * In contrast with dap_list_copy(), this function uses @func to make
 * a copy of each list element, in addition to copying the list
 * container itself.
 *
 * @func, as a #DapCopyFunc, takes two arguments, the data to be copied
 * and a @user_data pointer. It's safe to pass %NULL as user_data,
 * if the copy function takes only one argument.
 *
 * For instance,
 * |[<!-- language="C" -->   
 * another_list = dap_list_copy_deep (list, (DapCopyFunc) dap_object_ref, NULL);
 * ]|
 *
 * And, to entirely free the new list, you could do:
 * |[<!-- language="C" --> 
 * dap_list_free_full (another_list, dap_object_unref);
 * ]|
 *
 * Returns: the start of the new list that holds a full copy of @list, 
 *     use dap_list_free_full() to free it
 */
dap_list_t *dap_list_copy_deep(dap_list_t *list, dap_callback_copy_t func, void* user_data)
{
    dap_list_t *new_list = NULL;

    if(list)
    {
        dap_list_t *last;

        new_list = dap_list_alloc();
        if(func)
            new_list->data = func(list->data, user_data);
        else
            new_list->data = list->data;
        new_list->prev = NULL;
        last = new_list;
        list = list->next;
        while(list)
        {
            last->next = dap_list_alloc();
            last->next->prev = last;
            last = last->next;
            if(func)
                last->data = func(list->data, user_data);
            else
                last->data = list->data;
            list = list->next;
        }
        last->next = NULL;
    }

    return new_list;
}

/**
 * dap_list_reverse:
 * @list: a DapList, this must point to the top of the list
 *
 * Reverses a DapList.
 * It simply switches the next and prev pointers of each element.
 *
 * Returns: the start of the reversed DapList
 */
dap_list_t * dap_list_reverse(dap_list_t *list)
{
    dap_list_t *last;

    last = NULL;
    while(list)
    {
        last = list;
        list = last->next;
        last->next = last->prev;
        last->prev = list;
    }

    return last;
}

/**
 * dap_list_nth:
 * @list: a DapList, this must point to the top of the list
 * @n: the position of the element, counting from 0
 *
 * Gets the element at the given position in a DapList.
 *
 * Returns: the element, or %NULL if the position is off 
 *     the end of the DapList
 */
dap_list_t *dap_list_nth(dap_list_t *list, unsigned int n)
{
    while((n-- > 0) && list)
        list = list->next;

    return list;
}

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
dap_list_t *dap_list_nth_prev(dap_list_t *list, unsigned int n)
{
    while((n-- > 0) && list)
        list = list->prev;

    return list;
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
void* dap_list_nth_data(dap_list_t *list, unsigned int n)
{
    while((n-- > 0) && list)
        list = list->next;

    return list ? list->data : NULL ;
}

/**
 * dap_list_find:
 * @list: a DapList, this must point to the top of the list
 * @data: the element data to find
 *
 * Finds the element in a DapList which contains the given data.
 *
 * Returns: the found DapList element, or %NULL if it is not found
 */
dap_list_t *dap_list_find(dap_list_t *list, const void * data)
{
    while(list)
    {
        if(list->data == data)
            break;
        list = list->next;
    }

    return list;
}

/**
 * dap_list_find_custom:
 * @list: a DapList, this must point to the top of the list
 * @data: user data passed to the function
 * @func: the function to call for each element. 
 *     It should return 0 when the desired element is found
 *
 * Finds an element in a DapList, using a supplied function to
 * find the desired element. It iterates over the list, calling 
 * the given function which should return 0 when the desired 
 * element is found. The function takes two const pointer arguments,
 * the DapList element's data as the first argument and the
 * given user data.
 *
 * Returns: the found DapList element, or %NULL if it is not found
 */
dap_list_t *dap_list_find_custom(dap_list_t *list, const void * data, dap_callback_compare_t func)
{
    dap_return_val_if_fail(func != NULL, list);

    while(list)
    {
        if(!func(list->data, data))
            return list;
        list = list->next;
    }

    return NULL ;
}

/**
 * dap_list_position:
 * @list: a DapList, this must point to the top of the list
 * @llink: an element in the DapList
 *
 * Gets the position of the given element 
 * in the DapList (starting from 0).
 *
 * Returns: the position of the element in the DapList,
 *     or -1 if the element is not found
 */
int dap_list_position(dap_list_t *list, dap_list_t *llink)
{
    int i;

    i = 0;
    while(list)
    {
        if(list == llink)
            return i;
        i++;
        list = list->next;
    }

    return -1;
}

/**
 * dap_list_index:
 * @list: a DapList, this must point to the top of the list
 * @data: the data to find
 *
 * Gets the position of the element containing 
 * the given data (starting from 0).
 *
 * Returns: the index of the element containing the data, 
 *     or -1 if the data is not found
 */
int dap_list_index(dap_list_t *list, const void * data)
{
    int i;

    i = 0;
    while(list)
    {
        if(list->data == data)
            return i;
        i++;
        list = list->next;
    }

    return -1;
}

/**
 * dap_list_last:
 * @list: any DapList element
 *
 * Gets the last element in a DapList.
 *
 * Returns: the last element in the DapList,
 *     or %NULL if the DapList has no elements
 */
dap_list_t * dap_list_last(dap_list_t *list)
{
    if(list)
    {
        while(list && list->next)
            list = list->next;
    }

    return list;
}

/**
 * dap_list_first:
 * @list: any DapList element
 *
 * Gets the first element in a DapList.
 *
 * Returns: the first element in the DapList,
 *     or %NULL if the DapList has no elements
 */
dap_list_t *dap_list_first(dap_list_t *list)
{
    if(list)
    {
        while(list->prev)
            list = list->prev;
    }

    return list;
}

/**
 * dap_list_length:
 * @list: a DapList, this must point to the top of the list
 *
 * Gets the number of elements in a DapList.
 *
 * This function iterates over the whole list to count its elements.
 *
 * Returns: the number of elements in the DapList
 */
unsigned int dap_list_length(dap_list_t *list)
{
    unsigned int length;

    length = 0;
    while(list)
    {
        length++;
        list = list->next;
    }

    return length;
}

/**
 * dap_list_foreach:
 * @list: a DapList, this must point to the top of the list
 * @func: the function to call with each element's data
 * @user_data: user data to pass to the function
 *
 * Calls a function for each element of a DapList.
 */
void dap_list_foreach(dap_list_t *list, dap_callback_t func, void* user_data)
{
    while(list)
    {
        dap_list_t *next = list->next;
        (*func)(list->data, user_data);
        list = next;
    }
}

static dap_list_t* dap_list_insert_sorted_real(dap_list_t *list, void* data, dap_callback_t func, void* user_data)
{
    dap_list_t *tmp_list = list;
    dap_list_t *new_list;
    int cmp;

    dap_return_val_if_fail(func != NULL, list);

    if(!list)
    {
        new_list = dap_list_alloc();
        new_list->data = data;
        return new_list;
    }

    cmp = ((dap_callback_compare_data_t) func)(data, tmp_list->data, user_data);

    while((tmp_list->next) && (cmp > 0))
    {
        tmp_list = tmp_list->next;

        cmp = ((dap_callback_compare_data_t) func)(data, tmp_list->data, user_data);
    }

    new_list = dap_list_alloc();
    new_list->data = data;

    if((!tmp_list->next) && (cmp > 0))
            {
        tmp_list->next = new_list;
        new_list->prev = tmp_list;
        return list;
    }

    if(tmp_list->prev)
    {
        tmp_list->prev->next = new_list;
        new_list->prev = tmp_list->prev;
    }
    new_list->next = tmp_list;
    tmp_list->prev = new_list;

    if(tmp_list == list)
        return new_list;
    else
        return list;
}

/**
 * dap_list_insert_sorted:
 * @list: a pointer to a DapList, this must point to the top of the
 *     already sorted list
 * @data: the data for the new element
 * @func: the function to compare elements in the list. It should
 *     return a number > 0 if the first parameter comes after the
 *     second parameter in the sort order.
 *
 * Inserts a new element into the list, using the given comparison
 * function to determine its position.
 *
 * If you are adding many new elements to a list, and the number of
 * new elements is much larger than the length of the list, use
 * dap_list_prepend() to add the new items and sort the list afterwards
 * with dap_list_sort().
 *
 * Returns: the (possibly changed) start of the DapList
 */
dap_list_t *dap_list_insert_sorted(dap_list_t *list, void* data, dap_callback_compare_t func)
{
    return dap_list_insert_sorted_real(list, data, (dap_callback_t) func, NULL);
}

/**
 * dap_list_insert_sorted_with_data:
 * @list: a pointer to a DapList, this must point to the top of the
 *     already sorted list
 * @data: the data for the new element
 * @func: the function to compare elements in the list. It should
 *     return a number > 0 if the first parameter  comes after the
 *     second parameter in the sort order.
 * @user_data: user data to pass to comparison function
 *
 * Inserts a new element into the list, using the given comparison 
 * function to determine its position.
 *
 * If you are adding many new elements to a list, and the number of
 * new elements is much larger than the length of the list, use
 * dap_list_prepend() to add the new items and sort the list afterwards
 * with dap_list_sort().
 *
 * Returns: the (possibly changed) start of the DapList
 */
dap_list_t * dap_list_insert_sorted_with_data(dap_list_t *list, void* data, dap_callback_compare_data_t func, void* user_data)
{
    return dap_list_insert_sorted_real(list, data, (dap_callback_t) func, user_data);
}

static dap_list_t *dap_list_sort_merge(dap_list_t *l1, dap_list_t *l2, dap_callback_t compare_func, void* user_data)
{
    dap_list_t list, *l, *lprev;
    int cmp;

    l = &list;
    lprev = NULL;

    while(l1 && l2)
    {
        cmp = ((dap_callback_compare_data_t) compare_func)(l1->data, l2->data, user_data);

        if(cmp <= 0)
                {
            l->next = l1;
            l1 = l1->next;
        }
        else
        {
            l->next = l2;
            l2 = l2->next;
        }
        l = l->next;
        l->prev = lprev;
        lprev = l;
    }
    l->next = l1 ? l1 : l2;
    l->next->prev = l;

    return list.next;
}

static dap_list_t *dap_list_sort_real(dap_list_t *list, dap_callback_t compare_func, void* user_data)
{
    dap_list_t *l1, *l2;

    if(!list)
        return NULL ;
    if(!list->next)
        return list;

    l1 = list;
    l2 = list->next;

    while((l2 = l2->next) != NULL )
    {
        if((l2 = l2->next) == NULL)
            break;
        l1 = l1->next;
    }
    l2 = l1->next;
    l1->next = NULL;

    return dap_list_sort_merge(dap_list_sort_real(list, compare_func, user_data),
            dap_list_sort_real(l2, compare_func, user_data),
            compare_func,
            user_data);
}

/**
 * dap_list_sort:
 * @list: a DapList, this must point to the top of the list
 * @compare_func: the comparison function used to sort the DapList.
 *     This function is passed the data from 2 elements of the DapList
 *     and should return 0 if they are equal, a negative value if the 
 *     first element comes before the second, or a positive value if 
 *     the first element comes after the second.
 *
 * Sorts a DapList using the given comparison function. The algorithm
 * used is a stable sort.
 *
 * Returns: the (possibly changed) start of the DapList
 */
/**
 * DapCompareFunc:
 * @a: a value
 * @b: a value to compare with
 *
 * Specifies the type of a comparison function used to compare two
 * values.  The function should return a negative integer if the first
 * value comes before the second, 0 if they are equal, or a positive
 * integer if the first value comes after the second.
 *
 * Returns: negative value if @a < @b; zero if @a = @b; positive
 *          value if @a > @b
 */
dap_list_t *dap_list_sort(dap_list_t *list, dap_callback_compare_t compare_func)
{
    return dap_list_sort_real(list, (dap_callback_t) compare_func, NULL);
}

/**
 * dap_list_sort_with_data:
 * @list: a DapList, this must point to the top of the list
 * @compare_func: comparison function
 * @user_data: user data to pass to comparison function
 *
 * Like dap_list_sort(), but the comparison function accepts
 * a user data argument.
 *
 * Returns: the (possibly changed) start of the DapList
 */
/**
 * DapCompareFunc:
 * @a: a value
 * @b: a value to compare with
 * @user_data: user data
 *
 * Specifies the type of a comparison function used to compare two
 * values.  The function should return a negative integer if the first
 * value comes before the second, 0 if they are equal, or a positive
 * integer if the first value comes after the second.
 *
 * Returns: negative value if @a < @b; zero if @a = @b; positive
 *          value if @a > @b
 */
dap_list_t *dap_list_sort_with_data(dap_list_t *list, dap_callback_compare_data_t compare_func, void* user_data)
{
    return dap_list_sort_real(list, (dap_callback_t) compare_func, user_data);
}
