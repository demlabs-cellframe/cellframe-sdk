#pragma once

#include "dap_ht.h"

#ifndef DAP_HT_UTILS_H
#define DAP_HT_UTILS_H

#define DAP_HT_HHO(add, hhname) ((ptrdiff_t)((char *)&((add)->hhname) - (char *)(add)))

#define dap_ht_add_keyptr_hh(hhname, head, keyptr, keylen, add) \
    dap_ht_add_impl((void**)&(head), (add), &((add)->hhname), \
        (keyptr), (unsigned)(keylen), \
        DAP_HT_HHO((add), hhname))

#define dap_ht_clear_hh(hhname, head) do { \
    if ((head) && (head)->hhname.tbl) { \
        DAP_DELETE((head)->hhname.tbl->buckets); \
        DAP_DELETE((head)->hhname.tbl); \
    } \
    (head) = NULL; \
} while (0)

static inline void dap_ht_sort_impl(void **head, ptrdiff_t hho, int (*cmp)(void*, void*)) {
    if (!head || !*head || !cmp) return;
    void *sorted = NULL;
    void *tail = NULL;
    void *el = *head;
    dap_ht_table_t *tbl = ((dap_ht_handle_t*)((char*)*head + hho))->tbl;

    while (el) {
        dap_ht_handle_t *el_hh = (dap_ht_handle_t*)((char*)el + hho);
        void *next = el_hh->next;
        el_hh->prev = NULL;
        el_hh->next = NULL;

        if (!sorted) {
            sorted = el;
            tail = el;
        } else {
            void *cur = sorted;
            dap_ht_handle_t *cur_hh = (dap_ht_handle_t*)((char*)cur + hho);
            if (cmp(el, cur) < 0) {
                el_hh->next = cur;
                cur_hh->prev = el;
                sorted = el;
            } else {
                while (cur_hh->next) {
                    void *cur_next = cur_hh->next;
                    if (cmp(el, cur_next) < 0) break;
                    cur = cur_next;
                    cur_hh = (dap_ht_handle_t*)((char*)cur + hho);
                }
                el_hh->next = cur_hh->next;
                el_hh->prev = cur;
                if (cur_hh->next)
                    ((dap_ht_handle_t*)((char*)cur_hh->next + hho))->prev = el;
                cur_hh->next = el;
                if (!el_hh->next)
                    tail = el;
            }
        }
        el = next;
    }

    if (!tail) {
        void *cur = sorted;
        while (cur) {
            tail = cur;
            cur = ((dap_ht_handle_t*)((char*)cur + hho))->next;
        }
    }
    if (tbl)
        tbl->tail = tail;
    *head = sorted;
}

#define dap_ht_sort(head, cmp) do { \
    if (head) \
        dap_ht_sort_impl((void**)&(head), DAP_HT_HHO((head), hh), (int (*)(void*, void*))(cmp)); \
} while (0)

#define dap_ht_sort_hh(hhname, head, cmp) do { \
    if (head) \
        dap_ht_sort_impl((void**)&(head), DAP_HT_HHO((head), hhname), (int (*)(void*, void*))(cmp)); \
} while (0)

#define dap_ht_add_inorder_hh(hhname, head, field, keylen, add, cmp) do { \
    dap_ht_add_hh(hhname, head, field, add); \
    dap_ht_sort_hh(hhname, head, cmp); \
} while (0)

#define dap_ht_last(head) ((head) && (head)->hh.tbl ? (DAP_HT_TYPEOF(head))((head)->hh.tbl->tail) : NULL)

#define dap_ht_last_hh(hhname, head) ((head) && (head)->hhname.tbl ? (DAP_HT_TYPEOF(head))((head)->hhname.tbl->tail) : NULL)

#define dap_ht_select_hh(hh_dst, dest, hh_src, src, cond) do { \
    (dest) = NULL; \
    if (src) { \
        DAP_HT_TYPEOF(src) _el, _tmp; \
        dap_ht_foreach_hh(hh_src, src, _el, _tmp) { \
            if (cond(_el)) { \
                dap_ht_add_by_hashvalue_impl((void**)&(dest), (void*)_el, &(_el)->hh_dst, \
                    (_el)->hh_src.key, (unsigned)(_el)->hh_src.keylen, (_el)->hh_src.hashv, \
                    DAP_HT_HHO((_el), hh_dst)); \
            } \
        } \
    } \
} while (0)

#endif // DAP_HT_UTILS_H
