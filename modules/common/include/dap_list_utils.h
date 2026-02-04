#pragma once

#include "dap_dl.h"
#include "dap_sl.h"

#ifndef DAP_LIST_UTILS_H
#define DAP_LIST_UTILS_H

#ifndef dap_dl_search_cmp
#define dap_dl_search_cmp(head, out, elt, cmp) do { \
    (out) = NULL; \
    DAP_DL_TYPEOF(head) _dl_el; \
    dap_dl_foreach(head, _dl_el) { \
        if ((cmp)(_dl_el, (elt)) == 0) { \
            (out) = _dl_el; \
            break; \
        } \
    } \
} while (0)
#endif

#ifndef dap_sl_insert_inorder
#define dap_sl_insert_inorder(head, add, cmp) do { \
    if (!(head)) { \
        (head) = (add); \
        (add)->next = NULL; \
    } else if ((cmp)((head), (add)) > 0) { \
        (add)->next = (head); \
        (head) = (add); \
    } else { \
        __typeof__(head) _sl_cur = (head); \
        while (_sl_cur->next && (cmp)(_sl_cur->next, (add)) <= 0) { \
            _sl_cur = _sl_cur->next; \
        } \
        (add)->next = _sl_cur->next; \
        _sl_cur->next = (add); \
    } \
} while (0)
#endif

#endif // DAP_LIST_UTILS_H
