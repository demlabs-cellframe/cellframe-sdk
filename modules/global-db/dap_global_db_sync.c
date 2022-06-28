/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Demlabs Ltd.   https://demlabs.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "dap_common.h"
#include "dap_list.h"
#include "dap_strfuncs.h"
#include "dap_fnmatch.h"
#include "dap_global_db.h"
#include "dap_global_db_sync.h"

#define LOG_TAG "dap_global_db_sync"

static dap_list_t *s_sync_group_items = NULL;
static dap_list_t *s_sync_group_extra_items = NULL;

static void s_clear_sync_grp(void *a_elm);
static int s_db_add_sync_group(dap_list_t **a_grp_list, dap_sync_group_item_t *a_item);

void dap_global_db_sync_init()
{

}

/**
 * @brief Deinitialize a database.
 * @note You should call this function at the end.
 * @return (none)
 */
void dap_global_db_sync_deinit()
{
    dap_list_free_full(s_sync_group_items, s_clear_sync_grp);
    dap_list_free_full(s_sync_group_extra_items, s_clear_sync_grp);
    s_sync_group_extra_items = s_sync_group_items = NULL;
}

/**
 * @brief Adds a group name for synchronization.
 * @param a_net_name a net name string, for all net a_net_name=null
 * @param a_group_prefix a prefix of the group name
 * @param a_callback a callback function
 * @param a_arg a pointer to an argument
 * @return (none)
 */
void dap_chain_global_db_add_sync_group(const char *a_net_name, const char *a_group_prefix, dap_global_db_obj_callback_notify_t a_callback, void *a_arg)
{
    dap_sync_group_item_t *l_item = DAP_NEW_Z(dap_sync_group_item_t);
    l_item->net_name = dap_strdup(a_net_name);
    l_item->group_mask = dap_strdup_printf("%s.*", a_group_prefix);
    l_item->callback_notify = a_callback;
    l_item->callback_arg = a_arg;
    s_db_add_sync_group(&s_sync_group_items, l_item);
}

/**
 * @brief Adds a group name for synchronization with especially node addresses.
 * @param a_net_name a net name string, for all net a_net_name=null
 * @param a_group_mask a group mask string
 * @param a_callback a callabck function
 * @param a_arg a pointer to an argument
 * @return (none)
 */
void dap_chain_global_db_add_sync_extra_group(const char *a_net_name, const char *a_group_mask, dap_global_db_obj_callback_notify_t a_callback, void *a_arg)
{
    dap_sync_group_item_t* l_item = DAP_NEW_Z(dap_sync_group_item_t);
    l_item->net_name = dap_strdup(a_net_name);
    l_item->group_mask = dap_strdup(a_group_mask);
    l_item->callback_notify = a_callback;
    l_item->callback_arg = a_arg;
    s_db_add_sync_group(&s_sync_group_extra_items, l_item);
}

/**
 * @brief Gets a list of a group mask for s_sync_group_items.
 * @param a_net_name a net name string, for all net a_net_name=null
 * @return Returns a pointer to a list of a group mask.
 */
dap_list_t* dap_chain_db_get_sync_groups(const char *a_net_name)
{
    if(!a_net_name)
        return dap_list_copy(s_sync_group_items);

    dap_list_t *l_list_out = NULL;
    dap_list_t *l_list_group = s_sync_group_items;
    while(l_list_group) {
        if(!dap_strcmp(a_net_name, ((dap_sync_group_item_t*) l_list_group->data)->net_name)) {
            l_list_out = dap_list_append(l_list_out, l_list_group->data);
        }
        l_list_group = dap_list_next(l_list_group);
    }
    return l_list_out;
}

/**
 * @brief Gets a list of a group mask for s_sync_group_items.
 * @param a_net_name a net name string, for all net a_net_name=null
 * @return Returns a pointer to a list of a group mask.
 */
dap_list_t* dap_chain_db_get_sync_extra_groups(const char *a_net_name)
{
    if(!a_net_name)
        return dap_list_copy(s_sync_group_extra_items);

    dap_list_t *l_list_out = NULL;
    dap_list_t *l_list_group = s_sync_group_extra_items;
    while(l_list_group) {
        if(!dap_strcmp(a_net_name, ((dap_sync_group_item_t*) l_list_group->data)->net_name)) {
            l_list_out = dap_list_append(l_list_out, l_list_group->data);
        }
        l_list_group = dap_list_next(l_list_group);
    }
    return l_list_out;
}

/**
 * @brief dap_global_db_get_sync_groups_all
 * @return
 */
dap_list_t * dap_global_db_get_sync_groups_all()
{
    return s_sync_group_items;
}

/**
 * @brief dap_global_db_get_sync_groups_extra_all
 * @return
 */
dap_list_t * dap_global_db_get_sync_groups_extra_all()
{
    return s_sync_group_extra_items;
}

/**
 * @brief s_clear_sync_grp
 * @param a_elm
 */
static void s_clear_sync_grp(void *a_elm)
{
    dap_sync_group_item_t *l_item = (dap_sync_group_item_t *)a_elm;
    DAP_DELETE(l_item->group_mask);
    DAP_DELETE(l_item);
}

/**
 * @brief s_db_add_sync_group
 * @param a_grp_list
 * @param a_item
 * @return
 */
static int s_db_add_sync_group(dap_list_t **a_grp_list, dap_sync_group_item_t *a_item)
{
    for (dap_list_t *it = *a_grp_list; it; it = it->next) {
        dap_sync_group_item_t *l_item = (dap_sync_group_item_t *)it->data;
        if (!dap_strcmp(l_item->group_mask, a_item->group_mask) && !dap_strcmp(l_item->net_name, a_item->net_name)) {
            log_it(L_WARNING, "Group mask '%s' already present in the list, ignore it", a_item->group_mask);
            s_clear_sync_grp(a_item);
            return -1;
        }
    }
    *a_grp_list = dap_list_append(*a_grp_list, a_item);
    return 0;
}
