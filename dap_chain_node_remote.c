/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <pthread.h>

#include "dap_chain_node_remote.h"


// List of connections
static GList *connect_list = NULL;

// for separate access to connect_list
static pthread_mutex_t connect_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Add new established connection in the list
 */
bool chain_node_client_list_add(dap_chain_node_client_t *client)
{
    if(!client)
        return false;
    pthread_mutex_lock(&connect_list_mutex);
    connect_list = g_list_append(connect_list, client);
    pthread_mutex_unlock(&connect_list_mutex);
    return true;
}

/**
 * Delete established connection from the list
 */
bool chain_node_client_list_del(dap_chain_node_client_t *client)
{
    pthread_mutex_lock(&connect_list_mutex);
    GList *list = g_list_find(connect_list, client);
    // found
    if(list)
        connect_list = g_list_remove(connect_list, client);
    pthread_mutex_unlock(&connect_list_mutex);
    if(list)
        return true;
    return false;
}

/**
 * Get one established connection
 *
 * n - the position of the established connection, counting from 0
 *
 * return client, or NULL if the position is off the end of the list
 */
dap_chain_node_client_t* chain_node_client_list_get_item(int n)
{
    pthread_mutex_lock(&connect_list_mutex);
    dap_chain_node_client_t *client = g_list_nth_data(connect_list, (guint) n);
    pthread_mutex_unlock(&connect_list_mutex);
    return client;
}
/**
 * Get the number of established connections
 */
int chain_node_client_list_count(void)
{
    pthread_mutex_lock(&connect_list_mutex);
    int len = g_list_length(connect_list);
    pthread_mutex_unlock(&connect_list_mutex);
    return len;
}

