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

#include <sys/socket.h>
#include <netinet/in.h>

#include <string.h>

#include "dap_config.h"
#include "dap_chain_net.h"
#include "dap_chain_node_ctl.h"

#define LOG_TAG "chain_node_ctl"

typedef struct dap_chain_node_ctl_pvt{
    uint_fast64_t padding;
} dap_chain_node_ctl_pvt_t;

#define PVT(a) ( (dap_chain_node_ctl_pvt_t *) (a)->pvt )
#define PVT_S(a) ( (dap_chain_node_ctl_pvt_t *) (a).pvt )


/**
 * @brief dap_chain_node_new
 * @return
 */
dap_chain_node_ctl_t * dap_chain_node_ctl_new()
{
    dap_chain_node_ctl_t * ret = DAP_NEW_Z_SIZE(dap_chain_node_ctl_t, sizeof(ret->pub) + sizeof(dap_chain_node_ctl_pvt_t) );

    return ret;
}

/**
 * @brief dap_chain_node_delete
 * @param a_node
 */
void dap_chain_node_ctl_delete(dap_chain_node_ctl_t * a_node)
{
    DAP_DELETE(a_node);
}

/**
 * @brief dap_chain_node_ctl_open
 * @param a_name
 * @return
 */
dap_chain_node_ctl_t * dap_chain_node_ctl_open( const char * a_name )
{
   dap_chain_node_ctl_t * l_node = NULL;
   const char c_node_folder[]="node";
   size_t buf_size = 2+strlen(a_name)+strlen(c_node_folder);
   char *buf= DAP_NEW_SIZE(char, buf_size);
   snprintf(buf,buf_size,"%s/%s",c_node_folder,a_name);
   dap_config_t * l_node_cfg = dap_config_open(buf);
   if ( l_node_cfg ){
       //dap_config_get_item_str_default()
        l_node = dap_chain_node_ctl_new();
   } else {
       log_it(L_ERROR,"Can't open node \"%s\". Check the configuration files path.",a_name);
   }
   DAP_DELETE(buf);
   return l_node;
}
