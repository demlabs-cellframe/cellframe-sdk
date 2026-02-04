/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
 */

#include "dap_chain_net_core.h"
#include "dap_cli_server.h"
#include "dap_json_rpc.h"
#include "dap_chain_net_types.h"  // Base types from common (NOT dap_chain_net.h!)
#include "dap_chain.h"
#include "dap_string.h"
#include "dap_ht_utils.h"
#include "dap_list_utils.h"
#include "dap_chain_net_utils.h"  // For dap_chain_net_get_default_chain_by_chain_type

#define LOG_TAG "chain_net_core"

// Forward declarations
dap_chain_t* dap_chain_net_get_chain_by_name(dap_chain_net_t *a_net, const char *a_name);
dap_chain_t* dap_chain_net_get_chain_by_id(dap_chain_net_t *a_net, dap_chain_id_t a_chain_id);

// Forward declarations - these will be resolved at final link from net module
extern dap_chain_t *dap_chain_net_get_chain_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type);

// ============ NETWORK REGISTRY ============
// Global registry of all networks (by name and by ID)
static dap_chain_net_t *s_nets_by_name = NULL;
static dap_chain_net_t *s_nets_by_id = NULL;

/**
 * @brief Register network in global registry
 * @param a_net Network to register
 */
void dap_chain_net_register(dap_chain_net_t *a_net)
{
    if (!a_net)
        return;
    dap_ht_add_str(s_nets_by_name, pub.name, a_net);
    dap_ht_add_hh(hh2, s_nets_by_id, pub.id, a_net);
}

/**
 * @brief Unregister network from global registry
 * @param a_net Network to unregister
 */
void dap_chain_net_unregister(dap_chain_net_t *a_net)
{
    if (!a_net)
        return;
    dap_ht_del(s_nets_by_name, a_net);
    dap_ht_del_hh(hh2, s_nets_by_id, a_net);
}

/**
 * @brief Find network by name
 * @param a_name Network name
 * @return Network pointer or NULL if not found
 */
dap_chain_net_t *dap_chain_net_by_name(const char *a_name)
{
    dap_chain_net_t *l_net = NULL;
    if (a_name)
        dap_ht_find_str(s_nets_by_name, a_name, l_net);
    return l_net;
}

/**
 * @brief Find network by ID
 * @param a_id Network ID
 * @return Network pointer or NULL if not found
 */
dap_chain_net_t *dap_chain_net_by_id(dap_chain_net_id_t a_id)
{
    dap_chain_net_t *l_net = NULL;
    dap_ht_find_hh(hh2, s_nets_by_id, &a_id, sizeof(a_id), l_net);
    return l_net;
}

// ============ CLI ARGUMENT PARSER ============

/**
 * @brief Parse -net and -chain arguments from CLI
 * @details Core utility for all network-related CLI commands
 */
int dap_chain_net_parse_net_chain(dap_json_t *a_json_arr_reply, int *a_arg_index,
                                       int a_argc, char **a_argv,
                                       dap_chain_t **a_chain, dap_chain_net_t **a_net,
                                       dap_chain_type_t a_default_chain_type)
{
    const char *l_chain_str = NULL, *l_net_str = NULL;

    // Net name
    if(a_net)
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-net", &l_net_str);
    else {
        dap_json_rpc_error_add(a_json_arr_reply, -100, "Error in internal command processing.");
        return -100;
    }

    // Select network
    if(!l_net_str) {
        dap_json_rpc_error_add(a_json_arr_reply, -101, "%s requires parameter '-net'", a_argv[0]);
        return -101;
    }

    if (! (*a_net = dap_chain_net_by_name(l_net_str)) ) {
        return dap_json_rpc_error_add(a_json_arr_reply, -102, "Network %s not found", l_net_str), -102;
    }

    // Chain name
    if(a_chain) {
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-chain", &l_chain_str);

        // Select chain
        if(l_chain_str) {
            if ((*a_chain = dap_chain_net_get_chain_by_name(*a_net, l_chain_str)) == NULL) {
                dap_string_t *l_reply = dap_string_new("");
                dap_string_append_printf(l_reply, "Invalid '-chain' parameter \"%s\", not found in net %s\nAvailable chains:",
                                                  l_chain_str, l_net_str);
                dap_chain_t *l_chain;
                dap_dl_foreach((*a_net)->pub.chains, l_chain) {
                    dap_string_append_printf(l_reply, "\n\t%s", l_chain->name);
                }
                char *l_str_reply = dap_string_free(l_reply, false);
                dap_json_rpc_error_add(a_json_arr_reply, -103, "%s", l_str_reply);
                DAP_DELETE(l_str_reply);
                return -103;
            }
        } else if (a_default_chain_type != CHAIN_TYPE_INVALID) {
            if (( *a_chain = dap_chain_net_get_default_chain_by_chain_type(*a_net, a_default_chain_type) ))
                return 0;
            else {
                dap_json_rpc_error_add(a_json_arr_reply, -104,
                        "Unable to get the default chain of type %s for the network.", 
                        dap_chain_type_to_str(a_default_chain_type));
                return -104;
            }
        }
    }
    return 0;
}

// ============ CHAIN LOOKUP FUNCTIONS ============

/**
 * @brief Find chain by name in network
 * @param a_net Network
 * @param a_name Chain name
 * @return Chain pointer or NULL if not found
 */
dap_chain_t* dap_chain_net_get_chain_by_name(dap_chain_net_t *a_net, const char *a_name)
{
   dap_chain_t *l_chain;
   dap_dl_foreach(a_net->pub.chains, l_chain){
        if(dap_strcmp(l_chain->name, a_name) == 0)
            return l_chain;
   }
   return NULL;
}

/**
 * @brief Find chain by ID in network
 * @param a_net Network
 * @param a_chain_id Chain ID
 * @return Chain pointer or NULL if not found
 */
dap_chain_t* dap_chain_net_get_chain_by_id(dap_chain_net_t *a_net, dap_chain_id_t a_chain_id)
{
   dap_chain_t *l_chain;
   dap_dl_foreach(a_net->pub.chains, l_chain)
        if (l_chain->id.uint64 == a_chain_id.uint64)
            return l_chain;
   return NULL;
}

// REMOVED: dap_chain_net_get_default_chain_by_chain_type() - duplicate definition
// Already implemented in modules/net/dap_chain_net_utils.c
// This was causing "multiple definition" linker error

// ============ MODULE INITIALIZATION ============

// Include API registry from common module
#include "dap_chain_net_api.h"

/**
 * @brief Initialize network core module and register API functions
 * @details This function must be called before dap_chain_net_init()
 *          to properly register API functions and avoid circular dependencies
 * @return 0 on success, negative error code on failure
 */
int dap_chain_net_core_init(void)
{
    // Phase 5.3: Register network API functions for mid-level modules
    // This breaks cyclic dependencies by allowing blocks/esbocs/stake to use
    // core net functions without depending on full net module
    // 
    // Registration is done in net_core (not net) because:
    // 1. Core functions (by_id, by_name, get_chain_by_name, get_chain_by_id) are defined here
    // 2. Registering in net caused multiple definition errors due to circular dependency
    // 3. Full net functions (get_chain_by_type, etc.) are declared as extern
    //
    // NOTE: Some functions (get_cur_cell, get_load_mode, get_reward, add_reward) have
    //       signature mismatches with the API registry and are set to NULL for now
    //       They will be registered properly when net module is fully loaded
    dap_chain_net_api_registry_t l_api_registry = {
        .by_id = dap_chain_net_by_id,
        .by_name = dap_chain_net_by_name,
        .get_chain_by_name = dap_chain_net_get_chain_by_name,
        .get_chain_by_type = dap_chain_net_get_chain_by_chain_type,
        .get_default_chain_by_type = dap_chain_net_get_default_chain_by_chain_type,
        .get_cur_cell = NULL,       // TODO: Signature mismatch - returns dap_chain_cell_t*, not dap_chain_cell_id_t*
        .get_load_mode = NULL,      // TODO: Signature mismatch - returns dap_chain_net_load_mode_t, not bool
        .get_reward = NULL,         // TODO: Will be set when net module loads
        .add_reward = NULL,         // TODO: Signature mismatch - returns void, not int
        .datum_add_to_mempool = NULL // TODO: Will be set when mempool integration is complete
    };
    int l_api_ret = dap_chain_net_api_register(&l_api_registry);
    if (l_api_ret != 0) {
        log_it(L_ERROR, "Failed to register network API functions (code %d)", l_api_ret);
        return -1;
    }
    log_it(L_INFO, "Network core API functions registered for dependency inversion");
    
    return 0;
}
