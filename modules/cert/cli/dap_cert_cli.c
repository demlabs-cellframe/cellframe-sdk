/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Sources         https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of Cellframe SDK the open source project
 *
 *    Cellframe SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    Cellframe SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_cert_cli.h"
#include "dap_cert.h"
#include "dap_cli_server.h"
#include "dap_json_rpc.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_sign.h"
#include "dap_hash_compat.h"
#include "dap_enc_key.h"

#define LOG_TAG "dap_cert_cli"

/**
 * @brief Error codes for cert CLI commands
 */
enum {
    DAP_CERT_CLI_OK = 0,
    DAP_CERT_CLI_ERR_UNKNOWN_SUBCMD = -1,
    DAP_CERT_CLI_ERR_NO_CERTS = -2
};

/**
 * @brief Add certificate info to JSON object
 * 
 * @param a_cert Certificate to dump info from
 * @param a_version JSON-RPC version (1 or 2)
 * @return JSON object with certificate info
 */
static dap_json_t *s_cert_info_to_json(dap_cert_t *a_cert, int a_version)
{
    dap_json_t *l_json_cert = dap_json_object_new();
    if (!l_json_cert)
        return NULL;

    dap_json_object_add_string(l_json_cert, "name", a_cert->name);
    
    if (a_cert->enc_key) {
        const char *l_key_type_str = dap_enc_get_type_name(a_cert->enc_key->type);
        dap_json_object_add_string(l_json_cert, "key_type", l_key_type_str ? l_key_type_str : "unknown");
        
        dap_sign_type_t l_sign_type = dap_sign_type_from_key_type(a_cert->enc_key->type);
        const char *l_sign_type_str = dap_sign_type_to_str(l_sign_type);
        dap_json_object_add_string(l_json_cert, "sign_type", l_sign_type_str ? l_sign_type_str : "unknown");
        
        bool l_has_private = a_cert->enc_key->priv_key_data && a_cert->enc_key->priv_key_data_size > 0;
        dap_json_object_add_bool(l_json_cert, "has_private_key", l_has_private);
        
        if (a_cert->enc_key->pub_key_data && a_cert->enc_key->pub_key_data_size > 0) {
            dap_hash_sha3_256_t l_pkey_hash;
            if (dap_hash_fast(a_cert->enc_key->pub_key_data, 
                              a_cert->enc_key->pub_key_data_size, 
                              &l_pkey_hash) == 0) {
                char *l_hash_str = dap_hash_sha3_256_to_str_static(&l_pkey_hash);
                dap_json_object_add_string(l_json_cert, "pkey_hash", l_hash_str);
            }
        }
    } else {
        dap_json_object_add_string(l_json_cert, "key_type", "none");
        dap_json_object_add_bool(l_json_cert, "has_private_key", false);
    }

    return l_json_cert;
}

/**
 * @brief Handler for 'cert list' command
 * 
 * Lists all certificates currently loaded in memory from ca_folders
 * 
 * @param a_argc Argument count
 * @param a_argv Argument values
 * @param a_json_arr_reply JSON array for response
 * @param a_version JSON-RPC version
 * @return 0 on success, negative error code on failure
 */
static int s_cli_cert_list(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void)a_argc;
    (void)a_argv;

    dap_list_t *l_certs = dap_cert_get_all_mem();
    
    dap_json_t *l_json_result = dap_json_object_new();
    if (!l_json_result) {
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }

    dap_json_t *l_json_certs_arr = dap_json_array_new();
    if (!l_json_certs_arr) {
        dap_json_object_free(l_json_result);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }

    size_t l_count = 0;
    for (dap_list_t *l_item = l_certs; l_item; l_item = l_item->next) {
        dap_cert_t *l_cert = (dap_cert_t *)l_item->data;
        if (!l_cert)
            continue;

        dap_json_t *l_json_cert = s_cert_info_to_json(l_cert, a_version);
        if (l_json_cert) {
            dap_json_array_add(l_json_certs_arr, l_json_cert);
            l_count++;
        }
    }

    dap_list_free(l_certs);

    dap_json_object_add_int64(l_json_result, "count", (int64_t)l_count);
    dap_json_object_add_object(l_json_result, "certificates", l_json_certs_arr);

    if (l_count == 0) {
        dap_json_object_add_string(l_json_result, "message", 
            "No certificates loaded. Check ca_folders parameter in [resources] section of config.");
    }

    dap_json_array_add(a_json_arr_reply, l_json_result);

    return DAP_CERT_CLI_OK;
}

/**
 * @brief Main command handler for 'cert' CLI command
 * 
 * @param a_argc Argument count
 * @param a_argv Argument values
 * @param a_json_arr_reply JSON array for response
 * @param a_version JSON-RPC version
 * @return 0 on success, negative error code on failure
 */
static int s_cli_cert(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int l_arg_index = 1;

    const char *l_subcmd = NULL;
    if (a_argc > l_arg_index)
        l_subcmd = a_argv[l_arg_index];

    if (!l_subcmd) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CERT_CLI_ERR_UNKNOWN_SUBCMD,
                               "Subcommand required. Use: cert list");
        return DAP_CERT_CLI_ERR_UNKNOWN_SUBCMD;
    }

    if (dap_strcmp(l_subcmd, "list") == 0) {
        return s_cli_cert_list(a_argc, a_argv, a_json_arr_reply, a_version);
    }

    dap_json_rpc_error_add(a_json_arr_reply, DAP_CERT_CLI_ERR_UNKNOWN_SUBCMD,
                           "Unknown subcommand '%s'. Use: cert list", l_subcmd);
    return DAP_CERT_CLI_ERR_UNKNOWN_SUBCMD;
}

/**
 * @brief Initialize certificate CLI commands
 * 
 * @return 0 on success, negative error code on failure
 */
int dap_cert_cli_init(void)
{
    dap_cli_server_cmd_add("cert", s_cli_cert, NULL,
                           "Certificate operations",
                           -1,
                           "cert { list }\n"
                           "\tManage certificates loaded from ca_folders\n\n"
                           "cert list\n"
                           "\tList all certificates loaded in memory.\n"
                           "\tShows: name, key_type, sign_type, has_private_key, pkey_hash.\n"
                           "\tUseful for checking available values for -certs parameter\n"
                           "\tin commands like: decree create, token_decl, etc.\n");

    log_it(L_INFO, "Certificate CLI commands registered");
    return 0;
}

/**
 * @brief Cleanup certificate CLI
 */
void dap_cert_cli_deinit(void)
{
    log_it(L_INFO, "Certificate CLI commands unregistered");
}
