/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2024
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP is free software: you can redistribute it and/or modify
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

#include "dap_common.h"
#include "dap_cli_error_codes.h"
#include "dap_chain_token_cli_error_codes.h"

#define LOG_TAG "dap_chain_token_cli_error_codes"

/**
 * @brief dap_chain_token_cli_error_codes_init
 * Register all token CLI error codes with the dynamic error code system
 * @return 0 on success
 */
int dap_chain_token_cli_error_codes_init(void)
{
    // Token declaration errors
    dap_cli_error_code_register("TOKEN_DECL_CANT_CREATE_DATUM", -300, "Cannot create datum for token declaration");
    dap_cli_error_code_register("TOKEN_DECL_FAILED", -301, "Token declaration failed");
    dap_cli_error_code_register("TOKEN_DECL_FIND_TICKER_ERR", -302, "Token ticker not found");
    dap_cli_error_code_register("TOKEN_DECL_NO_SUITABLE_CHAIN", -303, "No suitable chain for token declaration");
    dap_cli_error_code_register("TOKEN_DECL_NOT_VALID_CERT_ERR", -304, "Certificate not valid for token declaration");
    dap_cli_error_code_register("TOKEN_DECL_TOKEN_CANNOT_MATCH", -305, "Token cannot match declaration");
    dap_cli_error_code_register("TOKEN_DECL_UNKNOWN_TOKEN_TYPE", -306, "Unknown token type for declaration");
    
    // Token declaration signature errors
    dap_cli_error_code_register("TOKEN_DECL_SIGN_NEED_DATUM_ARG_ERR", -310, "Datum argument required for token declaration signature");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_HEX_PARAM_ERR", -311, "Invalid hex parameter for token declaration signature");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_NET_PARAM_ERR", -312, "Network parameter error for token declaration signature");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_NOT_VALID_CERT_ERR", -313, "Certificate not valid for token declaration signature");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_CANT_FIND_DATUM_ERR", -314, "Cannot find datum for token declaration signature");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_WRONG_DATUM_TYPE_ERR", -315, "Wrong datum type for token declaration signature");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_DATUM_HAS_WRONG_SIGNATURE_ERR", -316, "Datum has wrong signature for token declaration");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_SERT_NOT_VALID_ERR", -317, "Certificate not valid for token declaration signature");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_DATUM_CANT_BE_PL_MEMPOOL_ERR", -318, "Datum cannot be placed in mempool for token declaration");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_CANT_REMOVE_OLD_DATUM_ERR", -319, "Cannot remove old datum for token declaration signature");
    dap_cli_error_code_register("TOKEN_DECL_SIGN_OK", 0, "Token declaration signature successful");
    
    // Token emission errors
    dap_cli_error_code_register("TOKEN_EMIT_ADDR_INVALID_ERR", -320, "Invalid address for token emission");
    dap_cli_error_code_register("TOKEN_EMIT_CANT_FIND_EMI_ERR", -321, "Cannot find emission for token");
    dap_cli_error_code_register("TOKEN_EMIT_H_PARAM_ERR", -322, "Invalid -H parameter for token emission");
    dap_cli_error_code_register("TOKEN_EMIT_REQUIRES_PARAMETER_CERTS", -323, "Certificate parameter required for token emission");
    dap_cli_error_code_register("TOKEN_EMIT_NOT_VALID_CERT_ERRS", -324, "Certificate not valid for token emission");
    dap_cli_error_code_register("TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION_VAL", -325, "Emission value parameter required");
    dap_cli_error_code_register("TOKEN_EMIT_REQUIRES_PARAMETER_ADDR", -326, "Address parameter required for token emission");
    dap_cli_error_code_register("TOKEN_EMIT_REQUIRES_PARAMETER_TOKEN", -327, "Token parameter required for emission");
    dap_cli_error_code_register("TOKEN_EMIT_REQUIRES_PARAMETER_CHAIN_EMISSION", -328, "Chain emission parameter required");
    dap_cli_error_code_register("TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION", -329, "Emission parameter required");
    
    // Token update errors
    dap_cli_error_code_register("TOKEN_UPDATE_NOT_VALID_CERT_ERR", -340, "Certificate not valid for token update");
    dap_cli_error_code_register("TOKEN_UPDATE_UNKNOWN_TOKEN_TYPE", -341, "Unknown token type for update");
    dap_cli_error_code_register("TOKEN_UPDATE_NO_SUITABLE_CHAIN", -342, "No suitable chain for token update");
    dap_cli_error_code_register("TOKEN_UPDATE_OK", 0, "Token update successful");
    
    // Chain CA publication errors
    dap_cli_error_code_register("CHAIN_CA_PUB_CANT_SERIALIZE_MEMORY_CERT_ERR", -330, "Cannot serialize certificate to memory");
    dap_cli_error_code_register("CHAIN_CA_PUB_CANT_PRODUCE_CERT_ERR", -331, "Cannot produce certificate");
    dap_cli_error_code_register("CHAIN_CA_PUB_OK", 0, "Chain CA publication successful");
    dap_cli_error_code_register("CHAIN_CA_PUB_CANT_PLACE_CERT_ERR", -332, "Cannot place certificate");
    dap_cli_error_code_register("CHAIN_CA_PUB_CANT_FIND_CERT_ERR", -333, "Cannot find certificate");
    dap_cli_error_code_register("CHAIN_CA_PUB_CORRUPTED_CERT_ERR", -334, "Certificate is corrupted");
    
    log_it(L_NOTICE, "Token CLI error codes registered");
    return 0;
}

/**
 * @brief dap_chain_token_cli_error_codes_deinit
 * Cleanup token CLI error codes (currently no-op as codes are managed globally)
 */
void dap_chain_token_cli_error_codes_deinit(void)
{
    // No cleanup needed - error codes are managed by global system
}

