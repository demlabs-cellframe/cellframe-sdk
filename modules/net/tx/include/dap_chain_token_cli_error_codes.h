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

#pragma once

#include "dap_cli_error_codes.h"

// Token CLI error code macros - map to dynamic error code system

// Token declaration errors
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_CANT_CREATE_DATUM              dap_cli_error_code_get("TOKEN_DECL_CANT_CREATE_DATUM")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_FAILED                         dap_cli_error_code_get("TOKEN_DECL_FAILED")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_FIND_TICKER_ERR                dap_cli_error_code_get("TOKEN_DECL_FIND_TICKER_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_NO_SUITABLE_CHAIN              dap_cli_error_code_get("TOKEN_DECL_NO_SUITABLE_CHAIN")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_NOT_VALID_CERT_ERR             dap_cli_error_code_get("TOKEN_DECL_NOT_VALID_CERT_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_TOKEN_CANNOT_MATCH             dap_cli_error_code_get("TOKEN_DECL_TOKEN_CANNOT_MATCH")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_UNKNOWN_TOKEN_TYPE             dap_cli_error_code_get("TOKEN_DECL_UNKNOWN_TOKEN_TYPE")

// Token declaration signature errors
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_NEED_DATUM_ARG_ERR           dap_cli_error_code_get("TOKEN_DECL_SIGN_NEED_DATUM_ARG_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_HEX_PARAM_ERR                dap_cli_error_code_get("TOKEN_DECL_SIGN_HEX_PARAM_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_NET_PARAM_ERR                dap_cli_error_code_get("TOKEN_DECL_SIGN_NET_PARAM_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_NOT_VALID_CERT_ERR           dap_cli_error_code_get("TOKEN_DECL_SIGN_NOT_VALID_CERT_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_CANT_FIND_DATUM_ERR          dap_cli_error_code_get("TOKEN_DECL_SIGN_CANT_FIND_DATUM_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_WRONG_DATUM_TYPE_ERR         dap_cli_error_code_get("TOKEN_DECL_SIGN_WRONG_DATUM_TYPE_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_DATUM_HAS_WRONG_SIGNATURE_ERR dap_cli_error_code_get("TOKEN_DECL_SIGN_DATUM_HAS_WRONG_SIGNATURE_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_SERT_NOT_VALID_ERR           dap_cli_error_code_get("TOKEN_DECL_SIGN_SERT_NOT_VALID_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_DATUM_CANT_BE_PL_MEMPOOL_ERR dap_cli_error_code_get("TOKEN_DECL_SIGN_DATUM_CANT_BE_PL_MEMPOOL_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_CANT_REMOVE_OLD_DATUM_ERR    dap_cli_error_code_get("TOKEN_DECL_SIGN_CANT_REMOVE_OLD_DATUM_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_DECL_SIGN_OK                            dap_cli_error_code_get("TOKEN_DECL_SIGN_OK")

// Token emission errors
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_ADDR_INVALID_ERR               dap_cli_error_code_get("TOKEN_EMIT_ADDR_INVALID_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_CANT_FIND_EMI_ERR              dap_cli_error_code_get("TOKEN_EMIT_CANT_FIND_EMI_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_H_PARAM_ERR                    dap_cli_error_code_get("TOKEN_EMIT_H_PARAM_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_CERTS       dap_cli_error_code_get("TOKEN_EMIT_REQUIRES_PARAMETER_CERTS")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_NOT_VALID_CERT_ERRS           dap_cli_error_code_get("TOKEN_EMIT_NOT_VALID_CERT_ERRS")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION_VAL dap_cli_error_code_get("TOKEN_EMIT_REQUIRES_PARAMETER_EMISSION_VAL")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_ADDR        dap_cli_error_code_get("TOKEN_EMIT_REQUIRES_PARAMETER_ADDR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_EMIT_REQUIRES_PARAMETER_TOKEN       dap_cli_error_code_get("TOKEN_EMIT_REQUIRES_PARAMETER_TOKEN")

// Token update errors
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_NOT_VALID_CERT_ERR           dap_cli_error_code_get("TOKEN_UPDATE_NOT_VALID_CERT_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_UNKNOWN_TOKEN_TYPE           dap_cli_error_code_get("TOKEN_UPDATE_UNKNOWN_TOKEN_TYPE")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_NO_SUITABLE_CHAIN            dap_cli_error_code_get("TOKEN_UPDATE_NO_SUITABLE_CHAIN")
#define DAP_CHAIN_NODE_CLI_COM_TOKEN_UPDATE_OK                            dap_cli_error_code_get("TOKEN_UPDATE_OK")

// Chain CA publication errors
#define DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_SERIALIZE_MEMORY_CERT_ERR dap_cli_error_code_get("CHAIN_CA_PUB_CANT_SERIALIZE_MEMORY_CERT_ERR")
#define DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_PRODUCE_CERT_ERR          dap_cli_error_code_get("CHAIN_CA_PUB_CANT_PRODUCE_CERT_ERR")
#define DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_OK                              dap_cli_error_code_get("CHAIN_CA_PUB_OK")
#define DAP_CHAIN_NODE_CLI_COM_CHAIN_CA_PUB_CANT_PLACE_CERT_ERR             dap_cli_error_code_get("CHAIN_CA_PUB_CANT_PLACE_CERT_ERR")

// Initialization and cleanup functions
int dap_chain_token_cli_error_codes_init(void);
void dap_chain_token_cli_error_codes_deinit(void);

