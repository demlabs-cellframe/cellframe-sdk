#include "dap_chain_types.h"
#include "dap_strfuncs.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_types"

dap_chain_type_t dap_chain_type_from_str(const char *a_type_str)
{
    if(!dap_strcmp(a_type_str, "token")) {
        return CHAIN_TYPE_TOKEN;
    }
    if(!dap_strcmp(a_type_str, "emission")) {
        return CHAIN_TYPE_EMISSION;
    }
    if(!dap_strcmp(a_type_str, "transaction")) {
        return CHAIN_TYPE_TX;
    }
    if(!dap_strcmp(a_type_str, "ca")) {
        return CHAIN_TYPE_CA;
    }
    if(!dap_strcmp(a_type_str, "signer")) {
	    return CHAIN_TYPE_SIGNER;
    }
    if (!dap_strcmp(a_type_str, "decree"))
        return CHAIN_TYPE_DECREE;
    if (!dap_strcmp(a_type_str, "anchor"))
        return CHAIN_TYPE_ANCHOR;
    return CHAIN_TYPE_INVALID;
}

uint16_t dap_chain_type_to_datum_type(dap_chain_type_t a_type)
{
    switch (a_type) {
    case CHAIN_TYPE_TOKEN: 
        return DAP_CHAIN_DATUM_TOKEN;
    case CHAIN_TYPE_EMISSION:
        return DAP_CHAIN_DATUM_TOKEN_EMISSION;
    case CHAIN_TYPE_TX:
        return DAP_CHAIN_DATUM_TX;
    case CHAIN_TYPE_CA:
        return DAP_CHAIN_DATUM_CA;
	case CHAIN_TYPE_SIGNER:
		return DAP_CHAIN_DATUM_SIGNER;
    case CHAIN_TYPE_DECREE:
        return DAP_CHAIN_DATUM_DECREE;
    case CHAIN_TYPE_ANCHOR:
        return DAP_CHAIN_DATUM_ANCHOR;
    default:
        return DAP_CHAIN_DATUM_CUSTOM;
    }
}

dap_chain_type_t dap_datum_type_to_chain_type(uint16_t a_type)
{
    switch (a_type) {
    case DAP_CHAIN_DATUM_TOKEN: 
        return CHAIN_TYPE_TOKEN;
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:
        return CHAIN_TYPE_EMISSION;
    case DAP_CHAIN_DATUM_TX:
        return CHAIN_TYPE_TX;
    case DAP_CHAIN_DATUM_CA:
        return CHAIN_TYPE_CA;
	case DAP_CHAIN_DATUM_SIGNER:
		return CHAIN_TYPE_SIGNER;
    case DAP_CHAIN_DATUM_DECREE:
        return CHAIN_TYPE_DECREE;
    case DAP_CHAIN_DATUM_ANCHOR:
        return CHAIN_TYPE_ANCHOR;
    default:
        return CHAIN_TYPE_INVALID;
    }
}

const char *dap_chain_type_to_str(dap_chain_type_t a_default_chain_type)
{
    switch (a_default_chain_type)
    {
        case CHAIN_TYPE_INVALID:
            return "invalid";
        case CHAIN_TYPE_TOKEN:
            return "token";
        case CHAIN_TYPE_EMISSION:
            return "emission";
        case CHAIN_TYPE_TX:
            return "transaction";
        case CHAIN_TYPE_CA:
            return "ca";
        case CHAIN_TYPE_SIGNER:
            return "signer";
        case CHAIN_TYPE_DECREE:
            return "decree";
        case CHAIN_TYPE_ANCHOR:
            return "anchor";
        default:
            return "custom";
    }
}

const char *dap_datum_type_to_str(uint16_t a_datum_type)
{
    return dap_chain_type_to_str(dap_datum_type_to_chain_type(a_datum_type));
}

