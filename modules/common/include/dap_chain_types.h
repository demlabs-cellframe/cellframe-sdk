/*
 * Datum type identifiers
 * Shared constants for chain and datum modules to break circular dependencies
 */

#pragma once
#include <stdint.h>

// Block structure markers
#define DAP_CHAIN_DATUM_BLOCK_END           0x0000
#define DAP_CHAIN_DATUM_BLOCK_ROOTS         0x0001

// Transaction types
#define DAP_CHAIN_DATUM_TX                  0x0100
#define DAP_CHAIN_DATUM_TX_REQUEST          0x0300

// Governance
#define DAP_CHAIN_DATUM_DECREE              0x0200

// Smart contracts
#define DAP_CHAIN_DATUM_WASM_CODE           0x0900
#define DAP_CHAIN_DATUM_WASM_DATA           0x0901
#define DAP_CHAIN_DATUM_EVM_CODE            0x0910
#define DAP_CHAIN_DATUM_EVM_DATA            0x0911

// Certificate authority
#define DAP_CHAIN_DATUM_CA                  0x0c00
#define DAP_CHAIN_DATUM_SIGNER              0x0c01

// Token operations
#define DAP_CHAIN_DATUM_TOKEN               0xf000
#define DAP_CHAIN_DATUM_TOKEN_EMISSION      0xf100
#define DAP_CHAIN_DATUM_TOKEN_DISMISSAL     0xf200

// Anchoring
#define DAP_CHAIN_DATUM_ANCHOR              0x0a00

// Service state
#define DAP_CHAIN_DATUM_SERVICE_STATE       0x8000

// Custom datum type
#define DAP_CHAIN_DATUM_CUSTOM              0xffff

// Chain type enum
typedef enum dap_chain_type {
    CHAIN_TYPE_INVALID = -1,
    CHAIN_TYPE_TOKEN = 1,
    CHAIN_TYPE_EMISSION = 2,
    CHAIN_TYPE_TX = 3,
    CHAIN_TYPE_CA = 4,
    CHAIN_TYPE_SIGNER = 5,
    CHAIN_TYPE_DECREE = 7,
    CHAIN_TYPE_ANCHOR = 8,
    CHAIN_TYPE_MAX
} dap_chain_type_t;

#ifdef __cplusplus
extern "C" {
#endif

// Convert chain type enum to datum type constant
uint16_t dap_chain_type_to_datum_type(dap_chain_type_t a_type);

// Convert datum type constant to chain type enum
dap_chain_type_t dap_datum_type_to_chain_type(uint16_t a_type);

const char *dap_chain_type_to_str(dap_chain_type_t a_type);
const char *dap_datum_type_to_str(uint16_t a_datum_type);
dap_chain_type_t dap_chain_type_from_str(const char *a_type_str);

#ifdef __cplusplus
}
#endif
