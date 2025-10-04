/**
 * @file dap_chain_net_srv_xchange_compose.h
 * @brief Xchange service transaction compose API
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_net_srv_xchange.h"

// Forward declaration
typedef struct compose_config compose_config_t;

/**
 * @brief Register xchange compose callbacks with compose module
 */
int dap_chain_net_srv_xchange_compose_init(void);

// Xchange compose functions (to be moved from compose module)
// TODO: Move implementations from modules/compose/dap_chain_tx_compose.c

