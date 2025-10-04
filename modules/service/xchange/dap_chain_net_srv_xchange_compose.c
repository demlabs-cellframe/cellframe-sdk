/**
 * @file dap_chain_net_srv_xchange_compose.c
 * @brief Xchange service transaction compose functions
 * 
 * These functions were moved from modules/compose/ to eliminate circular dependencies.
 * Xchange service now provides its own compose logic and registers it with compose module.
 */

#include "dap_common.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_tx_compose_callbacks.h"

#define LOG_TAG "xchange_compose"

// Forward declarations of functions to be moved here

