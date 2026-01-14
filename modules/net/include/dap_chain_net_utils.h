#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_chain_net_types.h"
#include "dap_chain_types.h"


// Set fee for network transaction
bool dap_chain_net_tx_set_fee(dap_chain_net_id_t a_net_id, uint256_t a_value, dap_chain_addr_t a_addr);

dap_chain_t *dap_chain_net_get_default_chain_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type);
