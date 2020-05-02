#pragma once

#include "dap_chain.h"
#include "dap_chain_wallet.h"

void dap_chain_wallet_op_tx_request(dap_chain_wallet_t * a_wallet, uint32_t a_wallet_key_idx, /// Sender's wallet and key index in it
                             dap_chain_t * a_chain_source, uint64_t a_value, /// Token source and daptoshi's value
                             dap_chain_t * a_chain_tx_request, dap_chain_addr_t a_destination ); ///  TX blockchain where to create new block
