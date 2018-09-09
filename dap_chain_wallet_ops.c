#include "dap_chain_common.h"
#include "dap_chain_wallet_ops.h"
#include "dap_chain_block_txs.h"

/**
 * @brief dap_chain_wallet_op_tx_request
 * @param a_wallet Sender's wallet
 * @param a_wallet_key_idx Key index in the wallet
 * @param a_chain_source Blockchain which token we send from
 * @param a_value Amount of daptoshi's that we wish to send
 * @param a_chain_tx_request Blockhain where we want to record our transaction request
 * @param a_destination Destination address
 */
void dap_chain_wallet_op_tx_request(dap_chain_wallet_t * a_wallet, uint32_t a_wallet_key_idx,
                             dap_chain_t * a_chain_source, uint64_t a_value, /// Token source and daptoshi's value
                             dap_chain_t * a_chain_tx_request, dap_chain_addr_t a_destination ) ///  TX blockchain where to create new block
{

}
