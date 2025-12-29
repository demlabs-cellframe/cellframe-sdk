#!/bin/bash

# Mempool
cd mempool
sed -i 's|#include "dap_chain_node.h"|#include "dap_chain_net_core.h"|g' dap_chain_mempool_cli.c
echo "✅ Mempool CLI → uses net-core"

# Ledger  
cd ../ledger
sed -i 's|#include "dap_chain_node.h"|#include "dap_chain_net_core.h"|g' dap_chain_ledger_cli.c
echo "✅ Ledger CLI → uses net-core"

# Net
cd ../net
sed -i 's|#include "dap_chain_node.h"|#include "dap_chain_net_core.h"|g' dap_chain_net_cli.c
sed -i '26i #include "dap_chain_net_core.h"' dap_chain_net_cli.c 2>/dev/null
echo "✅ Net CLI → uses net-core"

# Chain - переносим в net-tx!
cd ../net-tx
mkdir -p token_cli
echo "✅ Preparing net-tx for token CLI"

echo ""
echo "🎯 Архитектура:"
echo "   net-core (low-level utils) ← mempool CLI, ledger CLI, net CLI"
echo "   net-tx (high-level) ← token CLI (будет перенесено)"
