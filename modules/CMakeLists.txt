# Common types (header-only, base for all modules - must be first!)
if (CELLFRAME_MODULES MATCHES "chains")
    add_subdirectory(common)
endif()

# Chains
if (CELLFRAME_MODULES MATCHES "chains")
    add_subdirectory(datum)
    add_subdirectory(wallet)          # PURE wallet: keys + signing only
    add_subdirectory(chain)
    add_subdirectory(ledger)
    add_subdirectory(wallet-cache)    # Address cache (depends on ledger + wallet)
    add_subdirectory(wallet-shared)   # Shared TX cache (depends on ledger + mempool + wallet)
    add_subdirectory(governance)      # High-level governance (decree, policies)
endif()

# Node CLI Commands (high-level, depends on all modules - add last to avoid cycles)
# Removed: CLI commands are now defined in their respective modules as separate libraries
if (CELLFRAME_MODULES MATCHES "network")
endif()

# Network
if (CELLFRAME_MODULES MATCHES "network")
    add_subdirectory(mempool)
    # add_subdirectory(policy)  # Disabled - incompatible API (missing ledger functions)
    add_subdirectory(net)  # Contains net/tx and net/srv submodules
endif()


# Network services (contained within net/srv/)
# if (CELLFRAME_MODULES MATCHES "srv")
#     add_subdirectory(net-srv-stake)  # Common stake types (must be before services)
#     add_subdirectory(net-srv)
# endif()

# No consensus
if (CELLFRAME_MODULES MATCHES "cs-none")
    add_subdirectory(type/none)
endif()

# Consensus type dag
if (CELLFRAME_MODULES MATCHES "cs-dag-")
    add_subdirectory(type/dag)
endif()

# DAG PoA
if (CELLFRAME_MODULES MATCHES "cs-dag-poa")
    add_subdirectory(consensus/dag-poa)
endif()

# Consensus type blocks
if (CELLFRAME_MODULES MATCHES "cs-block-" OR CELLFRAME_MODULES MATCHES "cs-esbocs")
    add_subdirectory(type/blocks)
endif()

# Consensus callbacks registry (breaks circular dependencies)
if (CELLFRAME_MODULES MATCHES "cs-")
    add_subdirectory(consensus)
endif()

# ESBOCS
if (CELLFRAME_MODULES MATCHES "cs-esbocs")
    add_subdirectory(consensus/esbocs)
endif()

# Block PoW
if (CELLFRAME_MODULES MATCHES "cs-block-pow")
    add_subdirectory(consensus/block-pow)
endif()

# Service App
if (CELLFRAME_MODULES MATCHES "srv-app")
    add_subdirectory(service/app)
endif()

# Service App DB
if (CELLFRAME_MODULES MATCHES "srv-app-db")
    add_subdirectory(service/app-db)
endif()

# Service Datum
if (CELLFRAME_MODULES MATCHES "srv-datum")
    add_subdirectory(service/datum)
endif()

# Service eXchange
if (CELLFRAME_MODULES MATCHES "srv-xchange")
    add_subdirectory(service/xchange)
endif()

# Service for token staking and PoS delegation
if (CELLFRAME_MODULES MATCHES "srv-stake")
    add_subdirectory(service/stake)
endif()

# Service for polls and voting
if (CELLFRAME_MODULES MATCHES "srv-voting")
    add_subdirectory(service/voting)
endif()

# Service for bridge
if (CELLFRAME_MODULES MATCHES "srv-bridge")
    add_subdirectory(service/bridge)
endif()

# Service for emission rights delegate to wallets consensus
if (CELLFRAME_MODULES MATCHES "srv-emission")
    add_subdirectory(service/emission)
endif()

# Service for stake-ext
if (CELLFRAME_MODULES MATCHES "srv-stake-ext")
    add_subdirectory(service/stake-ext)
endif()

