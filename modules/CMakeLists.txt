
# Core
if (CELLFRAME_MODULES MATCHES "core")
    add_subdirectory(common)
endif()

# Chains
if (CELLFRAME_MODULES MATCHES "chains")
    add_subdirectory(chain)
    add_subdirectory(wallet)
endif()

# Distributed Hash Tables (DHT)
if (CELLFRAME_MODULES MATCHES "dht")
    add_subdirectory(dht)
endif()

# Network
if (CELLFRAME_MODULES MATCHES "network")
    add_subdirectory(mempool)
    add_subdirectory(net)
    add_subdirectory(net/srv)
    add_subdirectory(json_rpc)
    # Stream channels
    add_subdirectory(channel/chain)
    add_subdirectory(channel/chain-net)
    add_subdirectory(channel/chain-voting)
endif()

# Mining
if (CELLFRAME_MODULES MATCHES "mining")
    add_subdirectory(mining)
endif()

# Network services
if (CELLFRAME_MODULES MATCHES "srv")
    add_subdirectory(channel/chain-net-srv)
endif()

# Consensus type dag
if (CELLFRAME_MODULES MATCHES "cs-dag-")
    add_subdirectory(type/dag)
endif()

# DAG PoA
if (CELLFRAME_MODULES MATCHES "cs-dag-poa")
    add_subdirectory(consensus/dag-poa)
endif()

# DAG PoS
if (CELLFRAME_MODULES MATCHES "cs-dag-pos")
    add_subdirectory(consensus/dag-pos)
endif()

# Consensus type blocks
if (CELLFRAME_MODULES MATCHES "cs-block-")
    add_subdirectory(type/blocks)
endif()

# Block PoA
if (CELLFRAME_MODULES MATCHES "cs-block-poa")
    add_subdirectory(consensus/block-poa)
endif()

# Block PoS
if (CELLFRAME_MODULES MATCHES "cs-block-pos")
    add_subdirectory(consensus/block-pos)
endif()

# Block TON
if (CELLFRAME_MODULES MATCHES "cs-esbocs")
    add_subdirectory(consensus/esbocs)
endif()

# Block PoW
if (CELLFRAME_MODULES MATCHES "cs-block-pow")
    add_subdirectory(consensus/block-pow)
endif()

# No consensus
if (CELLFRAME_MODULES MATCHES "cs-none")
    add_subdirectory(consensus/none)
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

# Service VPN
if (CELLFRAME_MODULES MATCHES "srv-vpn")
    add_subdirectory(service/vpn)
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