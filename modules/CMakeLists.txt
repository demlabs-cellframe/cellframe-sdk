# Core
if (CELLFRAME_MODULES MATCHES "core")
    add_subdirectory(common)
    add_subdirectory(app-cli)
endif()

# Chains
if (CELLFRAME_MODULES MATCHES "chains")
    add_subdirectory(chain)
    add_subdirectory(wallet)
    add_subdirectory(global-db)
endif()

# Network
if (CELLFRAME_MODULES MATCHES "network")
    add_subdirectory(mempool)
    add_subdirectory(net)
    # Stream channels
    add_subdirectory(channel/chain)
    add_subdirectory(channel/chain-net)
    add_subdirectory(channel/chain-net-srv)
endif()

# Mining
if (CELLFRAME_MODULES MATCHES "mining")
    add_subdirectory(mining)
endif()

# Network services
if (CELLFRAME_MODULES MATCHES "srv")
    add_subdirectory(net/srv)
endif()

# Consensus type dag
if (CELLFRAME_MODULES MATCHES "cs-dag")
    add_subdirectory(type/dag)
endif()

# Consensus type dag
if (CELLFRAME_MODULES MATCHES "cs-block")
    add_subdirectory(type/block)
endif()

# No consensus
if (CELLFRAME_MODULES MATCHES "cs-none")
    add_subdirectory(consensus/none)
endif()

# DAG PoA
if (CELLFRAME_MODULES MATCHES "cs-dag-poa")
    add_subdirectory(consensus/dag-poa)
endif()

# DAG PoS
if (CELLFRAME_MODULES MATCHES "cs-dag-pos")
    add_subdirectory(consensus/dag-pos)
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
