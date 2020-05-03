add_subdirectory(app-cli)
add_subdirectory(chain)
add_subdirectory(common)
add_subdirectory(mining)
add_subdirectory(wallet)
add_subdirectory(mempool)
add_subdirectory(net)
add_subdirectory(net/srv)
add_subdirectory(global-db)

# Consensus types
add_subdirectory(type/dag)
#add_subdirectory(type/block)

# Consensuses
add_subdirectory(consensus/none)
#add_subdirectory(consensus/block-pow)
#add_subdirectory(consensus/block-poa)
add_subdirectory(consensus/dag-pos)
add_subdirectory(consensus/dag-poa)

# Stream channels
add_subdirectory(channel/chain)
add_subdirectory(channel/chain-net)
add_subdirectory(channel/chain-net-srv)

# Services 
if(NOT (WIN32))
  add_subdirectory(service/vpn)
endif()

add_subdirectory(service/app)
add_subdirectory(service/app-db)
add_subdirectory(service/datum)
add_subdirectory(service/mining-pool)


