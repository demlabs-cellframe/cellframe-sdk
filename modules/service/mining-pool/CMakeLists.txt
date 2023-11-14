cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_datum_pool)
  
file(GLOB DAP_CHAIN_NET_SRV_DATUM_POOL_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_DATUM_POOL_SRCS} ${DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_chain_net_srv dap_chain_net_srv_datum)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/mining-pool/
        ARCHIVE DESTINATION lib/modules/service/mining-pool/
        PUBLIC_HEADER DESTINATION include/modules/service/mining-pool/
)
endif()