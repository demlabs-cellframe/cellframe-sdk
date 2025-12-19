cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_datum)
  
file(GLOB DAP_CHAIN_NET_SRV_DATUM_SRCS *.c)

file(GLOB DAP_CHAIN_NET_SRV_DATUM_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_SRV_DATUM_SRCS} HEADERS ${DAP_CHAIN_NET_SRV_DATUM_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_chain_net_srv)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_DATUM_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/datum/
        ARCHIVE DESTINATION lib/modules/service/datum/
        PUBLIC_HEADER DESTINATION include/modules/service/datum/
)
endif()