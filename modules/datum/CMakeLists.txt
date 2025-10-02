cmake_minimum_required(VERSION 3.10)
project (dap_chain_datum)
  
file(GLOB DAP_CHAIN_DATUM_SRCS  *.c)
file(GLOB DAP_CHAIN_DATUM_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_DATUM_SRCS} HEADERS ${DAP_CHAIN_DATUM_HEADERS})

if(BUILD_CELLFRAME_SDK_TESTS)
    add_subdirectory(tests)
endif()

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_global_db dap_json_rpc dap_common dap_chain)
target_include_directories(${PROJECT_NAME} PUBLIC include/ )


if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_DATUM_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/datum/
        ARCHIVE DESTINATION lib/modules/datum/
        PUBLIC_HEADER DESTINATION include/modules/datum/
)
endif()
