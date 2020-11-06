project (libsatoshi-script-tpl)
  
file(GLOB DAP_SATOSHI_TPL_SRCS dap_satoshi_tpl.c)
file(GLOB DAP_SATOSHI_TPL_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_SATOSHI_TPL_SRCS} ${DAP_SATOSHI_TPL_HEADERS})
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core  )

add_executable(satoshi-script-tpl satoshi-script-tpl.c )
target_link_libraries(satoshi-script-tpl dap_core pthread )
target_include_directories(satoshi-script-tpl INTERFACE .)

