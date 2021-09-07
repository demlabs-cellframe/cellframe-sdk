project(mega_headers C)

file(GLOB DAP_MEGA_HEADERS dap_core.h)
file(GLOB DAP_MEGA_SRCS dap_core.c)

add_library(${PROJECT_NAME} STATIC ${DAP_MEGA_HEADERS} ${DAP_MEGA_SRCS})
