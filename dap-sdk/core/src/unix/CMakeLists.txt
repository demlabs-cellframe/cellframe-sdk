cmake_minimum_required(VERSION 3.10)

project (dap_core_unix)

file(GLOB CORE_UNIX_SRCS *.c)
file(GLOB CORE_UNIX_HEADERS *.h)

if(LINUX)
    file(GLOB CORE_LINUX_SRCS linux/*.c)
    file(GLOB CORE_LINUX_HEADERS linux/*.h)
endif()

add_library(${PROJECT_NAME} STATIC ${CORE_UNIX_SRCS} ${CORE_UNIX_HEADERS}
    ${CORE_LINUX_SRCS} ${CORE_LINUX_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core)

if (ANDROID)
    target_link_libraries(${PROJECT_NAME} dap_core_android)
else()
    target_link_libraries(${PROJECT_NAME} pthread)
endif()

target_include_directories(dap_core_unix INTERFACE .)

if(LINUX)
    target_include_directories(dap_core_unix INTERFACE ./linux)
endif()

