cmake_minimum_required(VERSION 3.10)

project (dap_core_darwin)

file(GLOB CORE_DARWIN_SRCS *.c)
file(GLOB CORE_DARWIN_HEADERS *.h)

if(DARWIN)
    file(GLOB CORE_MACOS_SRCS macos/*.c)
    file(GLOB CORE_MACOS_HEADERS macos/*.h)
endif()

add_library(${PROJECT_NAME} STATIC ${CORE_DARWIN_SRCS} ${CORE_DARWIN_HEADERS}
    ${CORE_MACOS_SRCS} ${CORE_MACOS_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core pthread)

