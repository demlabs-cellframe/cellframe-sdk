cmake_minimum_required(VERSION 3.0)
project (dap_core)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

set(CMAKE_C_FLAGS "-std=c11 -Wall -Wextra")



file(GLOB CORE_SRCS src/*.c)
file(GLOB CORE_HEADERS include/*.h include/unix/*.h include/unix/linux/*.h )

add_library(${PROJECT_NAME} STATIC ${CORE_SRCS} ${CORE_UNIX_SRCS})

#This paths will be used by project-dependent project libraries
target_include_directories(${PROJECT_NAME} INTERFACE include/)

if ( ${CMAKE_SYSTEM_NAME} MATCHES "Linux" )
    set(LINUX "Linux")
endif()

if(UNIX)
    add_subdirectory(src/unix)
    target_link_libraries(${PROJECT_NAME} dap_core_unix)
endif()

if(DARWIN)
    add_subdirectory(src/darwin)
    target_link_libraries(${PROJECT_NAME} dap_core_darwin)
endif()


if(BUILD_DAP_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

