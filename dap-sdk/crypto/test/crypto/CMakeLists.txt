cmake_minimum_required(VERSION 3.10)

project(crypto-test)
# init CellFrame SDK
add_definitions("-DDAP_VERSION=\"${CPACK_PACKAGE_VERSION_MAJOR}-${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}\"")
set(SUBMODULES_NO_BUILD ON)
include (cellframe-sdk/cmake/OS_Detection.cmake)
set(DAPSDK_MODULES "core crypto network-core network-client network-server")

# There is no need, as it was added in cellframe-sdk/CMakeLists.txt

#if( DARWIN)
#    add_subdirectory(cellframe-sdk/3rdparty/json-c-darwin)
#    add_subdirectory(cellframe-sdk/3rdparty/libmagic-darwin)
#    include_directories(cellframe-sdk/3rdparty/json-c-darwin)
#endif()
#if (ANDROID)
#    add_subdirectory(cellframe-sdk/3rdparty/libmagic)
#    add_subdirectory(cellframe-sdk/3rdparty/json-c)
#    include_directories(cellframe-sdk/cellframe-sdk/3rdparty/)
#endif()

#add_subdirectory(cellframe-sdk/dap-sdk)
#enable_testing()
#add_subdirectory(test)


if ( NOT ( TARGET dap_core ) )
    #add_subdirectory(libdap)
endif()

if ( NOT ( TARGET dap_test ) )
    #add_subdirectory(libdap-test)
endif()

file(GLOB SRC *.h *.c)

add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} dap_test dap_core dap_crypto m)

add_test(
    NAME crypto-test
    COMMAND crypto-test
)
