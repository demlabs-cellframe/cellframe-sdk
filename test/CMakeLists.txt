cmake_minimum_required(VERSION 3.4.1)

project(dap_global_db_test)

IF (NOT DEFINED DAP_SDK_ROOT)
    SET(DAP_SDK_ROOT    "${CMAKE_CURRENT_SOURCE_DIR}/../../cellframe-sdk")
    SET(DAP_LIBSDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../build")
ENDIF()

ADD_DEFINITIONS(-DDAP_SDK_ROOT=${DAP_SDK_ROOT})
ADD_DEFINITIONS(-DDAP_LIBSDK_ROOT=${DAP_LIBSDK_ROOT})

message(STATUS "Current DAP SDK path is '${DAP_SDK_ROOT}'. 
	Add '-DDAP_SDK_ROOT=<path_to_sdk>' to cmake if want to change path")
message(STATUS "Current DAP SDK Library path is '${DAP_LIBSDK_ROOT}'. 
	Add '-DDAP_LIBSDK_ROOT=<path_to_sdk_library>' to cmake if want to change path")

include_directories(
        ${DAP_SDK_ROOT}/dap-sdk/net/core/include/
        ${DAP_SDK_ROOT}/dap-sdk/crypto/src/sha3/
        ${DAP_SDK_ROOT}/dap-sdk/crypto/include/
        ${DAP_SDK_ROOT}/modules/common/include/
        ${DAP_SDK_ROOT}/modules/global-db/include/
	${DAP_SDK_ROOT}/dap-sdk/net/core/include/
	${DAP_SDK_ROOT}/dap-sdk/core/include/
	${DAP_SDK_ROOT}/dap-sdk/core/src/unix/
	${DAP_SDK_ROOT}/dap-sdk/crypto/src/XKCP/lib/common
	${DAP_SDK_ROOT}/3rdparty/uthash/src/
	)

link_directories(
	${DAP_LIBSDK_ROOT}/dap-sdk/core/
	${DAP_LIBSDK_ROOT}/dap-sdk/net/core/
	)

add_executable(dap_global_db_test dap_global_db_test.c)

target_compile_definitions(dap_global_db_test PRIVATE
        -DCELLFRAME_SDK_VERSION="3.0-15"
        -DDAP_MODULES_DYNAMIC=1
        -DDAP_OS_LINUX=1
        -DDAP_OS_UNIX=1
        -DDAP_SRV_STAKE_USED=1
        -DDAP_VERSION="5-0.26"
        -D_GNU_SOURCE=1
        )


target_link_libraries(dap_global_db_test -pthread -lrt)

target_link_libraries(dap_global_db_test  ${DAP_LIBSDK_ROOT}/modules/global-db/libdap_chain_global_db.a)
target_link_libraries(dap_global_db_test  ${DAP_LIBSDK_ROOT}/dap-sdk/crypto/libdap_crypto.a)
target_link_libraries(dap_global_db_test  ${DAP_LIBSDK_ROOT}/dap-sdk/net/core/libdap_server_core.a)
target_link_libraries(dap_global_db_test  ${DAP_LIBSDK_ROOT}/dap-sdk/core/libdap_core.a)
target_link_libraries(dap_global_db_test  ${DAP_LIBSDK_ROOT}/3rdparty/cuttdb/libdap_cuttdb.a)
target_link_libraries(dap_global_db_test -lsqlite3)

target_link_libraries(dap_global_db_test -pthread -lrt -lm -latomic)
