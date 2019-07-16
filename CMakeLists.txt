cmake_minimum_required(VERSION 3.0)
project (dap_crypto)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

set(CMAKE_C_FLAGS "-std=c11 -Wall -Wextra")

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    add_subdirectory(libdap)
endif()

file(GLOB CRYPTO_SRCS src/*.c src/rand/*.c src/iaes/*.c src/oaes/*.c src/sha3/*.c src/msrln/*.c src/defeo_scheme/*.c src/sig_bliss/*.c src/sig_tesla/*.c src/sig_picnic/*.c)
file(GLOB CRYPTO_HEADERS src/*.h src/rand/*.h src/iaes/*.h src/oaes/*.h src/sha3/*.h src/msrln/*.h src/defeo_scheme/*.h src/sig_bliss/*.h src/sig_tesla/*.h src/sig_picnic/*.c include/*.h)

add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS} ${CRYPTO_HEADERS} )

target_include_directories(dap_crypto PRIVATE src/rand src/iaes src/oaes sha3 src/msrln src/defeo_scheme src/sig_bliss src/sig_tesla src/sig_picnic src include)
target_include_directories(dap_crypto INTERFACE src/ src/sha3 include/)

if(WIN32)
  target_link_libraries(dap_crypto dap_core)
endif()

if(UNIX)
  target_link_libraries(dap_crypto dap_core m)
endif()

if(BUILD_CRYPTO_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
