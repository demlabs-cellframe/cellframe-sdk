cmake_minimum_required(VERSION 3.10)
project (dap_cache)

file( GLOB CACHE_SRCS
      src/*.c
)

file( GLOB CACHE_HEADERS
      include/*.h
)

add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS} ${CRYPTO_HEADERS} )

target_link_libraries(${PROJECT_NAME} dap_crypto)