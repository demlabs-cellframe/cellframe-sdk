cmake_minimum_required(VERSION 3.0)
project (dap_crypto)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

set(CMAKE_C_FLAGS "-std=c11 -Wall -Wextra -fPIC -fno-pie -no-pie")
set(CMAKE_ASM_FLAGS "-std=c11 -Wall -Wextra -fPIC -fno-pie -no-pie")

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))

  # Check whether we're on a 32-bit or 64-bit system
  if(CMAKE_SIZEOF_VOID_P EQUAL "8")
    set(DEFAULT_BUILD_64 ON)
  else()
    set(DEFAULT_BUILD_64 OFF)
  endif()
  option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ${DEFAULT_BUILD_64})

  add_definitions ("-DDAP_SERVER")
  add_definitions ("-DNODE_NETNAME=\"kelvin\"")

  set(_CCOPT "-Wall -pg -fPIC -fno-pie -no-pie")
  set(_LOPT "-pg")
  SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
  set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${_LOPT}")

  if (NOT (TARGET dap_core))
    add_subdirectory(libdap)
  endif()
endif()

file( GLOB CRYPTO_SRCS 
      src/*.c 
      src/rand/*.c 
      src/iaes/*.c 
      src/oaes/*.c 
      src/sha3/*.c 
      src/msrln/*.c 
      src/defeo_scheme/*.c 
      src/sig_bliss/*.c 
      src/sig_tesla/*.c 
      src/sig_picnic/*.c
)

file( GLOB CRYPTO_HEADERS 
      src/*.h 
      src/rand/*.h 
      src/iaes/*.h 
      src/oaes/*.h 
      src/sha3/*.h 
      src/msrln/*.h 
      src/defeo_scheme/*.h 
      src/sig_bliss/*.h 
      src/sig_tesla/*.h 
      src/sig_picnic/*.h 
      include/*.h
)

enable_language(ASM)

file( GLOB XKCP_SRCS 
  src/XKCP/lib/high/Keccak/FIPS202/KeccakHash.c
  src/XKCP/lib/high/Keccak/FIPS202/SimpleFIPS202.c
  src/XKCP/lib/high/Keccak/KeccakSpongeWidth1600.c
)

if(WIN32)
  if(BUILD_64)
    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64/win32/KeccakP-1600-x86-64-gas.s )
  else()
    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Inplace32BI/KeccakP-1600-inplace32BI.c )
  endif()
endif()

if(UNIX)
  if(BUILD_64)
    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64/KeccakP-1600-x86-64-gas.s )
  else()
    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Inplace32BI/KeccakP-1600-inplace32BI.c )
  endif()
endif()

add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS} ${XKCP_SRCS} ${XKCP_SRCS2} ${CRYPTO_HEADERS} )

target_include_directories(dap_crypto PRIVATE src/rand src/iaes src/oaes sha3 src/msrln src/defeo_scheme src/sig_bliss src/sig_tesla src/sig_picnic src include)
target_include_directories(dap_crypto INTERFACE src/ src/sha3 include/)

target_include_directories(dap_crypto INTERFACE src/XKCP/lib/common)
target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/common)
target_include_directories(dap_crypto INTERFACE src/XKCP/lib/high/Keccak)
target_include_directories(dap_crypto INTERFACE src/XKCP/lib/high/Keccak/FIPS202)
target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600/Optimized)
target_include_directories(dap_crypto PRIVATE src/XKCP/lib/common)
target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/common)
target_include_directories(dap_crypto PRIVATE src/XKCP/lib/high/Keccak)
target_include_directories(dap_crypto PRIVATE src/XKCP/lib/high/Keccak/FIPS202)
target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600/Optimized)

if(WIN32)
  if(BUILD_64)
    target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64/win32)
    target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64/win32)
  else()
    target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600/Inplace32BI)
    target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600/Inplace32BI)
  endif()
endif()

if(UNIX)
  if(BUILD_64)
    target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64)
    target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64)
  else()
    target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600/Inplace32BI)
    target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600/Inplace32BI)
  endif()
endif()

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
