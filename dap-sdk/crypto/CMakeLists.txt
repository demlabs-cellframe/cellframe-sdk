cmake_minimum_required(VERSION 3.0)
project (dap_crypto)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

file( GLOB CRYPTO_SRCS
      src/*.c
      src/rand/*.c
      src/iaes/*.c
      src/oaes/*.c
      src/blowfish/*.c
      src/GOST/*.c
      src/salsa2012/*.c
      src/seed/*.c
      src/sha3/*.c
      src/msrln/*.c
      src/defeo_scheme/*.c
      src/newhope/*.c
      src/sig_bliss/*.c
      src/sig_tesla/*.c
      src/sig_picnic/*.c
      src/sig_dilithium/*.c
      src/ringct20/*.c
)

file( GLOB CRYPTO_HEADERS
      src/*.h
      src/rand/*.h
      src/iaes/*.h
      src/oaes/*.h
      src/blowfish/*.h
      src/GOST/*.h
      src/salsa2012/*.h
      src/seed/*.h
      src/sha3/*.h
      src/msrln/*.h
      src/defeo_scheme/*.h
      src/newhope/*.h
      src/sig_bliss/*.h
      src/sig_tesla/*.h
      src/sig_picnic/*.h
      src/sig_dilithium/*.h
      src/ringct20/*.h
      include/*.h
)

enable_language(ASM)

file( GLOB XKCP_SRCS
  #src/XKCP/lib/high/Keccak/FIPS202/KeccakHash.c
  #src/XKCP/lib/high/Keccak/KeccakSpongeWidth1600.c
  src/XKCP/lib/high/Keccak/SP800-185/SP800-185.c
  src/XKCP/lib/high/Keccak/FIPS202/SimpleFIPS202.c
)

if(WIN32)
  if(BUILD_64)
    #file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64/KeccakP-1600-x86-64-gas.s ) - SIGSEGV on MinGW
    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Compact64/KeccakP-1600-compact64.c )
  else()
    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Inplace32BI/KeccakP-1600-inplace32BI.c )
  endif()
endif()

if(UNIX)
    if (LINUX)
	if(DAP_DEBUG)
	    if(BUILD_64)
		file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Compact64/KeccakP-1600-compact64.c )
    	    else()
		file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Inplace32BI/KeccakP-1600-inplace32BI.c )
    	    endif()
	endif()
    elseif(APPLE)
	if(BUILD_64)
	    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64/KeccakP-1600-x86-64-gas_Apple.s )
	else()
	    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Inplace32BI/KeccakP-1600-inplace32BI.c )
	endif()
    elseif(BSD)
	if(BUILD_64)
            file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Compact64/KeccakP-1600-compact64.c )
	else()
	    file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Inplace32BI/KeccakP-1600-inplace32BI.c )
        endif()
    else()
	file( GLOB XKCP_SRCS2 src/XKCP/lib/low/KeccakP-1600/Inplace32BI/KeccakP-1600-inplace32BI.c )
    endif()

endif()





add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS} ${XKCP_SRCS} ${XKCP_SRCS2} ${CRYPTO_HEADERS} )

target_include_directories(dap_crypto PRIVATE src/seed src/rand src/iaes src/oaes src/sha3 src/msrln src/defeo_scheme src/sig_bliss src/sig_tesla src/sig_picnic src/sig_dilithium src include)
target_include_directories(dap_crypto INTERFACE src/ src/sha3 include/)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/uthash/src)

target_include_directories(dap_crypto PUBLIC
        src/XKCP/lib/common
        src/XKCP/lib/low/common
        src/XKCP/lib/high/Keccak
        src/XKCP/lib/high/common
        src/XKCP/lib/high/Keccak/FIPS202
        src/XKCP/lib/high/Keccak/SP800-185
        src/XKCP/lib/low/KeccakP-1600/Optimized
)

if(WIN32)
  if(BUILD_64)

    #target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64)
    target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600/Compact64)

    if (__AVX__)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/SIMD256)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX2ufull)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn4)
    elseif(__AVX2__)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/SIMD512)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/SIMD512)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/SIMD512)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/SIMD512/AVX512ufull)
    elseif(__SSE4_1__)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/SIMD128)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/SIMD128/SSE2ufull)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn2)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn2)
    else()
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/FallbackOn1)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn1)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn1)
    endif()

  else()
    target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600/Inplace32BI)

    if (__AVX__)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/SIMD256)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX2ufull)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn4)
    elseif(__AVX2__)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/SIMD512)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/SIMD512)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/SIMD512)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/SIMD512/AVX512ufull)
    elseif(__SSE4_1__)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/SIMD128)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/SIMD128/SSE2ufull)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn2)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn2)
    else()
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times2/FallbackOn1)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn1)
        target_include_directories(dap_crypto PUBLIC src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn1)
    endif()
  endif()
endif()

if(UNIX)
  if(BUILD_64)
    target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64)
    target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600/OptimizedAsmX86-64)

    if(__AVX2__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/SIMD512)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/SIMD512)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/SIMD512/AVX512ufull)
    elseif(__SSE4_1__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/SIMD128)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/SIMD128/SSE2ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/SIMD128)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/SIMD128/SSE2ufull)
    else()
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/FallbackOn1)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/FallbackOn1)
    endif()

    if(__AVX2__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX512ufull)
    elseif(__AVX__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/SIMD256)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX2ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/SIMD256)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX2ufull)
    elseif(__SSE4_1__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn2)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn2)
    else()
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn1)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn1)
    endif()

    if(__AVX2__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/SIMD512)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/SIMD512)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/SIMD512/AVX512ufull)
    elseif(__AVX__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn4)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn4)
    elseif(__SSE4_1__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn2)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn2)
    else()
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn1)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn1)
    endif()

  else()
    target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600/Inplace32BI)
    target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600/Inplace32BI)

    if(__AVX2__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/SIMD512)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/SIMD512)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/SIMD512/AVX512ufull)
    elseif(__SSE4_1__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/SIMD128)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/SIMD128/SSE2ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/SIMD128)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/SIMD128/SSE2ufull)
    else()
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times2/FallbackOn1)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times2/FallbackOn1)
    endif()

    if(__AVX2__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX512ufull)
    elseif(__AVX__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/SIMD256)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX2ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/SIMD256)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/SIMD512/AVX2ufull)
    elseif(__SSE4_1__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn2)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn2)
    else()
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn1)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times4/FallbackOn1)
    endif()

    if(__AVX2__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/SIMD512)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/SIMD512/AVX512ufull)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/SIMD512)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/SIMD512/AVX512ufull)
    elseif(__AVX__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn4)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn4)
    elseif(__SSE4_1__)
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn2)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn2)
    else()
        target_include_directories(dap_crypto INTERFACE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn1)
        target_include_directories(dap_crypto PRIVATE src/XKCP/lib/low/KeccakP-1600-times8/FallbackOn1)
    endif()

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
