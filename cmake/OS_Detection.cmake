include_guard(GLOBAL)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(OS_TYPE_DESKTOP ON)
    set(LINUX ON)
    set(UNIX ON)
    EXECUTE_PROCESS( COMMAND cat /etc/os-release COMMAND grep VERSION_CODENAME COMMAND sed s/VERSION_CODENAME=// COMMAND tr -d '\n' OUTPUT_VARIABLE L_DEBIAN_OS_NAME)
    EXECUTE_PROCESS( COMMAND cat /etc/os-release COMMAND grep VERSION_ID COMMAND sed s/VERSION_ID=// COMMAND tr -d '\n' COMMAND sed s/\\x22// COMMAND sed s/\\x22// OUTPUT_VARIABLE L_DEBIAN_OS_VERSION)
    SET(DEBIAN_OS_NAME "${L_DEBIAN_OS_NAME}")
    SET(DEBIAN_OS_VERSION ${L_DEBIAN_OS_VERSION})
    message("[ ] Debian OS ${DEBIAN_OS_VERSION} (${DEBIAN_OS_NAME})")
# check if we're building natively on Android (TERMUX)
    EXECUTE_PROCESS( COMMAND uname -o COMMAND tr -d '\n' OUTPUT_VARIABLE OPERATING_SYSTEM)
    
    execute_process (
                    COMMAND bash -c "awk -F= '/^ID=/{print $2}' /etc/os-release |tr -d '\n' | tr -d '\"'"
                    OUTPUT_VARIABLE DEBIAN_OS_RELEASE_NAME
    )
    
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Android")
    set(ANDROID ON)
    set(UNIX ON)
    set(LINUX OFF)
    set(OS_TYPE_MOBILE ON)
    message("[*] ANDROID build")
    add_definitions(-DANDROID -DDAP_OS_ANDROID)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Win")
    set(OS_TYPE_DESKTOP ON)
endif()

if((CMAKE_BUILD_TYPE STREQUAL "Debug") OR (DAP_DEBUG))
    message("[!] Debug build")
    SET(DAP_DEBUG ON)
else()
    message("[!] Release build")
    SET(DAP_RELEASE ON)
    if((CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo"))
        message("[!] Debug symbols ON")
        SET(DAP_DBG_INFO ON)
    endif()
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL "8")
  set(DEFAULT_BUILD_64 ON)
else()
  set(DEFAULT_BUILD_64 OFF)
endif()
option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ${DEFAULT_BUILD_64})

if(BUILD_64)
  set(ARCH_WIDTH "64")
else()
  set(ARCH_WIDTH "32")
endif()
message(STATUS "[*] Building for a ${ARCH_WIDTH}-bit system")

if(UNIX)
    add_definitions ("-DDAP_OS_UNIX")
    if (APPLE)
        
        EXECUTE_PROCESS( COMMAND whoami COMMAND tr -d '\n' OUTPUT_VARIABLE L_USER)
        EXECUTE_PROCESS( COMMAND echo -n /Users/${L_USER} OUTPUT_VARIABLE L_USERDIR_PATH)
        set (USERDIR_PATH "${L_USERDIR_PATH}")
        add_definitions ("-DDAP_OS_DARWIN -DDARWIN -DDAP_OS_BSD")
        set(DARWIN ON)
        set(BSD ON)
        if (${_CMAKE_OSX_SYSROOT_PATH} MATCHES "MacOS")
            set(MACOS ON)
	    # on macOS "uname -m" returns the architecture (x86_64 or arm64)
	    if (NOT DEFINED MACOS_ARCH)
        
            execute_process(
            COMMAND uname -m
            RESULT_VARIABLE result
            OUTPUT_VARIABLE MACOS_ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            )
        endif()
            add_definitions("-DDAP_OS_MAC -DDAP_OS_MAC_ARCH=${MACOS_ARCH}")
        elseif (${_CMAKE_OSX_SYSROOT_PATH} MATCHES "iOS")
            set(IOS ON)
            add_definitions("-DDAP_OS_IOS")
        else()
            set(MACOS ON)
            add_definitions("-DDAP_OS_MAC -DDAP_OS_MAC_ARCH=${MACOS_ARCH}")
        endif()
    endif()
    
    if (${CMAKE_SYSTEM_NAME} MATCHES "BSD" )
        add_definitions ("-DDAP_OS_BSD")
        set(BSD ON)
    endif()

    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux" )
        add_definitions ("-DDAP_OS_LINUX")
    endif()
    
    set(CFLAGS_WARNINGS "-Wall -Wextra -Werror=sign-compare  -Wno-unused-command-line-argument -Wno-deprecated-declarations -Wno-unused-local-typedefs -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter")
    if (LINUX)
        set(CCOPT_SYSTEM "")
        set(LDOPT_SYSTEM "")
        if(DAP_DEBUG)
            set(_CCOPT "-DDAP_DEBUG ${CFLAGS_WARNINGS} -pg -g3 -ggdb -fno-eliminate-unused-debug-symbols -fno-strict-aliasing")
            set(_LOPT "-pg")
            if (DEFINED ENV{DAP_ASAN})
                message("[!] Address Sanitizer enabled")
                set(_CCOPT "${_CCOPT} -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer -fno-common -O1")
                set(_LOPT "${_LOPT} -fsanitize=address")
            elseif(DEFINED ENV{DAP_MSAN})
                if (CMAKE_C_COMPILER_ID MATCHES ".*[Cc][Ll][Aa][Nn][Gg].*")
                    message("[!] Memory Sanitizer enabled")
                    set(_CCOPT "${_CCOPT} -fsanitize=memory -fPIE -pie -fno-omit-frame-pointer -O2")
                    set(_LOPT "${_LOPT} -fsanitize=memory -fPIE -pie")
                else()
                    message("[!] Memory Sanitizer is not available on this compiler")
                endif()
            elseif(DEFINED ENV{DAP_TSAN})
                message("[!] Thread Sanitizer enabled")
                set(_CCOPT "${_CCOPT} -fsanitize=thread")
                set(_LOPT "${_LOPT} -fsanitize=thread")
            elseif(DEFINED ENV{DAP_UBSAN})
                message("[!] Undefined behaviour Sanitizer enabled")
                set(_CCOPT "${_CCOPT} -fsanitize=undefined -fsanitize=bounds -fno-omit-frame-pointer")
                set(_LOPT "${_LOPT} -fsanitize=undefined")
            endif()
            SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")
        else()
            set(_CCOPT "${CFLAGS_WARNINGS} -O3 -fPIC -fno-strict-aliasing -fno-ident -ffast-math -ftree-vectorize -fno-asynchronous-unwind-tables -ffunction-sections -Wl,--gc-sections -std=gnu11")
            if(NOT DAP_DBG_INFO)
                set(_CCOPT "${_CCOPT} -Wl,--strip-all")
            endif()
        endif()
    elseif (DARWIN)
        set(CCOPT_SYSTEM "-L/usr/local/lib -L/opt/homebrew/lib -I/opt/homebrew/include -I/usr/local/include")
        set(LDOPT_SYSTEM "-L/usr/local/lib -L/opt/homebrew/lib -lintl -flat_namespace")
        set(CCFLAGS_COMMON "-std=c11 ${CFLAGS_WARNINGS}")
        if(DAP_DEBUG)
          set(_CCOPT "${CCOPT_SYSTEM} -DDAP_DEBUG ${CCFLAGS_COMMON} -g3 -ggdb -fno-eliminate-unused-debug-symbols -fno-strict-aliasing")
          set(_LOPT "${LDOPT_SYSTEM}")
          SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
        else()
          set(_CCOPT "${CCOPT_SYSTEM} ${CCFLAGS_COMMON} -O3 -fPIC -fno-strict-aliasing -fno-ident -ffast-math -ftree-vectorize -fno-asynchronous-unwind-tables -ffunction-sections")
          set(_LOPT "${LDOPT_SYSTEM}")
          SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
        endif()
    elseif(BSD)
        set(CCOPT_SYSTEM "-L/usr/local/lib -I/usr/local/include")
        set(LDOPT_SYSTEM "-L/usr/local/lib")
        if(DAP_DEBUG)
          set(_CCOPT "${CCOPT_SYSTEM} -DDAP_DEBUG ${CFLAGS_WARNINGS} -pg -g3 -ggdb -fno-eliminate-unused-debug-symbols -fno-strict-aliasing")
          set(_LOPT "-pg ${LDOPT_SYSTEM} ")
	  SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")
        else()
          set(_CCOPT "${CCOPT_SYSTEM} ${CFLAGS_WARNINGS} -O3 -fPIC -fno-strict-aliasing -fno-ident -ffast-math -ftree-vectorize -fno-asynchronous-unwind-tables -ffunction-sections -std=gnu11")
          set(_LOPT "${LDOPT_SYSTEM} ")
          SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
        endif()
    endif()

    if (ANDROID)
        set(_CCOPT "${_CCOPT} -fforce-enable-int128 -std=gnu11")
        add_definitions ("-DDAP_OS_ANDROID")
        add_definitions ("-DDAP_OS_LINUX")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${_LOPT}")

endif()

if(WIN32)
    message(STATUS "[*] Building for Windows")
    add_definitions ("-DDAP_OS_WINDOWS")
    add_definitions ("-DUNDEBUG")
    add_definitions ("-DWIN32")
    add_definitions ("-D_WINDOWS")
    add_definitions ("-D__WINDOWS__")
    add_definitions ("-D_CRT_SECURE_NO_WARNINGS")
    add_definitions ("-DCURL_STATICLIB")
    add_definitions("-DHAVE_PREAD")
    add_definitions("-DHAVE_MMAP")
    add_definitions("-DHAVE_STRNDUP")
    add_definitions("-DNGHTTP2_STATICLIB")
    add_compile_definitions(WINVER=0x0600 _WIN32_WINNT=0x0600)
    add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)

    set(CCOPT_SYSTEM "")
    set(LDOPT_SYSTEM "")

    if(DAP_DEBUG)
      set(_CCOPT "-mconsole -static -std=gnu11 ${CFLAGS_WARNINGS} -g3 -ggdb -fno-strict-aliasing -fno-eliminate-unused-debug-symbols -pg")
      set(_LOPT "-mconsole -static -pg")
    else()
      set(_CCOPT "-static -std=gnu11 ${CFLAGS_WARNINGS} -O3 -fPIC -fno-ident -ffast-math -fno-strict-aliasing -ftree-vectorize -mfpmath=sse -mmmx -msse2 -fno-asynchronous-unwind-tables -ffunction-sections -Wl,--gc-sections")
      if(NOT DAP_DBG_INFO)
          add_definitions ("-DNDEBUG")
          set(_CCOPT "${_CCOPT} -Wl,--strip-all")
      endif()
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT} ")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${_LOPT}")

    include_directories(../../dap-sdk/3rdparty/uthash/src/)
    include_directories(../../dap-sdk/3rdparty/json-c)
    include_directories(3rdparty/wepoll/)
    #include_directories(libdap-chain-net-srv-vpn/)
endif()
