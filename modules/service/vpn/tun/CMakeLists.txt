cmake_minimum_required(VERSION 3.10)
project(dap_net_tun C)

# Platform-specific source selection
if(UNIX)
    if(APPLE)
        set(TUN_PLATFORM_SOURCES platform/darwin/dap_net_tun.c)
        set(TUN_PLATFORM "Darwin")
    elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD|OpenBSD|NetBSD")
        set(TUN_PLATFORM_SOURCES platform/bsd/dap_net_tun.c)
        set(TUN_PLATFORM "BSD")
    else()
        set(TUN_PLATFORM_SOURCES platform/linux/dap_net_tun.c)
        set(TUN_PLATFORM "Linux")
    endif()
elseif(WIN32)
    set(TUN_PLATFORM_SOURCES platform/windows/dap_net_tun.c)
    set(TUN_PLATFORM "Windows")
endif()

message(STATUS "DAP Net TUN: Building for ${TUN_PLATFORM}")

# Create library
add_library(dap_net_tun STATIC
    ${TUN_PLATFORM_SOURCES}
)

target_include_directories(dap_net_tun PUBLIC
    include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../..
)

target_link_libraries(dap_net_tun
    dap_core
    dap_io
)

# Platform-specific linking
if(WIN32)
    target_link_libraries(dap_net_tun
        ws2_32
        iphlpapi
        wintun  # WinTun library
    )
endif()

# Installation
install(TARGETS dap_net_tun
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES include/dap_net_tun.h
    DESTINATION include/dap/net/tun
)

