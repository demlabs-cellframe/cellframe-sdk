set(DAP_SDK_NATIVE_VERSION "2.2-1")
# Core, add it always
add_subdirectory(core)
if (DAPSDK_MODULES MATCHES "crypto")
    # Cryptography
    add_subdirectory(crypto)
endif()

# Networking core
if (DAPSDK_MODULES MATCHES "network-core")
    add_subdirectory(net/core)
    add_subdirectory(net/stream)
endif()

if (DAPSDK_MODULES MATCHES "network-pure")
    add_subdirectory(net/core)
endif()

# Networking client
if (DAPSDK_MODULES MATCHES "network-client")
    add_subdirectory(net/client)
endif()

# Networking server
if (DAPSDK_MODULES MATCHES "network-server")
    add_subdirectory(net/server)
#    add_subdirectory(net/server-udp)
endif()
