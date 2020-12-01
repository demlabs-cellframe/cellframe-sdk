set(DAP_SDK_NATIVE_VERSION "2.0-14")
# Core 
if (DAPSDK_MODULES MATCHES "core")
    # Core
    add_subdirectory(core)
endif()
if (DAPSDK_MODULES MATCHES "crypto")
    # Cryptography
    add_subdirectory(crypto)
endif()

# Networking core
if (DAPSDK_MODULES MATCHES "network-core")
    add_subdirectory(net/core)
    add_subdirectory(net/stream)
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
