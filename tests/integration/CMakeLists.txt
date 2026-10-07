# Integration Tests
#
# Contains subdirectories with integration test suites for various modules.

cmake_minimum_required(VERSION 3.10)

# DEX module integration tests
add_subdirectory(dex)

# Cached ledger: incremental fill and resume across restarts
add_subdirectory(ledger_cache)

# UTXO blocking integration tests
add_subdirectory(utxo_blocking)

# CLI backpressure / dead-client-check integration tests (talk to the CLI server over a unix socket)
if(NOT WIN32)
    add_subdirectory(cli_backpressure)
endif()
