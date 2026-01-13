cmake_minimum_required(VERSION 3.10)

# Integration tests - testing module interactions

# Ledger integration tests (includes chain/ledger interaction tests)
add_subdirectory(ledger)

# Blocks tests (integration with chain)
add_subdirectory(blocks)

# Stake-ext tests
add_subdirectory(service)
