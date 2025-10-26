# Cellframe SDK

Core SDK for Cellframe blockchain platform development.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Recent Additions](#recent-additions)
- [Building](#building)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## 🌟 Overview

Cellframe SDK provides the foundational libraries and tools for building blockchain applications on the Cellframe network. It includes consensus mechanisms, chain management, token systems, network protocols, and cryptographic primitives.

## ✨ Features

### Core Blockchain
- Multi-chain architecture
- Multiple consensus mechanisms (PoA, PoS, etc.)
- DAG (Directed Acyclic Graph) support
- Transaction processing and validation
- Mempool management

### Token System
- **CF20 Tokens**: Native token standard with advanced features
- **UTXO Blocking**: Fine-grained control over unspent outputs (NEW in v2.1)
- Token emission and management
- Vesting and lock-up support
- Address-based permissions
- Delegation mechanisms

### Networking
- P2P protocol
- Global database (GDB) synchronization
- Network decree system
- Service infrastructure

### Security & Cryptography
- Post-quantum cryptography support (Kyber, Falcon, SPHINCS+)
- Multi-signature schemes
- Certificate-based authentication
- Hash functions and encryption

## 🆕 Recent Additions

### UTXO Blocking Mechanism (v2.1)

The latest release introduces a powerful UTXO (Unspent Transaction Output) blocking mechanism for CF20 tokens, enabling token issuers to prevent specific outputs from being spent.

**Key Features:**
- ✅ **Enabled by default** for all CF20 tokens (opt-out security model)
- 🕐 **Delayed activation**: Schedule blocking to activate at a future blockchain time
- ⏰ **Automatic expiration**: UTXOs can auto-unblock after a specified time
- 🔒 **Immutable blocklists**: Lock blocklists permanently with `STATIC_UTXO_BLOCKLIST`
- 🚀 **High performance**: O(1) lookup using hash tables, thread-safe implementation
- 🎯 **Independent control**: Separate from address-based blocking

**Use Cases:**
- Vesting schedules for team/investor allocations
- Escrow services
- Security incident response
- Regulatory compliance
- ICO/IDO token distribution

**Quick Example:**
```bash
# Block a specific UTXO
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -utxo_blocked_add 0x1234...abcd:0 \
    -certs owner_cert

# Schedule automatic unblocking after 6 months
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -utxo_blocked_remove 0x1234...abcd:0:1733097600 \
    -certs owner_cert
```

📖 **Full Documentation:** [docs/UTXO_BLOCKING_EXAMPLES.md](docs/UTXO_BLOCKING_EXAMPLES.md)

## 🛠️ Building

### Prerequisites

- GCC 7+ or Clang 6+
- CMake 3.10+
- OpenSSL development libraries
- pthread
- Python 3.7+ (for Python bindings)

### Build Instructions

```bash
# Clone the repository
git clone https://gitlab.demlabs.net/cellframe/cellframe-sdk.git
cd cellframe-sdk

# Create build directory
mkdir -p build && cd build

# Configure with CMake
cmake ..

# Build
make -j$(nproc)

# Optional: Build tests
cmake -DBUILD_TESTS=On ..
make -j$(nproc)

# Run tests
ctest --output-on-failure
```

### Build Options

- `BUILD_TESTS=On`: Enable test infrastructure (unit tests, integration tests)
- `BUILD_DIAGTOOL=On`: Build diagnostic tools
- `BUILD_PYTHON_MODULES=On`: Build Python bindings

## 📚 Documentation

### API Documentation
- **Token System**: [modules/common/include/dap_chain_datum_token.h](modules/common/include/dap_chain_datum_token.h)
- **Ledger**: [modules/net/include/dap_chain_ledger.h](modules/net/include/dap_chain_ledger.h)
- **Chains**: [modules/chain/](modules/chain/)
- **Consensus**: [modules/consensus/](modules/consensus/)

### User Guides
- **UTXO Blocking**: [docs/UTXO_BLOCKING_EXAMPLES.md](docs/UTXO_BLOCKING_EXAMPLES.md)
- **Changelog**: [Changelog](Changelog)

### CLI Reference
Use `cellframe-node-cli help <command>` for detailed command documentation:
```bash
cellframe-node-cli help token_decl
cellframe-node-cli help token_update
cellframe-node-cli help token
```

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. **Code Quality**:
   - Follow [DAP SDK Coding Standards](.context/modules/standards/dap_sdk_coding_standards.json)
   - Use snake_case naming conventions
   - Add doxygen comments for public APIs

2. **Testing**:
   - Add unit tests for new features (`tests/unit/`)
   - Add integration tests for complex scenarios (`tests/integration/`)
   - Ensure all tests pass before submitting PR

3. **Documentation**:
   - Update API documentation (doxygen comments)
   - Update CLI help text if commands change
   - Add usage examples for new features
   - Update Changelog

## 📄 License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

---

## 🔗 Links

- **Main Project**: [cellframe-node](https://gitlab.demlabs.net/cellframe/cellframe-node)
- **DAP SDK**: [dap-sdk](dap-sdk/)
- **Website**: [cellframe.net](https://cellframe.net)
- **Documentation**: [docs.cellframe.net](https://docs.cellframe.net)

## 📞 Support

For support, questions, or feedback:
- Open an issue on GitLab
- Join our community channels
- Contact the development team

---

**Note**: This is the core SDK. For the complete node software, see [cellframe-node](https://gitlab.demlabs.net/cellframe/cellframe-node).
