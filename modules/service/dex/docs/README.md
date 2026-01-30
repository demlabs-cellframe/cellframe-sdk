# DEX v2 Documentation

## Overview

DEX v2 is a decentralized exchange service for the Cellframe network, enabling trustless token trading with on-chain order matching and execution.

## Documentation Structure

| Document | Description |
|----------|-------------|
| [01_TERMINOLOGY.md](01_TERMINOLOGY.md) | Core concepts, data types, and terminology |
| [02_FEE_SYSTEM.md](02_FEE_SYSTEM.md) | Fee types, calculation, and configuration |
| [03_STORAGE.md](03_STORAGE.md) | Caching architecture and data structures |
| [04_MATCHING.md](04_MATCHING.md) | Order matching engine and execution |
| [05_VERIFICATION.md](05_VERIFICATION.md) | Transaction validation and security |
| [06_CLI_REFERENCE.md](06_CLI_REFERENCE.md) | Command-line interface reference |
| [07_CONFIGURATION.md](07_CONFIGURATION.md) | Node configuration and governance |
| [08_API_REFERENCE.md](08_API_REFERENCE.md) | C API functions and error codes |
| [09_MIGRATION_SYNC.md](09_MIGRATION_SYNC.md) | SRV_XCHANGE -> SRV_DEX migration notes |

## Quick Start

### Enable DEX Service

Add to `cellframe-node.cfg`:

```ini
[srv_dex]
cache_enabled=true
history_cache=true
debug_more=true
```

### Whitelist a Trading Pair

```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -method pair_add -token_base KEL -token_quote USDT -fee_pct 2.0
```

### Create an Order

```bash
srv_dex order create -net TestNet -token_sell KEL -token_buy USDT \
  -w /path/to/wallet.dwallet -value 100.0 -rate 2.5 -fee 0.05
```

### Execute a Trade

```bash
srv_dex purchase_auto -net TestNet -token_sell USDT -token_buy KEL \
  -w /path/to/wallet.dwallet -value 50.0 -unit buy -fee 0.05
```

### Analyze Matches

```bash
srv_dex find_matches -net TestNet -order <hash> -addr <wallet_addr>
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CLI Layer                        │
│  (srv_dex order/purchase/query commands)            │
├─────────────────────────────────────────────────────┤
│                 Matching Engine                     │
│  (s_dex_matches_build_*, s_dex_compose_*)           │
├─────────────────────────────────────────────────────┤
│                  Memory Cache                       │
│  (s_dex_orders_cache, s_dex_pair_index)             │
├─────────────────────────────────────────────────────┤
│                   Verificator                       │
│  (s_dex_verificator_callback)                       │
├─────────────────────────────────────────────────────┤
│                     Ledger                          │
│  (dap_ledger_*, persistent storage)                 │
└─────────────────────────────────────────────────────┘
```

## Key Features

- **Atomic Execution** — Trades execute in single transaction
- **Partial Fills** — Support for min_fill policies
- **Multi-Order** — Match against multiple orders in one TX
- **Auto-Match** — Best price matching by criteria
- **Fee Flexibility** — Native or percent-based fees
- **History Cache** — OHLCV aggregation for analytics
- **Governance** — Decree-based pair and fee management

## Source Files

| File | Description |
|------|-------------|
| `dap_chain_net_srv_dex.c` | Main implementation (~9500 lines) |
| `dap_chain_net_srv_dex.h` | Public API header |

## Version

DEX v2 — Service ID `0x0A`



