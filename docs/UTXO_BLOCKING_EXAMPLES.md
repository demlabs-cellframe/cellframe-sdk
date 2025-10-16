# UTXO Blocking Mechanism - Usage Examples

## Overview

The UTXO (Unspent Transaction Output) blocking mechanism allows token issuers to prevent specific UTXOs from being spent. This feature is **enabled by default** for all CF20 tokens and can be controlled via token flags and `token_update` commands.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Delayed Activation & Unblocking](#delayed-activation--unblocking)
3. [Flag Management](#flag-management)
4. [Integration with Address-Based Blocking](#integration-with-address-based-blocking)
5. [Common Use Cases](#common-use-cases)
6. [Best Practices](#best-practices)

---

## Basic Usage

### 1. Creating a Token with UTXO Blocking Enabled (Default)

UTXO blocking is **enabled by default** for all CF20 tokens. No special flags are needed:

```bash
# Create CF20 token with UTXO blocking enabled (default behavior)
cellframe-node-cli token_decl \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -total_supply 1000000 \
    -decimals 18 \
    -signs_total 1 \
    -signs_emission 1 \
    -certs owner_cert
```

### 2. Blocking a Specific UTXO (Immediate)

```bash
# Block UTXO immediately
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -utxo_blocked_add 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:0 \
    -certs owner_cert
```

**Format:** `<tx_hash>:<out_idx>`

- `tx_hash`: 32-byte transaction hash (64 hex characters with `0x` prefix)
- `out_idx`: Output index (0-based integer)

### 3. Unblocking a UTXO (Immediate)

```bash
# Unblock UTXO immediately (remove from blocklist)
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -utxo_blocked_remove 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:0 \
    -certs owner_cert
```

### 4. Clearing All Blocked UTXOs

```bash
# Clear entire UTXO blocklist
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -utxo_blocked_clear \
    -certs owner_cert
```

### 5. Viewing UTXO Blocklist

```bash
# Display token info including UTXO blocklist
cellframe-node-cli token info -net mynetwork -name TEST
```

**Example output:**
```json
{
  "ticker": "TEST",
  "type": "CF20",
  "flags": "0x00000000",
  "utxo_blocklist_count": 2,
  "utxo_blocklist": [
    {
      "tx_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      "out_idx": 0,
      "blocked_time": 1697529600,
      "becomes_effective": 1697529600,
      "becomes_unblocked": 0
    },
    {
      "tx_hash": "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
      "out_idx": 1,
      "blocked_time": 1697530000,
      "becomes_effective": 1697533600,
      "becomes_unblocked": 1697540800
    }
  ]
}
```

**Field descriptions:**
- `blocked_time`: When UTXO was added to blocklist (Unix timestamp)
- `becomes_effective`: When blocking activates (blockchain time)
- `becomes_unblocked`: When blocking expires (`0` = permanent)

---

## Delayed Activation & Unblocking

The UTXO blocking mechanism supports temporal semantics via blockchain time anchoring.

### 1. Delayed Blocking Activation

Block a UTXO, but activation occurs only after a specified blockchain time:

```bash
# Block UTXO starting from timestamp 1700000000 (blockchain time)
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -utxo_blocked_add 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:0:1700000000 \
    -certs owner_cert
```

**Format:** `<tx_hash>:<out_idx>:<timestamp>`

**Behavior:**
- UTXO remains spendable until `blockchain_time >= 1700000000`
- After activation, UTXO becomes blocked and cannot be spent
- Useful for scheduled restrictions (e.g., vesting periods)

### 2. Delayed Unblocking (Automatic Expiration)

Block a UTXO temporarily - it will automatically unblock after a specified time:

```bash
# Block UTXO now, but auto-unblock at timestamp 1700100000
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -utxo_blocked_remove 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:0:1700100000 \
    -certs owner_cert
```

**Format:** `<tx_hash>:<out_idx>:<timestamp>`

**Behavior:**
- If UTXO is currently blocked, it remains blocked until `blockchain_time >= 1700100000`
- After expiration, UTXO automatically becomes spendable
- Entry is removed from blocklist after expiration
- Useful for temporary restrictions (e.g., lock-up periods)

### 3. Combined Example: Vesting Period

```bash
# Step 1: Block UTXO immediately for vesting
cellframe-node-cli token_update \
    -net mynetwork \
    -token VEST \
    -type CF20 \
    -utxo_blocked_add 0xabcd...1234:0 \
    -certs owner_cert

# Step 2: Schedule automatic unblock after 6 months (timestamp: 1715788800)
cellframe-node-cli token_update \
    -net mynetwork \
    -token VEST \
    -type CF20 \
    -utxo_blocked_remove 0xabcd...1234:0:1715788800 \
    -certs owner_cert
```

**Result:**
- UTXO is blocked immediately
- UTXO automatically becomes spendable after May 15, 2024
- No further manual intervention required

---

## Flag Management

### 1. Disabling UTXO Blocking (Opt-Out)

If you want to disable UTXO blocking entirely for a token:

```bash
# Create token with UTXO blocking disabled
cellframe-node-cli token_decl \
    -net mynetwork \
    -token NOBLOCK \
    -type CF20 \
    -total_supply 1000000 \
    -decimals 18 \
    -signs_total 1 \
    -signs_emission 1 \
    -flags UTXO_BLOCKING_DISABLED \
    -certs owner_cert
```

Or disable it later via `token_update`:

```bash
# Disable UTXO blocking for existing token
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -flag_set UTXO_BLOCKING_DISABLED \
    -certs owner_cert
```

**Effect:**
- All UTXOs become spendable regardless of blocklist
- Blocklist data is preserved but ignored
- Can be re-enabled by unsetting the flag

### 2. Making UTXO Blocklist Immutable

Use `STATIC_UTXO_BLOCKLIST` to prevent any further modifications to the blocklist:

```bash
# Create token with static (immutable) UTXO blocklist
cellframe-node-cli token_decl \
    -net mynetwork \
    -token STATIC \
    -type CF20 \
    -total_supply 1000000 \
    -decimals 18 \
    -signs_total 1 \
    -signs_emission 1 \
    -flags STATIC_UTXO_BLOCKLIST \
    -utxo_blocked_add 0xabcd...1234:0 \
    -utxo_blocked_add 0xef01...5678:1 \
    -certs owner_cert
```

**Effect:**
- UTXO blocklist is set during token creation
- All subsequent `token_update` operations with `-utxo_blocked_add`, `-utxo_blocked_remove`, or `-utxo_blocked_clear` are **rejected**
- Blocklist becomes permanent and immutable
- **Warning:** This is a one-way operation and cannot be reversed

### 3. Disabling Address-Based Blocking

UTXO blocking and address-based blocking are **independent** features. You can disable address-based blocking while keeping UTXO blocking:

```bash
# Disable address-based sender blocking only
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -flag_set DISABLE_ADDRESS_SENDER_BLOCKING \
    -certs owner_cert

# Disable address-based receiver blocking only
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -flag_set DISABLE_ADDRESS_RECEIVER_BLOCKING \
    -certs owner_cert

# Disable both address-based blocking types
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -flag_set DISABLE_ADDRESS_SENDER_BLOCKING,DISABLE_ADDRESS_RECEIVER_BLOCKING \
    -certs owner_cert
```

**Effect:**
- `tx_send_block`/`tx_send_allow` lists are ignored (if sender blocking disabled)
- `tx_recv_block`/`tx_recv_allow` lists are ignored (if receiver blocking disabled)
- UTXO blocking continues to work normally (unless `UTXO_BLOCKING_DISABLED` is also set)

---

## Integration with Address-Based Blocking

UTXO blocking and address-based blocking can be used together for fine-grained control.

### Example: Hybrid Control

```bash
# Step 1: Create token with both UTXO blocking and address blocking
cellframe-node-cli token_decl \
    -net mynetwork \
    -token HYBRID \
    -type CF20 \
    -total_supply 1000000 \
    -decimals 18 \
    -signs_total 1 \
    -signs_emission 1 \
    -tx_sender_blocked 0x00...bad_actor \
    -certs owner_cert

# Step 2: Block specific UTXO from a good address (e.g., escrow)
cellframe-node-cli token_update \
    -net mynetwork \
    -token HYBRID \
    -type CF20 \
    -utxo_blocked_add 0xabcd...escrow_tx:0 \
    -certs owner_cert
```

**Result:**
- Address `0x00...bad_actor` cannot send any HYBRID tokens (address-based blocking)
- UTXO `0xabcd...escrow_tx:0` cannot be spent even if held by a whitelisted address (UTXO blocking)
- All other UTXOs from non-blocked addresses are spendable

---

## Common Use Cases

### 1. Vesting / Lock-up Periods

```bash
# Lock team allocation for 12 months
cellframe-node-cli token_update \
    -net mynetwork \
    -token COMPANY \
    -type CF20 \
    -utxo_blocked_add 0xteam_allocation_tx:0 \
    -certs owner_cert

# Schedule auto-unlock after 12 months
cellframe-node-cli token_update \
    -net mynetwork \
    -token COMPANY \
    -type CF20 \
    -utxo_blocked_remove 0xteam_allocation_tx:0:1733097600 \
    -certs owner_cert
```

### 2. Escrow Services

```bash
# Block escrow UTXO until dispute resolution
cellframe-node-cli token_update \
    -net mynetwork \
    -token TRADE \
    -type CF20 \
    -utxo_blocked_add 0xescrow_tx:0 \
    -certs escrow_cert

# Release escrow after resolution
cellframe-node-cli token_update \
    -net mynetwork \
    -token TRADE \
    -type CF20 \
    -utxo_blocked_remove 0xescrow_tx:0 \
    -certs escrow_cert
```

### 3. Security Incident Response

```bash
# Emergency: Block suspicious UTXO
cellframe-node-cli token_update \
    -net mynetwork \
    -token SEC \
    -type CF20 \
    -utxo_blocked_add 0xsuspicious_tx:0 \
    -certs security_cert

# Investigate and either:
# a) Unblock if false positive
cellframe-node-cli token_update \
    -net mynetwork \
    -token SEC \
    -type CF20 \
    -utxo_blocked_remove 0xsuspicious_tx:0 \
    -certs security_cert

# b) Keep blocked permanently (no action needed, becomes_unblocked = 0)
```

### 4. Regulatory Compliance

```bash
# Block UTXOs from sanctioned addresses
cellframe-node-cli token_update \
    -net mynetwork \
    -token COMPLIANT \
    -type CF20 \
    -utxo_blocked_add 0xsanctioned_tx:0 \
    -utxo_blocked_add 0xsanctioned_tx:1 \
    -utxo_blocked_add 0xsanctioned_tx:2 \
    -certs compliance_cert
```

### 5. ICO/IDO Token Distribution

```bash
# Create immutable allocation with STATIC_UTXO_BLOCKLIST
cellframe-node-cli token_decl \
    -net mynetwork \
    -token ICO \
    -type CF20 \
    -total_supply 10000000 \
    -decimals 18 \
    -signs_total 1 \
    -signs_emission 1 \
    -flags STATIC_UTXO_BLOCKLIST \
    -utxo_blocked_add 0xteam_alloc:0 \
    -utxo_blocked_add 0xadvisor_alloc:0 \
    -utxo_blocked_add 0xreserve_alloc:0 \
    -certs owner_cert

# Later schedule unlocking via delayed unblocking
# (Note: requires STATIC_UTXO_BLOCKLIST to NOT be set if you want to modify)
```

---

## Best Practices

### 1. Security

- **Use `STATIC_UTXO_BLOCKLIST` carefully**: Once set, it cannot be undone
- **Validate tx_hash and out_idx**: Incorrect values will silently fail
- **Protect signing certificates**: UTXO management requires token owner certs
- **Monitor blocklist size**: Large blocklists may impact performance

### 2. Operations

- **Use delayed activation for vesting**: Avoids need for future manual unlocking
- **Document blocklist changes**: Maintain audit trail of all UTXO blocks
- **Test on testnet first**: Verify blocklist behavior before production deployment
- **Use `token info` regularly**: Monitor current blocklist state

### 3. Compatibility

- **UTXO blocking is enabled by default**: No migration needed for existing tokens
- **Address blocking is independent**: Can be disabled without affecting UTXO blocking
- **Flags are combinable**: Multiple flags can be set together
- **Timestamps are blockchain time**: Use `dap_ledger_get_blockchain_time()` for accuracy

### 4. Performance

- **Blocklist uses hash table (uthash)**: O(1) lookup performance
- **Thread-safe by design**: Uses `pthread_rwlock_t` for concurrent access
- **Memory efficient**: 36-byte key + ~32 bytes metadata per entry
- **No global database overhead**: In-memory storage only

### 5. Debugging

- **Check `token info` output**: Verify `utxo_blocklist` and `utxo_blocklist_count`
- **Inspect flags**: Ensure `UTXO_BLOCKING_DISABLED` is NOT set
- **Review timestamps**: Verify `becomes_effective` and `becomes_unblocked` values
- **Check error messages**: Look for `DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED` errors

---

## Error Messages

| Error Code | Description | Solution |
|-----------|-------------|----------|
| `DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED` | UTXO is blocked | Wait for `becomes_unblocked` time or unblock manually |
| `STATIC_UTXO_BLOCKLIST enforced` | Blocklist is immutable | Cannot modify blocklist (permanent restriction) |
| `UTXO_BLOCKING_DISABLED is set` | UTXO blocking is disabled | Unset `UTXO_BLOCKING_DISABLED` flag |
| `Invalid UTXO format` | Incorrect `tx_hash:out_idx` format | Use correct format: `0x<64_hex_chars>:<uint32>` |

---

## Related Documentation

- [DAP SDK Coding Standards](../.context/modules/standards/dap_sdk_coding_standards.json)
- [Cellframe SDK Project Structure](../.context/modules/projects/cellframe_sdk.json)
- [dap_chain_datum_token.h](modules/common/include/dap_chain_datum_token.h) - Token flags and TSD types
- [dap_chain_ledger.c](modules/net/dap_chain_ledger.c) - UTXO blocking implementation

---

## Conclusion

The UTXO blocking mechanism provides powerful, fine-grained control over token transactions. By combining UTXO blocking with address-based restrictions and temporal semantics (delayed activation/unblocking), token issuers can implement complex compliance, security, and business logic requirements.

For additional support, consult the inline doxygen documentation or contact the Cellframe development team.

