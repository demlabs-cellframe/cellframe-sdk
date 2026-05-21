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
7. [Arbitrage Transactions](#10-arbitrage-transactions)

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

Use `UTXO_STATIC_BLOCKLIST` to prevent any further modifications to the blocklist:

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
    -flags UTXO_STATIC_BLOCKLIST \
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
    -flag_set UTXO_DISABLE_ADDRESS_SENDER_BLOCKING \
    -certs owner_cert

# Disable address-based receiver blocking only
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -flag_set UTXO_DISABLE_ADDRESS_RECEIVER_BLOCKING \
    -certs owner_cert

# Disable both address-based blocking types
cellframe-node-cli token_update \
    -net mynetwork \
    -token TEST \
    -type CF20 \
    -flag_set UTXO_DISABLE_ADDRESS_SENDER_BLOCKING,UTXO_DISABLE_ADDRESS_RECEIVER_BLOCKING \
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
# Create immutable allocation with UTXO_STATIC_BLOCKLIST
cellframe-node-cli token_decl \
    -net mynetwork \
    -token ICO \
    -type CF20 \
    -total_supply 10000000 \
    -decimals 18 \
    -signs_total 1 \
    -signs_emission 1 \
    -flags UTXO_STATIC_BLOCKLIST \
    -utxo_blocked_add 0xteam_alloc:0 \
    -utxo_blocked_add 0xadvisor_alloc:0 \
    -utxo_blocked_add 0xreserve_alloc:0 \
    -certs owner_cert

# Later schedule unlocking via delayed unblocking
# (Note: requires UTXO_STATIC_BLOCKLIST to NOT be set if you want to modify)
```

---

## Best Practices

### 1. Security

- **Use `UTXO_STATIC_BLOCKLIST` carefully**: Once set, it cannot be undone
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
| `UTXO_STATIC_BLOCKLIST enforced` | Blocklist is immutable | Cannot modify blocklist (permanent restriction) |
| `UTXO_BLOCKING_DISABLED is set` | UTXO blocking is disabled | Unset `UTXO_BLOCKING_DISABLED` flag |
| `Invalid UTXO format` | Incorrect `tx_hash:out_idx` format | Use correct format: `0x<64_hex_chars>:<uint32>` |

---

## 10. Arbitrage Transactions

### Overview

**Arbitrage transactions** are special emergency transactions that allow token owners to bypass **ALL** blocking mechanisms (UTXO blocking, conditional outputs, address banlists) to recover funds or resolve disputes. They are marked with a special TSD marker (`DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE = 0x00A1`) and have strict validation rules.

### Purpose

Arbitrage transactions are designed for emergency situations:
- Recovering funds from blocked UTXOs
- Resolving disputes between parties
- Emergency token owner intervention
- Compliance with court orders or regulatory requirements

### Security Model

⚠️ **CRITICAL SECURITY RESTRICTIONS:**

1. **Must be signed by token owner** - Requires valid signature from token's `auth_pkeys`
2. **Minimum signature threshold** - Must meet `auth_signs_valid` requirement:
   - Wallet signature counts as 1
   - Additional signatures from `-certs` parameter
   - Total signatures must be >= `auth_signs_valid`
   - If insufficient, transaction stays in mempool for additional signatures
3. **Network fee address ONLY** - Can **ONLY** send funds to network fee address (`net->pub.fee_addr`), NOT to `tx_recv_allow` list
4. **Can be disabled** - Token can set `UTXO_ARBITRAGE_TX_DISABLED` flag to permanently disable arbitrage
5. **Distributed signing support** - Use `tx_sign` command to add signatures from different nodes

🔒 **Why only network fee address?** This prevents token owners from adding their own addresses to `tx_recv_allow` and misusing arbitrage. The network fee address is controlled by network operators, not by individual token owners.

### Usage

#### Creating Arbitrage Transaction

```bash
# Create arbitrage transaction with -arbitrage flag
# NOTE: -to_addr parameter is NOT required for arbitrage transactions
# CLI automatically sends ALL outputs to network fee address (net->pub.fee_addr)
cellframe-node-cli tx_create \
    -net mynetwork \
    -token MYTOKEN \
    -from_wallet owner_wallet \
    -value 1000.0 \
    -fee 0.01 \
    -arbitrage \
    -certs token_owner_cert
```

**Prerequisites:**
1. Network must have `fee_addr` configured (network fee collection address)
2. Arbitrage must not be disabled (`UTXO_ARBITRAGE_TX_DISABLED` flag not set)
3. Transaction must be signed by token owner certificate(s)

⚠️ **AUTOMATIC ADDRESS HANDLING:** Arbitrage transactions automatically send all outputs to the network fee address (`net->pub.fee_addr`):
- `-to_addr` parameter is optional and will be ignored if provided
- All outputs (main, change, fee change) go to fee address only
- Fee address is configured at network level, not by token owners

#### Checking Network Fee Address

Before using arbitrage, verify the network fee address:

```bash
# Check network fee address
cellframe-node-cli net get -net mynetwork fee_addr
# Output: mXyZ123... (network fee collection address)
```

#### Disabling Arbitrage (Irreversible)

```bash
# Permanently disable arbitrage for this token
cellframe-node-cli token_update \
    -net mynetwork \
    -chain main \
    -token MYTOKEN \
    -flag_set UTXO_ARBITRAGE_TX_DISABLED \
    -certs token_owner_cert
```

⚠️ **Warning:** Once `UTXO_ARBITRAGE_TX_DISABLED` is set, it cannot be unset (irreversible flag).

### Validation Rules

When ledger processes arbitrage transaction, it performs these checks:

1. **TSD Marker Check** - TX must have `DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE` (0x00A1) TSD
2. **Flag Check** - Token must not have `UTXO_ARBITRAGE_TX_DISABLED` set
3. **Signature Check** - TX must be signed by:
   - **Emission owner** (to authorize spending the UTXO)
   - **Token owner(s)** (to authorize arbitrage - must be in `auth_pkeys` and meet `auth_signs_valid` threshold):
     - Wallet signature counts as 1
     - Additional signatures from `-certs` parameter
     - Total valid owner signatures must be >= `auth_signs_valid`
     - If insufficient (`auth_signs_valid` not met), transaction returns `DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS` and **stays in mempool**
4. **Network Fee Address Check** - Network must have `fee_addr` configured
5. **Output Address Check** - **ALL** TX outputs must go **ONLY** to network fee address (`net->pub.fee_addr`)

⚠️ **CRITICAL:** Arbitrage transactions can ONLY send funds to the network fee collection address.

**Mempool Behavior:**
- Transactions with insufficient signatures (`DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS`) are **NOT deleted** from mempool
- This allows distributed signing: transaction can be created on one node, then signatures added from other nodes using `tx_sign` command
- Transaction remains in mempool until it has enough signatures or is manually removed
- Once `auth_signs_valid` signatures are collected, transaction can be processed normally

If any check fails (except insufficient signatures), transaction is rejected with `DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED`.

### Bypassed Checks

Arbitrage transactions **bypass ALL** of these checks:
- ✅ UTXO blocking (can spend blocked UTXOs)
- ✅ Conditional outputs (can spend locked/conditional outputs)
- ✅ Address sender blocking (`tx_send_block` ignored)
- ✅ Address receiver blocking (`tx_recv_block` ignored)

### Error Codes

| Error Code | Error Message | Cause |
|-----------|---------------|-------|
| `DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED` | Arbitrage TX not authorized | Missing owner signatures, disabled arbitrage, output to non-allowed address, or network fee address not configured |

### Common Scenarios

#### Scenario 1: Arbitrage Disabled

If token has `UTXO_ARBITRAGE_TX_DISABLED` flag set, arbitrage transactions are permanently disabled:

```bash
# Check if arbitrage is disabled
cellframe-node-cli token info -net mynetwork -name MYTOKEN
# Look for flags containing UTXO_ARBITRAGE_TX_DISABLED

# Attempt arbitrage (will fail)
cellframe-node-cli tx_create \
    -net mynetwork \
    -token MYTOKEN \
    -from_wallet owner_wallet \
    -to <network_fee_address> \
    -value 1000.0 \
    -arbitrage \
    -certs token_owner_cert
# Error: Arbitrage transactions disabled for token MYTOKEN
```

#### Scenario 2: Network Fee Address Not Configured

If network does not have `fee_addr` configured, arbitrage transactions are rejected:

```bash
# Check network fee address
cellframe-node-cli net get -net mynetwork fee_addr
# If blank, arbitrage will fail

# Attempt arbitrage (will fail)
cellframe-node-cli tx_create \
    -net mynetwork \
    -token MYTOKEN \
    -from_wallet owner_wallet \
    -to <any_address> \
    -value 1000.0 \
    -arbitrage \
    -certs token_owner_cert
# Error: Arbitrage TX rejected: network has no fee address configured
```

**Solution:** Network operators must configure `fee_addr` before arbitrage can be used.

#### Scenario 3: Arbitrage Bypasses Address Blocking

Arbitrage transactions bypass address-based blocking (both sender and receiver):

```bash
# Step 1: Block an address as sender
cellframe-node-cli token_update \
    -net mynetwork \
    -token MYTOKEN \
    -tx_sender_blocked_add 0xblocked_address \
    -certs owner_cert

# Step 2: Create arbitrage transaction from blocked address (will succeed)
cellframe-node-cli tx_create \
    -net mynetwork \
    -token MYTOKEN \
    -from_wallet blocked_wallet \  # Address is blocked
    -value 1000.0 \
    -arbitrage \
    -certs token_owner_cert
# NOTE: -to_addr not needed - outputs automatically go to network fee address
# Success: Arbitrage bypasses address blocking
```

#### Scenario 4: Multi-Signature Requirements

If token requires multiple owner signatures (`auth_signs_valid > 1`), arbitrage transaction must be signed by at least that many token owners.

**Important:** Signature counting rules depend on whether **fee token == arbitrage token**:

##### Case 1: fee_token == arbitrage_token (same token for both)

When the token being transferred is the same as the native ticker used for fees:

- **Wallet signature COUNTS** for arbitrage authorization
- Need `(auth_signs_valid - 1)` additional certificates via `-certs`
- Example: If `auth_signs_valid = 3`, need wallet + 2 certs = 3 total

```bash
# Token requires 3 owner signatures (auth_signs_valid = 3)
# fee_token == arbitrage_token (e.g., both are native ticker)
cellframe-node-cli tx_create \
    -net mynetwork \
    -token MYTOKEN \
    -from_wallet owner_wallet \  # Signature counts for arbitrage (1)
    -value 1000.0 \
    -fee 0.01 \
    -arbitrage \
    -certs token_owner_cert1,token_owner_cert2  # 2 certs (total = 3)
# NOTE: -to_addr not needed - automatically sends to fee address
```

##### Case 2: fee_token != arbitrage_token (different tokens)

When the token being transferred differs from the native ticker used for fees:

- **Wallet signature DOES NOT count** for arbitrage authorization (used ONLY for fee payment)
- Need **ALL** `auth_signs_valid` certificates via `-certs`
- Example: If `auth_signs_valid = 3`, need 3 certs (wallet signature is for fee only)

```bash
# Token requires 3 owner signatures (auth_signs_valid = 3)
# NOTE: For arbitrage with -from_wallet, wallet must have BOTH tokens:
#       - Arbitrage token (ARBMULTI) for transfer
#       - Native token (for fee payment)
cellframe-node-cli tx_create \
    -net mynetwork \
    -token ARBMULTI \
    -from_wallet arbitrage_wallet \
    -value 1000.0 \
    -fee 0.000000000000000001 \
    -arbitrage \
    -certs owner_cert1  # Only 1 cert provided (need 3 for auth_signs_valid=3)
# WARNING: Transaction created with INSUFFICIENT signatures (1 of 3)
# Will remain in mempool until remaining signatures are added via tx_sign
```

##### Creating Multi-Signature Arbitrage Transaction (Distributed Signing)

When token owners are on different nodes or you cannot provide all signatures at once, create the transaction with partial signatures first:

**Step 1:** Create arbitrage transaction with initial signature(s):

```bash
# Node 1: Create arbitrage TX with insufficient signatures
# Token requires 3 owner signatures (auth_signs_valid = 3)
# NOTE: Wallet must have both arbitrage token and native token (for fee)
cellframe-node-cli tx_create \
    -net mynetwork \
    -token ARBMULTI \
    -from_wallet arbitrage_wallet \
    -value 10000.0 \
    -fee 0.000000000000000001 \
    -arbitrage \
    -certs owner_cert1  # Only 1 owner cert (2 more needed for auth_signs_valid=3)
# CLI Notice: "Transaction will be created and placed in mempool. 
#             Add remaining 2 signatures via 'tx_sign' command."
# Returns transaction hash: 0xABC123...
```

**Step 2:** Add second signature from another node:

```bash
# Node 2: Add signature from second owner
cellframe-node-cli tx_sign \
    -net mynetwork \
    -chain main \
    -tx 0xABC123... \
    -certs owner_cert2
# Returns NEW transaction hash: 0xDEF456... (hash changes after adding signature)
# Now has 2 owner signatures (1 more needed)
```

**Step 3:** Add third signature to complete authorization:

```bash
# Node 3: Add signature from third owner
cellframe-node-cli tx_sign \
    -net mynetwork \
    -chain main \
    -tx 0xDEF456... \  # Use NEW hash from Step 2
    -certs owner_cert3
# Returns FINAL transaction hash: 0x789ABC...
# Now has 3 owner signatures - sufficient for processing
# Transaction will be automatically processed from mempool to ledger
```

**Important Notes:**
- **`tx_sign` command restrictions:**
  - Can **only** add signatures to **arbitrage transactions** (must have TSD marker)
  - Certificates must belong to token owners (verified against `auth_pkeys`)
  - Cannot sign regular (non-arbitrage) transactions
- **Transaction hash changes** after each `tx_sign` operation:
  - Old hash becomes invalid
  - New hash must be used for subsequent operations
  - Use the hash returned in `tx_sign` response for next signature
- **Mempool behavior:**
  - Transaction stays in mempool until sufficient signatures collected
  - Returns `DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS` (not an error - expected behavior)
  - Automatically processed once `auth_signs_valid` threshold is met
- **Certificate files:**
  - Certificates must be saved to files in the certificates directory
  - CLI searches for `<cert_name>.dcert` files, not just in-memory certificates
  - Default path: `/opt/cellframe-node/etc/certs/` (or as configured)

**Mempool Behavior:**
- Transactions with insufficient signatures (`DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS`) are **NOT** deleted from mempool
- This allows distributed signing across multiple nodes
- Transaction stays in mempool until it has enough signatures or is manually removed

#### The `tx_sign` Command

The `tx_sign` command allows adding signatures to existing arbitrage transactions in the mempool for distributed signing workflows.

**Syntax:**
```bash
cellframe-node-cli tx_sign \
    -net <network_name> \
    -chain <chain_name> \
    -tx <transaction_hash> \
    -certs <cert1>[,<cert2>,...]
```

**Parameters:**
- `-net`: Network name
- `-chain`: Chain name  
- `-tx`: Transaction hash (must be in mempool)
- `-certs`: Comma-separated list of certificate names

**Important Restrictions:**
1. Can **ONLY** sign arbitrage transactions (must have `DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE` TSD marker)
2. Certificates must belong to token owners (verified against token's `auth_pkeys`)
3. Transaction must exist in mempool (not yet processed to ledger)
4. Cannot sign regular (non-arbitrage) transactions

**Response:**
```json
{
  "status": "ok",
  "old_hash": "0xABC123...",
  "new_hash": "0xDEF456...",
  "signatures_added": 1,
  "total_signatures": 3
}
```

**Hash Change Behavior:**
- Each `tx_sign` operation creates a **NEW** transaction with additional signature(s)
- Old transaction hash becomes **INVALID**
- New hash MUST be used for subsequent `tx_sign` operations
- This is expected behavior for multi-signature transactions

**Example Workflow:**

```bash
# Initial transaction (2 signatures: wallet + cert1)
TX_HASH_1="0xABC123..."

# Add second signature (now 3 signatures total)
RESULT=$(cellframe-node-cli tx_sign -net Backbone -tx $TX_HASH_1 -certs owner_cert2)
TX_HASH_2=$(echo $RESULT | jq -r '.new_hash')  # Extract new hash

# Add third signature (now 4 signatures total)
RESULT=$(cellframe-node-cli tx_sign -net Backbone -tx $TX_HASH_2 -certs owner_cert3)
TX_HASH_FINAL=$(echo $RESULT | jq -r '.new_hash')

# Transaction automatically processes to ledger once auth_signs_valid threshold is met
```

**Error Messages:**
| Error | Cause | Solution |
|-------|-------|----------|
| `Transaction not found in mempool` | TX already processed or invalid hash | Verify hash is correct and TX is still in mempool |
| `Transaction is not an arbitrage transaction` | Missing TSD marker | Can only sign arbitrage TX - use `-arbitrage` flag in `tx_create` |
| `None of the provided certificates belong to token owners` | Certs not in `auth_pkeys` | Use certificates that were used to create the token |
| `Arbitrage marker lost after adding signatures` | Internal error | Report bug - TSD marker should be preserved |

**Testing Arbitrage with Multiple Signatures:**

```bash
# Step 1: Create token with multi-sig requirement
cellframe-node-cli token_decl \
    -net testnet \
    -token MULTISIG \
    -total_supply 100000.0 \
    -signs_valid 3 \  # Require 3 signatures
    -signs_total 3 \
    -certs owner1,owner2,owner3

# Step 2: Create arbitrage TX with insufficient signatures (distributed signing)
# NOTE: Wallet must have both MULTISIG token and native token for fee
cellframe-node-cli tx_create \
    -net testnet \
    -token MULTISIG \
    -from_wallet arb_wallet \
    -value 5000.0 \
    -fee 0.000000000000000001 \
    -arbitrage \
    -certs owner1  # Only 1 owner cert (need 3 total)
# Notice: "Add remaining 2 signatures via 'tx_sign' command"
# Returns: hash1 (TX in mempool with 2 signatures: wallet + owner1)

# Step 3: Add second owner signature
cellframe-node-cli tx_sign \
    -net testnet \
    -chain main \
    -tx <hash1> \
    -certs owner2
# Returns: hash2 (now 3 signatures: wallet + owner1 + owner2, still need 1 more)

# Step 4: Add third owner signature
cellframe-node-cli tx_sign \
    -net testnet \
    -chain main \
    -tx <hash2> \
    -certs owner3
# Returns: hash3 (now 4 signatures: wallet + 3 owners)
# TX automatically processes to ledger (auth_signs_valid=3 threshold met)
```

### Example: Emergency UTXO Recovery

```bash
# Scenario: UTXO accidentally blocked, need to recover funds

# Step 1: Check network fee address
cellframe-node-cli net get -net Backbone fee_addr
# Output: mAbCdEfGhIjKlMnOpQrStUvWxYz0123456789  (network fee address)

# Step 2: Create arbitrage transaction
# NOTE: Outputs automatically go to network fee address (net->pub.fee_addr)
cellframe-node-cli tx_create \
    -net Backbone \
    -token LOCKED \
    -from_wallet owner_wallet \
    -value 10000.0 \
    -arbitrage \
    -certs token_owner
# No -to_addr needed - CLI automatically uses mAbCdEfGhIjKlMnOpQrStUvWxYz0123456789

# Step 3: Verify transaction was created
cellframe-node-cli tx_history -net Backbone -addr mAbCdEfGhIjKlMnOpQrStUvWxYz0123456789

# Step 4: From fee collection address, redistribute funds normally
cellframe-node-cli tx_create \
    -net Backbone \
    -token LOCKED \
    -from mAbCdEfGhIjKlMnOpQrStUvWxYz0123456789 \
    -to <rightful_owner_address> \
    -value 10000.0
```

### Best Practices

1. **Network Fee Address** - Ensure network fee address is configured before using arbitrage
2. **Multi-Signature** - Set `auth_signs_valid` > 1 to require multiple owner signatures
3. **Documentation** - Maintain audit trail of all arbitrage transactions
4. **Testing** - Test arbitrage on testnet before using on mainnet

### Security Considerations

**For Token Owners:**
- Use multi-signature requirements when possible
- Document all arbitrage transactions
- All arbitrage funds go to network fee address - coordinate with network operators

**For Token Holders:**
- Check if token has `UTXO_ARBITRAGE_TX_DISABLED` set
- Verify network fee address is configured correctly
- Arbitrage does not use `tx_recv_allow` - funds go to network fee address only


## Conclusion

The UTXO blocking mechanism, combined with arbitrage transactions, provides fine-grained control over token transactions. Token issuers can implement compliance, security, and business logic requirements by combining:
- UTXO blocking
- Address-based restrictions
- Temporal semantics (delayed activation/unblocking)
- Emergency recovery via arbitrage

For additional support, contact the Cellframe development team.

