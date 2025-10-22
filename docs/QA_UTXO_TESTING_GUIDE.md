# QA Testing Guide: UTXO Blocking & Arbitrage

**Version:** 1.0  
**Date:** 2025-10-22  
**Target:** QA Engineers and Testers  
**Related Issue:** #19886

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Test Environment Setup](#test-environment-setup)
3. [Test Scenario 1: Basic UTXO Blocking](#test-scenario-1-basic-utxo-blocking)
4. [Test Scenario 2: UTXO Unblocking](#test-scenario-2-utxo-unblocking)
5. [Test Scenario 3: Delayed Activation](#test-scenario-3-delayed-activation)
6. [Test Scenario 4: UTXO_STATIC_BLOCKLIST Flag](#test-scenario-4-utxo_static_blocklist-flag)
7. [Test Scenario 5: UTXO_BLOCKING_DISABLED Flag](#test-scenario-5-utxo_blocking_disabled-flag)
8. [Test Scenario 6: Arbitrage Transactions](#test-scenario-6-arbitrage-transactions)
9. [Test Scenario 7: UTXO_ARBITRAGE_TX_DISABLED Flag](#test-scenario-7-utxo_arbitrage_tx_disabled-flag)
10. [Test Scenario 8: Negative Tests](#test-scenario-8-negative-tests)
11. [Verification Checklist](#verification-checklist)
12. [Known Issues](#known-issues)
13. [Reporting Bugs](#reporting-bugs)

---

## Prerequisites

### Required Software
- Cellframe Node installed and running
- Access to CLI (`cellframe-node-cli`)
- At least 2 network nodes for testing
- Test certificates for token creation

### Required Knowledge
- Basic understanding of blockchain transactions
- Familiarity with CLI commands
- Understanding of UTXO model

### Test Wallets
Create 3 test wallets:
```bash
# Wallet 1: Token Owner
cellframe-node-cli wallet new -w owner_wallet

# Wallet 2: Regular User
cellframe-node-cli wallet new -w user_wallet

# Wallet 3: Fee Collection (for arbitrage)
cellframe-node-cli wallet new -w fee_wallet
```

### Test Certificates
Create test certificates:
```bash
# Certificate for token owner
cellframe-node-cli cert create -cert_name token_owner_cert

# Get certificate path
cellframe-node-cli cert list
```

---

## Test Environment Setup

### Step 1: Create Test Token

```bash
# Create a test token with UTXO blocking support
cellframe-node-cli token_decl \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -total_supply 1000000.0 \
    -signs_total 1 \
    -signs_emission 1 \
    -decimals 18 \
    -certs token_owner_cert

# Expected result: Token declaration created successfully
```

**✅ Verification:**
- [ ] Command executed without errors
- [ ] Token appears in `token list`

### Step 2: Create Emission

```bash
# Create emission for testing
cellframe-node-cli token_emit \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -emission_value 100000.0 \
    -addr <owner_wallet_address> \
    -certs token_owner_cert

# Expected result: Emission created, tokens minted
```

**✅ Verification:**
- [ ] Emission created successfully
- [ ] Balance shows 100000.0 QATEST tokens

### Step 3: Create Test Transaction

```bash
# Transfer tokens to user wallet (creates UTXO)
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr <user_wallet_address> \
    -value 1000.0 \
    -fee 0.0

# Save the transaction hash for testing
TX_HASH=<transaction_hash_from_output>
```

**✅ Verification:**
- [ ] Transaction created successfully
- [ ] User wallet shows 1000.0 QATEST tokens
- [ ] TX hash saved for later use

---

## Test Scenario 1: Basic UTXO Blocking

**Purpose:** Verify that UTXO can be blocked and spending is prevented.

### Step 1.1: Block UTXO

```bash
# Block the UTXO using token_update
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add ${TX_HASH}:0 \
    -certs token_owner_cert

# Expected result: UTXO blocked successfully
```

**✅ Expected Results:**
- [ ] Command succeeds
- [ ] No error messages
- [ ] Token update datum created

### Step 1.2: Verify Token Info

```bash
# Check token info to see blocked UTXO
cellframe-node-cli token_info \
    -net YOUR_NETWORK \
    -name QATEST

# Expected output should show:
# - utxo_blocked_list: ${TX_HASH}:0
```

**✅ Verification:**
- [ ] Token info displays blocked UTXO list
- [ ] UTXO ${TX_HASH}:0 appears in the list

### Step 1.3: Attempt to Spend Blocked UTXO

```bash
# Try to create transaction from user wallet (should FAIL)
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet user_wallet \
    -to_addr <owner_wallet_address> \
    -value 100.0 \
    -fee 0.0

# Expected result: ERROR - UTXO is blocked
```

**✅ Expected Results:**
- [ ] Transaction **FAILS**
- [ ] Error code: `DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED`
- [ ] Error message mentions UTXO is blocked

**❌ FAIL Criteria:**
- Transaction succeeds when it should be blocked
- No error message displayed
- Different error code returned

---

## Test Scenario 2: UTXO Unblocking

**Purpose:** Verify that blocked UTXO can be unblocked.

### Step 2.1: Unblock UTXO

```bash
# Unblock the previously blocked UTXO
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_remove ${TX_HASH}:0 \
    -certs token_owner_cert

# Expected result: UTXO unblocked successfully
```

**✅ Expected Results:**
- [ ] Command succeeds
- [ ] No error messages

### Step 2.2: Verify Token Info

```bash
# Check token info - blocked list should be empty
cellframe-node-cli token_info \
    -net YOUR_NETWORK \
    -name QATEST

# Expected: utxo_blocked_list should NOT contain ${TX_HASH}:0
```

**✅ Verification:**
- [ ] UTXO no longer in blocked list

### Step 2.3: Attempt to Spend Unblocked UTXO

```bash
# Try to create transaction (should SUCCEED now)
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet user_wallet \
    -to_addr <owner_wallet_address> \
    -value 100.0 \
    -fee 0.0

# Expected result: Transaction created successfully
```

**✅ Expected Results:**
- [ ] Transaction **SUCCEEDS**
- [ ] No error messages
- [ ] Balance updated correctly

**❌ FAIL Criteria:**
- Transaction fails after unblocking
- UTXO still appears as blocked
- Balance not updated

---

## Test Scenario 3: Delayed Activation

**Purpose:** Verify that UTXO can be blocked with future activation time.

### Step 3.1: Block UTXO with Future Timestamp

```bash
# Get current timestamp + 60 seconds
FUTURE_TIME=$(($(date +%s) + 60))

# Create new test transaction first
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr <user_wallet_address> \
    -value 500.0 \
    -fee 0.0

# Save new TX hash
TX_HASH_2=<transaction_hash>

# Block with delayed activation
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add ${TX_HASH_2}:0:${FUTURE_TIME} \
    -certs token_owner_cert

# Expected: UTXO will be blocked at ${FUTURE_TIME}
```

**✅ Expected Results:**
- [ ] Command succeeds
- [ ] Token update accepted

### Step 3.2: Verify UTXO is NOT Blocked Yet

```bash
# Immediately try to spend (should SUCCEED before activation time)
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet user_wallet \
    -to_addr <owner_wallet_address> \
    -value 50.0 \
    -fee 0.0

# Expected: Transaction SUCCEEDS (not blocked yet)
```

**✅ Expected Results:**
- [ ] Transaction **SUCCEEDS** immediately
- [ ] No blocking error

### Step 3.3: Wait and Verify Blocking Activates

```bash
# Wait for activation time (60+ seconds)
sleep 65

# Try to spend again (should FAIL now)
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet user_wallet \
    -to_addr <owner_wallet_address> \
    -value 50.0 \
    -fee 0.0

# Expected: Transaction FAILS (now blocked)
```

**✅ Expected Results:**
- [ ] Transaction **FAILS** after activation time
- [ ] Error: UTXO is blocked

**❌ FAIL Criteria:**
- UTXO blocked immediately (should wait for timestamp)
- UTXO never gets blocked after timestamp
- Wrong activation time

---

## Test Scenario 4: UTXO_STATIC_BLOCKLIST Flag

**Purpose:** Verify that UTXO_STATIC_BLOCKLIST makes blocklist immutable.

### Step 4.1: Create Token with Static Blocklist

```bash
# Create new test token
cellframe-node-cli token_decl \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST2 \
    -total_supply 1000000.0 \
    -signs_total 1 \
    -signs_emission 1 \
    -decimals 18 \
    -flag_set UTXO_STATIC_BLOCKLIST \
    -certs token_owner_cert

# Expected: Token with static blocklist created
```

**✅ Verification:**
- [ ] Token created successfully
- [ ] UTXO_STATIC_BLOCKLIST flag is set

### Step 4.2: Create and Block UTXO

```bash
# Create emission and transaction (similar to Step 2-3 from setup)
# Then block UTXO
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST2 \
    -utxo_blocked_add <tx_hash>:0 \
    -certs token_owner_cert

# Expected: UTXO blocked successfully
```

**✅ Expected Results:**
- [ ] UTXO blocked successfully

### Step 4.3: Attempt to Unblock (Should FAIL)

```bash
# Try to remove UTXO from blocklist (should FAIL)
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST2 \
    -utxo_blocked_remove <tx_hash>:0 \
    -certs token_owner_cert

# Expected: ERROR - blocklist is static
```

**✅ Expected Results:**
- [ ] Command **FAILS**
- [ ] Error message: blocklist is immutable/static
- [ ] UTXO remains blocked

### Step 4.4: Attempt to Clear Blocklist (Should FAIL)

```bash
# Try to clear entire blocklist (should FAIL)
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST2 \
    -utxo_blocked_clear \
    -certs token_owner_cert

# Expected: ERROR - blocklist is static
```

**✅ Expected Results:**
- [ ] Command **FAILS**
- [ ] Error indicates static blocklist
- [ ] Blocklist unchanged

**❌ FAIL Criteria:**
- Successfully unblocked UTXO (should be immutable)
- Successfully cleared blocklist (should be immutable)
- No error message about static blocklist

---

## Test Scenario 5: UTXO_BLOCKING_DISABLED Flag

**Purpose:** Verify that UTXO_BLOCKING_DISABLED prevents all blocking operations.

### Step 5.1: Set UTXO_BLOCKING_DISABLED Flag

```bash
# Enable blocking disabled flag
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -flag_set UTXO_BLOCKING_DISABLED \
    -certs token_owner_cert

# Expected: Flag set successfully
```

**✅ Verification:**
- [ ] Command succeeds
- [ ] Flag is set in token info

### Step 5.2: Verify Token Info Shows Flag

```bash
# Check token info
cellframe-node-cli token_info \
    -net YOUR_NETWORK \
    -name QATEST

# Expected: UTXO_BLOCKING_DISABLED flag visible
```

**✅ Verification:**
- [ ] UTXO_BLOCKING_DISABLED appears in flags list

### Step 5.3: Attempt to Block UTXO (Should FAIL)

```bash
# Create new transaction
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr <user_wallet_address> \
    -value 200.0 \
    -fee 0.0

TX_HASH_3=<tx_hash>

# Try to block UTXO (should FAIL)
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add ${TX_HASH_3}:0 \
    -certs token_owner_cert

# Expected: ERROR - blocking is disabled
```

**✅ Expected Results:**
- [ ] Command **FAILS**
- [ ] Error code: `DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN`
- [ ] Error message indicates blocking is disabled

### Step 5.4: Verify UTXO is Spendable

```bash
# Try to spend the UTXO (should SUCCEED)
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet user_wallet \
    -to_addr <owner_wallet_address> \
    -value 100.0 \
    -fee 0.0

# Expected: Transaction succeeds (no blocking)
```

**✅ Expected Results:**
- [ ] Transaction **SUCCEEDS**
- [ ] UTXO can be spent normally

**❌ FAIL Criteria:**
- Successfully blocked UTXO when blocking is disabled
- Cannot spend UTXO (blocking still active)

---

## Test Scenario 6: Arbitrage Transactions

**Purpose:** Verify arbitrage transactions work correctly and only send to fee address.

### Step 6.1: Check Network Fee Address

```bash
# Get network fee address
cellframe-node-cli net get -net YOUR_NETWORK fee_addr

# Save the fee address
FEE_ADDR=<network_fee_address>

# Expected: Valid fee address returned
```

**✅ Verification:**
- [ ] Fee address is configured
- [ ] Fee address is valid format

**⚠️ CRITICAL:** If fee address is NOT configured or blank, arbitrage transactions will fail. Contact network administrator.

### Step 6.2: Create and Block UTXO for Testing

```bash
# First, unset UTXO_BLOCKING_DISABLED if set
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -flag_unset UTXO_BLOCKING_DISABLED \
    -certs token_owner_cert

# Create transaction
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr <user_wallet_address> \
    -value 5000.0 \
    -fee 0.0

TX_HASH_ARB=<tx_hash>

# Block the UTXO
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add ${TX_HASH_ARB}:0 \
    -certs token_owner_cert

# Expected: UTXO blocked successfully
```

**✅ Verification:**
- [ ] UTXO blocked successfully
- [ ] Regular transactions fail

### Step 6.3: Create Arbitrage Transaction to Fee Address

```bash
# Create arbitrage transaction to network fee address
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr ${FEE_ADDR} \
    -value 5000.0 \
    -fee 0.0 \
    -arbitrage \
    -certs token_owner_cert

# Expected: Transaction SUCCEEDS (bypasses UTXO block)
```

**✅ Expected Results:**
- [ ] Arbitrage transaction **SUCCEEDS**
- [ ] UTXO block bypassed
- [ ] Funds transferred to fee address

### Step 6.4: Verify Funds Arrived at Fee Address

```bash
# Check balance at fee address
cellframe-node-cli wallet info -w <fee_wallet> -net YOUR_NETWORK

# Expected: 5000.0 QATEST tokens received
```

**✅ Verification:**
- [ ] Balance at fee address = 5000.0 QATEST
- [ ] Transaction confirmed

### Step 6.5: Attempt Arbitrage to Non-Fee Address (Should FAIL)

```bash
# Create another blocked UTXO
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr <user_wallet_address> \
    -value 3000.0 \
    -fee 0.0

TX_HASH_ARB2=<tx_hash>

cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add ${TX_HASH_ARB2}:0 \
    -certs token_owner_cert

# Try arbitrage to user address (NOT fee address - should FAIL)
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr <user_wallet_address> \
    -value 3000.0 \
    -fee 0.0 \
    -arbitrage \
    -certs token_owner_cert

# Expected: ERROR - output not to fee address
```

**✅ Expected Results:**
- [ ] Transaction **FAILS**
- [ ] Error code: `DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED`
- [ ] Error message: outputs must go to fee address

**❌ FAIL Criteria:**
- Arbitrage succeeds to non-fee address (SECURITY BUG!)
- Funds go to unauthorized address
- No error about fee address requirement

---

## Test Scenario 7: UTXO_ARBITRAGE_TX_DISABLED Flag

**Purpose:** Verify that arbitrage can be permanently disabled.

### Step 7.1: Disable Arbitrage

```bash
# Set UTXO_ARBITRAGE_TX_DISABLED flag
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -flag_set UTXO_ARBITRAGE_TX_DISABLED \
    -certs token_owner_cert

# Expected: Flag set successfully
```

**✅ Verification:**
- [ ] Command succeeds
- [ ] Flag appears in token info

### Step 7.2: Verify Token Info

```bash
# Check token info
cellframe-node-cli token_info \
    -net YOUR_NETWORK \
    -name QATEST

# Expected: UTXO_ARBITRAGE_TX_DISABLED in flags
```

**✅ Verification:**
- [ ] Flag visible in token info

### Step 7.3: Attempt Arbitrage Transaction (Should FAIL)

```bash
# Create and block UTXO
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr <user_wallet_address> \
    -value 1000.0 \
    -fee 0.0

TX_HASH_NOARB=<tx_hash>

cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add ${TX_HASH_NOARB}:0 \
    -certs token_owner_cert

# Try arbitrage (should FAIL)
cellframe-node-cli tx_create \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -from_wallet owner_wallet \
    -to_addr ${FEE_ADDR} \
    -value 1000.0 \
    -fee 0.0 \
    -arbitrage \
    -certs token_owner_cert

# Expected: ERROR - arbitrage disabled
```

**✅ Expected Results:**
- [ ] Transaction **FAILS**
- [ ] Error: arbitrage is disabled for this token

### Step 7.4: Attempt to Re-enable Arbitrage (Should FAIL)

```bash
# Try to unset UTXO_ARBITRAGE_TX_DISABLED (should FAIL - irreversible)
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -flag_unset UTXO_ARBITRAGE_TX_DISABLED \
    -certs token_owner_cert

# Expected: ERROR - flag is irreversible
```

**✅ Expected Results:**
- [ ] Command **FAILS**
- [ ] Error: cannot unset irreversible flag
- [ ] Flag remains set

**❌ FAIL Criteria:**
- Arbitrage succeeds when disabled
- Successfully unset irreversible flag (CRITICAL BUG!)

---

## Test Scenario 8: Negative Tests

**Purpose:** Verify proper error handling for invalid inputs.

### Test 8.1: Invalid UTXO Format

```bash
# Try to block with invalid format
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add "invalid_format" \
    -certs token_owner_cert

# Expected: ERROR - invalid format
```

**✅ Expected:** Error about invalid UTXO format

### Test 8.2: Non-existent UTXO

```bash
# Try to block non-existent UTXO
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add 0x0000000000000000000000000000000000000000000000000000000000000000:0 \
    -certs token_owner_cert

# Expected: May succeed (blocking doesn't check existence)
# But spending will fail with "UTXO not found"
```

**✅ Expected:** No error (blocking accepts any format)

### Test 8.3: Unauthorized Certificate

```bash
# Try to block with wrong certificate
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_add <tx_hash>:0 \
    -certs wrong_cert

# Expected: ERROR - unauthorized
```

**✅ Expected:** Error about invalid/unauthorized signature

### Test 8.4: Clear Empty Blocklist

```bash
# Try to clear when blocklist is empty
cellframe-node-cli token_update \
    -net YOUR_NETWORK \
    -chain main \
    -token QATEST \
    -utxo_blocked_clear \
    -certs token_owner_cert

# Expected: SUCCESS (no-op)
```

**✅ Expected:** Success (idempotent operation)

---

## Verification Checklist

Use this checklist to verify all tests passed:

### Basic Functionality
- [ ] UTXO blocking works correctly
- [ ] UTXO unblocking works correctly
- [ ] Blocked UTXOs cannot be spent
- [ ] Unblocked UTXOs can be spent
- [ ] Token info displays blocklist correctly

### Delayed Activation
- [ ] UTXO can be blocked with future timestamp
- [ ] UTXO is spendable before activation time
- [ ] UTXO becomes blocked after activation time

### Flags
- [ ] UTXO_STATIC_BLOCKLIST prevents modifications
- [ ] UTXO_BLOCKING_DISABLED prevents all blocking
- [ ] UTXO_ARBITRAGE_TX_DISABLED prevents arbitrage
- [ ] Irreversible flags cannot be unset

### Arbitrage
- [ ] Arbitrage bypasses UTXO blocking
- [ ] Arbitrage ONLY sends to fee address
- [ ] Arbitrage fails to non-fee addresses
- [ ] Arbitrage respects UTXO_ARBITRAGE_TX_DISABLED

### Error Handling
- [ ] Invalid UTXO format handled correctly
- [ ] Unauthorized operations rejected
- [ ] Proper error codes returned
- [ ] Error messages are clear

---

## Known Issues

### Issue #1: TSD Type Conflicts (RESOLVED)
**Status:** ✅ FIXED  
**Description:** DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE changed from 0x0001 to 0x00A1 to avoid conflicts with voting TSD types.

### Issue #2: uint16_t Flag Overflow (RESOLVED)
**Status:** ✅ FIXED  
**Description:** UTXO flags moved to dedicated TSD section to prevent overflow. Now stored as uint32_t.

### Issue #3: Arbitrage Security (RESOLVED)
**Status:** ✅ FIXED  
**Description:** Arbitrage transactions now only send to network fee address, not tx_recv_allow list.

---

## Reporting Bugs

If you find a bug during testing, please report with:

### Required Information
1. **Test Scenario Number** (e.g., Test Scenario 6.5)
2. **Expected Result** (what should happen)
3. **Actual Result** (what actually happened)
4. **Command Used** (exact CLI command)
5. **Error Message** (if any)
6. **Network Info** (network name, node version)
7. **Steps to Reproduce** (how to replicate)

### Bug Severity Levels

**CRITICAL (P0):**
- Arbitrage sends to non-fee address
- Irreversible flags can be unset
- Security bypass discovered

**HIGH (P1):**
- UTXO blocking doesn't work
- Flags don't persist
- Wrong error codes

**MEDIUM (P2):**
- UI/UX issues
- Unclear error messages
- Documentation errors

**LOW (P3):**
- Minor inconsistencies
- Cosmetic issues

### Example Bug Report

```
**Test Scenario:** 6.5 - Arbitrage to non-fee address
**Expected:** Transaction fails with DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED
**Actual:** Transaction succeeded and funds went to user address
**Command:** cellframe-node-cli tx_create -net Backbone -token QATEST -arbitrage ...
**Error:** None (should have error!)
**Network:** Backbone testnet, node v5.2.0
**Severity:** CRITICAL (P0) - Security issue
**Steps:**
1. Created arbitrage transaction
2. Set output to user address (not fee address)
3. Transaction was accepted
4. Funds transferred to unauthorized address
```

---

## Summary

This testing guide covers:
- ✅ 8 comprehensive test scenarios
- ✅ 40+ individual test steps
- ✅ Both positive and negative tests
- ✅ Clear pass/fail criteria
- ✅ Bug reporting guidelines

**Estimated Testing Time:** 2-3 hours for full suite

**Required Expertise:** Intermediate (blockchain knowledge helpful)

**Prerequisites:** Running node, test tokens, certificates

---

**Document Version:** 1.0  
**Last Updated:** 2025-10-22  
**Related Documentation:**
- [UTXO_BLOCKING_EXAMPLES.md](UTXO_BLOCKING_EXAMPLES.md)
- [UTXO_FLAGS_TSD_MIGRATION.md](UTXO_FLAGS_TSD_MIGRATION.md)
- [UTXO_MIGRATION_SUMMARY.md](UTXO_MIGRATION_SUMMARY.md)

**Questions?** Contact development team with issue #19886 reference.

