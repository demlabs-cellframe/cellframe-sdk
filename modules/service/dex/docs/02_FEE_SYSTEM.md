# DEX v2 Fee System

## Fee Types Overview

| Fee Type | Purpose | Payer | Recipient | Token |
|----------|---------|-------|-----------|-------|
| **Validator Fee** | TX validation reward | Taker (buyer) | Validator | Native |
| **Network Fee** | Network maintenance | Taker (buyer) | Network collector | Native |
| **Service Fee** | DEX service revenue | Taker (buyer) | Service wallet | Native or INPUT |

---

## Fee Constants

```c
#define DAP_DEX_FEE_UNIT_NATIVE  10000000000000000ULL   // 0.01 native (per-pair step)
#define DAP_DEX_FEE_STEP_PCT     1000000000000000ULL    // 0.001 (0.1% step)
#define DAP_DEX_POW18            1000000000000000000ULL // 1.0 (scale factor)
```

---

## Service Fee Configuration

### fee_config Field Structure

```
Byte: [bit7: mode] [bits 6..0: value]
```

| Bit 7 | Mode | Value Interpretation |
|-------|------|---------------------|
| 0 | Native | Absolute fee in native token |
| 1 | Percent | Percentage of INPUT token |

### Native Mode (bit7 = 0)

```c
fee_amount = value * DAP_DEX_FEE_UNIT_NATIVE  // value × 0.01 native
```

| fee_config | Calculation | Result |
|------------|-------------|--------|
| 0x00 | Fallback to global | s_dex_native_fee_amount |
| 0x01 | 1 × 0.01 | 0.01 native |
| 0x05 | 5 × 0.01 | 0.05 native |
| 0x7F | 127 × 0.01 | 1.27 native |

### Percent Mode (bit7 = 1)

```c
fee_pct = value & 0x7F  // 0-100 in 0.1% steps
fee_amount = INPUT_amount × fee_pct / 1000
```

| fee_config | Percentage | Meaning |
|------------|------------|---------|
| 0x80 | 0.0% | Fee disabled |
| 0x81 | 0.1% | 0.1% of INPUT |
| 0x8A | 1.0% | 1% of INPUT |
| 0x94 | 2.0% | 2% of INPUT |
| 0xE4 | 10.0% | 10% of INPUT (0x80 + 100) |

### INPUT Token Definition

The INPUT token depends on trade direction:

| Trade Side | Taker Action | INPUT Token | Fee Token |
|------------|--------------|-------------|-----------|
| ASK | Buys BASE, pays QUOTE | QUOTE | QUOTE |
| BID | Sells BASE, gets QUOTE | BASE | BASE |

---

## Fee Calculation Flow

### Step 1: Read Configuration

```c
pthread_rwlock_rdlock(&s_dex_cache_rwlock);
l_srv_addr = s_dex_service_fee_addr;
l_fee_cfg = l_pair_idx->key.fee_config;
l_native_fee_cached = s_dex_native_fee_amount;
pthread_rwlock_unlock(&s_dex_cache_rwlock);
```

### Step 2: Compute Fee Amount

```c
if ((l_fee_cfg & 0x80) == 0) {
    // Native mode
    uint8_t l_mult = l_fee_cfg & 0x7F;
    l_srv_fee_req = l_mult > 0 
        ? GET_256_FROM_64((uint64_t)l_mult * DAP_DEX_FEE_UNIT_NATIVE)
        : l_native_fee_cached;  // Fallback
    l_srv_ticker = l_native_ticker;
} else {
    // Percent mode
    uint8_t l_pct = l_fee_cfg & 0x7F;
    l_srv_ticker = l_is_bid ? l_pair_idx->key.token_base : l_pair_idx->key.token_quote;
    if (l_pct > 0) {
        l_srv_fee_req = (INPUT_amount × l_pct) / 1000;
    }
}
```

---

## Fee Waiver (Service Wallet)

When the **buyer is the service wallet**, service fee is waived:

```c
bool l_buyer_is_service = dap_chain_addr_compare(&l_buyer_addr, &l_reqs.service_addr);
if (l_buyer_is_service)
    l_reqs.fee_srv = uint256_0;
```

---

## Fee Aggregation

Service fee can be **aggregated** with seller payout to reduce TX outputs:

### Aggregation Conditions

| Fee Mode | Aggregation | Condition |
|----------|-------------|-----------|
| Percent (ASK) | Always | Fee in QUOTE = seller payout token |
| Percent (BID) | Always | Fee in BASE = seller payout token |
| Native (ASK) | Conditional | NATIVE == QUOTE |
| Native (BID) | Conditional | NATIVE == BASE |

### Aggregation Logic

```c
// For ASK trades
bool l_can_agg_ask = l_reqs.fee_pct_mode || l_native_is_quote;
if (l_can_agg_ask && seller == service_addr) {
    // Add fee to seller's payout instead of separate OUT
    seller_payout += service_fee;
}
```

---

## Fee Verification (Verificator)

The verificator validates fee correctness:

### Network Fee Check

```c
if (l_net_used && compare256(l_collected_net_fee, l_net_fee_req) < 0)
    RET_ERR(DEXV_NETWORK_FEE_UNDERPAID);
```

### Service Fee Check

```c
if (l_srv_used && compare256(l_collected_srv_fee, l_srv_fee_req) < 0)
    RET_ERR(DEXV_SERVICE_FEE_UNDERPAID);

if (l_srv_used && l_srv_addr_blank)
    RET_ERR(DEXV_SERVICE_FEE_ADDR_BLANK);  // Would burn tokens!
```

---

## Global Fee Configuration (Decree)

Service fee defaults are set via decree:

### DEX_DECREE_FEE_SET

Sets global native fee fallback and service wallet address:

```
Method: FEE_SET (1)
Required TSD:
  - FEE_AMOUNT (uint256_t) — fallback native fee amount
  - FEE_ADDR (dap_chain_addr_t) — service wallet address
```

### Applied State

```c
pthread_rwlock_wrlock(&s_dex_cache_rwlock);
s_dex_native_fee_amount = <fee_amount>;
s_dex_service_fee_addr = <fee_addr>;
pthread_rwlock_unlock(&s_dex_cache_rwlock);
```

---

## Per-Pair Fee Configuration (Decree)

### DEX_DECREE_PAIR_FEE_SET

```
Method: PAIR_FEE_SET (4)
Required TSD:
  - TOKEN_BASE, TOKEN_QUOTE
  - NET_BASE, NET_QUOTE
  - FEE_CONFIG (uint8_t)
```

### DEX_DECREE_PAIR_FEE_SET_ALL

```
Method: PAIR_FEE_SET_ALL (5)
Required TSD:
  - FEE_CONFIG (uint8_t)
```

Applies `fee_config` to ALL existing pairs.

---

## Fee Examples

### Example 1: Native Fee (0.05)

```
Pair: KEL/USDT
fee_config: 0x05 (native mode, 5 units)
Fee: 5 × 0.01 = 0.05 TestCoin (native)
```

### Example 2: Percent Fee (2%)

```
Pair: KEL/USDT
fee_config: 0x94 (percent mode, 20 = 2.0%)
Trade: Buyer pays 100 USDT
Fee: 100 × 20 / 1000 = 2.0 USDT
```

### Example 3: Exempt Pair (0%)

```
Pair: CELL/USDC
fee_config: 0x80 (percent mode, 0%)
Fee: 0 (exempt)
```

---

## Fee Flow Diagram

```
TAKER (Buyer)
     |
     +--[Validator Fee]----> Validator (FEE OUT_COND)
     |
     +--[Network Fee]------> Network Collector (OUT_STD)
     |
     +--[Service Fee]------> Service Wallet (OUT_STD or aggregated)
     |
     +--[Payment]----------> Sellers (via trade execution)
```



