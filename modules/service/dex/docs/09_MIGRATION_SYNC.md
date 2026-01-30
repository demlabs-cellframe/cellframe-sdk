# DEX v2 Migration (SRV_XCHANGE -> SRV_DEX)

## Overview

Migration moves **open legacy orders** from SRV_XCHANGE (v1) into SRV_DEX (v2).
The migrated order keeps the same economic meaning (amount and price) and becomes a normal DEX v2 order.

---

## Eligible Orders

Only **open** legacy orders can be migrated:

- Order must have an active SRV_XCHANGE conditional output (tail).
- The tail hash is the only valid input for migration or cancel.

---

## Hash Semantics

| Field | Meaning |
|-------|---------|
| `order_root` | Original SRV_XCHANGE order transaction hash |
| `order_hash` | Current tail (active SRV_XCHANGE conditional output) |

Rules:

- **Only `order_hash` (tail) is actionable.**
- `order_root` is an identifier for the order chain.

---

## CLI Usage

### List open legacy orders

```bash
srv_xchange orders -net <net_name> [-addr <seller_addr>]
```

Output fields:

| Field | Description |
|-------|-------------|
| `order_hash` | Tail hash (use for migration/cancel) |
| `order_root` | Root hash (optional) |
| `seller_addr` | Order owner address |
| `availability` | `migrate` or `cancel_only` |

### Migrate a legacy order

```bash
srv_dex migrate -net <net_name> -from <order_hash> -rate <new_rate> -fee <validator_fee> -w <wallet_path>
```

Notes:

- `-from` expects **tail hash** (`order_hash`).
- `-rate` uses legacy XCHANGE price semantics and is converted if needed.
- Use `srv_dex find_matches` for a preflight check of potential counter-matches and expected spend/receive amounts.

---

## Rate Semantics

Legacy SRV_XCHANGE price is **BUY per SELL**.
DEX v2 uses canonical **QUOTE / BASE**.

Conversion rule:

- If `sell_ticker > buy_ticker` (lexicographic), the rate is inverted:
  - `rate_canon = 1e18 / rate`

This preserves the original price meaning after canonicalization.

---

## Ownership and Fees

Ownership rule:

- Only the **order owner** can migrate the order.
- Wallet address must match `seller_addr`.

Fees:

- Migration pays **validator fee** (and optional network fee).
- **Trading service fees apply later**, during actual order execution.

---

## Governance Cutoffs

Migration can be disabled by policy:

- `DAP_CHAIN_POLICY_XCHANGE_MIGRATE_CUTOFF` disables migrations after the cutoff timestamp.
- `DAP_CHAIN_POLICY_XCHANGE_LEGACY_TX_CUTOFF` disables new legacy orders.

---

## Cache Behavior

Open legacy orders are tracked in the SRV_XCHANGE open cache:

- Cache stores `order_root`, `tail_hash`, `seller_addr`, tokens, rate, and remaining value.
- `srv_xchange orders` reads from this cache when enabled.

