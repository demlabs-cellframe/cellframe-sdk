# DEX v2 Diagrams

## Overview

```mermaid
flowchart LR

subgraph A["Single-order partial fill"]
  O_prev["OUT_COND(SRV_DEX) V_prev"] -- "IN_COND(prev_hash,out_idx)" --> TX1["TX_EXCHANGE"]
  TX1 --> R["OUT_COND(SRV_DEX) V_out = V_prev - c"]
  TX1 --> P["Payout seller: c * rate"]
  R -. "references IN_COND" .- TX1
end

subgraph B["Multi-order fill (no residual)"]
  O1["OUT_COND V1"] -- "IN_COND 1 (full)" --> TX2["TX_EXCHANGE"]
  O2["OUT_COND V2"] -- "IN_COND 2 (full)" --> TX2
  TX2 --> P1["Payouts Σ S_i * rate_i"]
end

subgraph C["Multi-order with single residual (IN[0] partial)"]
  O_full["OUT_COND V_full"] -- "IN_COND x (full)" --> TX3["TX_EXCHANGE"]
  O_part["OUT_COND V_prev(k+1)"] -- "IN_COND 0 (partial)" --> TX3
  TX3 --> Rc["OUT_COND(SRV_DEX) V_out = V_prev - c'"]
  TX3 --> P2["Payouts Σ S_i * rate_i"]
  Rc -. "references IN_COND 0" .- TX3
end

subgraph D["Order chain (head/tail)"]
  Head["Head (first_chain_tx_hash)"] --> E1["Exchange"] --> E2["Exchange …"] --> Tail["Tail (final_chain_tx_hash)"]
  E1 --> I1["Invalidate (terminal)"]
end

subgraph E["Multi-order all closed + new buyer order"]
  Oa["OUT_COND V1"] -- "IN_COND 1 (full)" --> TX4["TX_EXCHANGE"]
  Ob["OUT_COND V2"] -- "IN_COND 2 (full)" --> TX4
  TX4 --> P3["Payouts Σ S_i * rate_i"]
  TX4 --> Rb["NEW OUT_COND(SRV_DEX) (buyer leftover) V_new = C_total_sell - Σ S_i"]
end
```

## Transaction Types

```mermaid
flowchart TD

%% ORDER CREATE (seller opens order)
subgraph ORDER_CREATE[Order Create (SRV_DEX)]
  direction TB
  SELLER["Seller"] -- "IN: inputs token_sell (Σ inputs = V_sell + fees)<br/>optional IN for fee token(s)" --> TXO[TX_CREATE]
  TXO --> OUTC["OUT_COND(SRV_DEX) with params:<br/>- value V=V_sell<br/>- buy_token, rate, seller_addr"]
  TXO --> FEES1["Fees outputs: net_fee, validator_fee, service_fee (as policy)"]
  TXO --> CHANGE1["Change back (sell, fee coins) if any"]
end

%% EXCHANGE SINGLE (may be partial)
subgraph EX_SINGLE[Exchange (single order)]
  direction TB
  OC_PREV["Prev OUT_COND: V_prev"] -- "IN_COND[0] (prev_hash,out_idx)" --> TXE[TX_EXCHANGE]
  TXE --> CALC1["Compute: S = min(request, V_prev)<br/>B = S * rate<br/>L = V_prev - S"]
  TXE --> OUT_SELLER["OUT_EXT seller: +B (buy_token)"]
  TXE --> OUT_BUYER["OUT_EXT buyer: +S' (token_sell)<br/>S' may be S or (S - fee_if_native)"]
  TXE --> FEES2["Fees: net/service/validator"]
  L{L > 0?} -->|yes| OUT_RES["OUT_COND(SRV_DEX) residual: V_out=L (refs IN[0])"]
  L -->|no| NORES["No residual OUT_COND"]
end

%% EXCHANGE MULTI (all full)
subgraph EX_MULTI_ALL_FULL[Exchange (multi-orders, all full)]
  direction TB
  O1[OUT_COND V1] -- "IN_COND 1 (full)" --> TXM[TX_EXCHANGE]
  O2[OUT_COND V2] -- "IN_COND 2 (full)" --> TXM
  dots((...)) -- "IN_COND i (full)" --> TXM
  TXM --> CALC2["S_i = V_i; B_i = S_i * rate_i<br/>ΣS = ΣV_i; ΣB = Σ(S_i*rate_i)"]
  TXM --> PAY_SELLERS["Payout sellers: ΣB (per-seller, per-token)"]
  TXM --> PAY_BUYER["Buyer receives ΣS' (sell token)"]
  TXM --> FEES3[Fees]
  TXM --> NORES2["No residual OUT_COND"]
end

%% EXCHANGE MULTI (one partial IN[0])
subgraph EX_MULTI_ONE_PARTIAL[Exchange (multi-orders, one partial IN[0])]
  direction TB
  OP[OUT_COND V_prev(k+1)] -- "IN_COND 0 (partial)" --> TXMP[TX_EXCHANGE]
  OF[OUT_COND V_full] -- "IN_COND i (full)" --> TXMP
  TXMP --> CALC3["For full i: S_i=V_i, B_i=S_i*rate_i<br/>For partial 0: S_0=c', L_0=V_prev - c'<br/>Totals: ΣS, ΣB"]
  TXMP --> PAY_SELLERS2["Payout sellers: ΣB"]
  TXMP --> OUT_RES0["Residual OUT_COND (only one): V_out=L_0 (refs IN[0])"]
  TXMP --> FEES4[Fees]
end

%% EXCHANGE MULTI (all closed + new buyer order)
subgraph EX_MULTI_NEW_BUYER_ORDER[Exchange (all sellers closed, new buyer order)]
  direction TB
  Oa[OUT_COND V1] -- "IN_COND 1 (full)" --> TXB[TX_EXCHANGE]
  Ob[OUT_COND V2] -- "IN_COND 2 (full)" --> TXB
  TXB --> CALC4["Requested buy capacity C_total (in sell token).<br/>Consumed ΣS = ΣV_i.<br/>Buyer leftover L_buy = max(0, C_total - ΣS)."]
  TXB --> PAY_SELLERS3["Payout sellers: Σ(S_i*rate_i)"]
  Lb{L_buy > 0?} -->|yes| NEW_ORDER["NEW OUT_COND(SRV_DEX) for buyer leftover: V_new=L_buy<br/>(acts as order)"]
  Lb -->|no| NONEW["No new buyer order"]
  TXB --> FEES5[Fees]
end

%% INVALIDATE (order removal)
subgraph INVALIDATE[Invalidate (close order by owner)]
  direction TB
  OCX[Prev OUT_COND V_prev] -- "IN_COND (prev_hash,out_idx)" --> TXI[TX_INVALIDATE]
  TXI --> BACK_SELLER["Return V_prev to seller (token_sell)"]
  TXI --> FEES6[Fees]
end
```

## Order Create

```mermaid
flowchart LR

subgraph ORDER_CREATE["TX_CREATE (datum)"]
  SELLER["Seller"]
  FEE_IN["Fee inputs"]
  OUT_ORDER["OUT_COND(SRV_DEX)<br/>value V = V_sell<br/>buy_token, rate, seller_addr"]
  OUT_NET["OUT_EXT net_fee (native)"]
  OUT_VAL["FEE validator"]
  OUT_SRV["FEE service (policy)"]
  OUT_CHG_SELL["OUT_EXT change (sell_token)"]
  OUT_CHG_FEE["OUT_EXT change (native fee)"]
  CALC["Calc:<br/>Require: V_sell>0, rate>0<br/>If sell_token==native: ΣIN_sell ≥ V_sell+Σfees; else: ΣIN_sell ≥ V_sell and ΣIN_fee ≥ Σfees<br/>Change = inputs - required"]
  SELLER -- "IN: Σ inputs(sell_token) = V_sell + Δ_native_fees?<br/>(if native fee is taken from sell)" --> CALC
  FEE_IN -- "IN: optional fee inputs (native)" --> CALC
  CALC --> OUT_ORDER
  CALC --> OUT_CHG_SELL
  CALC --> OUT_VAL
  CALC --> OUT_NET
  CALC --> OUT_SRV
  CALC --> OUT_CHG_FEE
end
```

## Exchange (Single Order)

```mermaid
flowchart LR

subgraph EX_SINGLE["TX_EXCHANGE (single order)"]
  direction TB
  PREV["Prev TX: OUT_COND(SRV_DEX) V_prev"]
  CALC["Calc:<br/>S = min(request, V_prev)<br/>B = S * rate<br/>L = V_prev - S<br/>If sell==native: S' = S - fee_native; else: S' = S"]
  OUT_RES["OUT_COND(SRV_DEX) residual<br/>V_out = L (refs IN[0])"]
  OUT_PAY_SELLER["OUT_EXT seller: +B (buy_token)"]
  OUT_PAY_BUYER["OUT_EXT buyer: +S' (sell_token)"]
  FEES["Fees: net/validator/service"]
  PREV -- "IN_COND[0] (prev_hash,out_idx)" --> CALC
  CALC --> OUT_RES
  CALC --> OUT_PAY_SELLER
  CALC --> OUT_PAY_BUYER
  CALC --> FEES
end
```

## Exchange (Multi, All Full)

```mermaid
flowchart LR

subgraph EX_MULTI_ALL_FULL["TX_EXCHANGE (multi-orders, all full)"]
  direction TB
  PREV1["Prev TX1: OUT_COND V1"]
  PREV2["Prev TX2: OUT_COND V2"]
  DOTS(("..."))
  CALC["Calc:<br/>For each i: S_i = V_i; B_i = S_i*rate_i<br/>SumS = ΣS_i = ΣV_i<br/>SumB = ΣB_i = Σ(S_i*rate_i)"]
  OUT_PAY_SELLERS["Σ OUT_EXT seller_i: +B_i (token_i)"]
  OUT_PAY_BUYER["OUT_EXT buyer: +SumS' (sell_token)"]
  FEES["Fees: net/validator/service"]
  PREV1 -- "IN_COND 1 (full)" --> CALC
  PREV2 -- "IN_COND 2 (full)" --> CALC
  DOTS -- "IN_COND i (full)" --> CALC
  CALC --> OUT_PAY_SELLERS
  CALC --> OUT_PAY_BUYER
  CALC --> FEES
end
```

## Exchange (Multi, One Partial)

```mermaid
flowchart LR

subgraph EX_MULTI_ONE_PARTIAL["TX_EXCHANGE (multi-orders, one partial IN[0])"]
  direction TB
  PREV_PART["Prev TX(k+1): OUT_COND V_prev"]
  PREV_FULL["Prev TXi: OUT_COND V_full"]
  CALC["Calc:<br/>Full i: S_i=V_full; B_i=S_i*rate_i<br/>Partial 0: S0=c', L0=V_prev - c'<br/>SumS = S0 + ΣS_i<br/>SumB = B0 + ΣB_i (B0=S0*rate0)"]
  OUT_RES["OUT_COND(SRV_DEX) residual: V_out=L0 (refs IN[0])"]
  OUT_PAY_SELLERS["Σ OUT_EXT seller_j: +B_j (token_j)"]
  OUT_PAY_BUYER["OUT_EXT buyer: +SumS' (sell_token)"]
  FEES["Fees"]
  PREV_PART -- "IN_COND 0 (partial)" --> CALC
  PREV_FULL -- "IN_COND i (full)" --> CALC
  CALC --> OUT_RES
  CALC --> OUT_PAY_SELLERS
  CALC --> OUT_PAY_BUYER
  CALC --> FEES
end
```

## Exchange (Multi, New Buyer Order)

```mermaid
flowchart LR

subgraph EX_MULTI_NEW_BUYER_ORDER["TX_EXCHANGE (all sellers closed + new buyer order)"]
  direction TB
  PREV1["Prev TX1: OUT_COND V1"]
  PREV2["Prev TX2: OUT_COND V2"]
  CALC["Calc:<br/>Buy capacity C_total (in sell token)<br/>SumS = ΣV_i<br/>L_buy = max(0, C_total - SumS)"]
  OUT_PAY_SELLERS["Σ OUT_EXT seller_i: + (V_i*rate_i)"]
  OUT_PAY_BUYER["OUT_EXT buyer: +SumS' (sell token)"]
  OUT_NEW_ORDER["NEW OUT_COND(SRV_DEX): V_new = L_buy (acts as order)"]
  FEES["Fees"]
  PREV1 -- "IN_COND 1 (full)" --> CALC
  PREV2 -- "IN_COND 2 (full)" --> CALC
  CALC --> OUT_PAY_SELLERS
  CALC --> OUT_PAY_BUYER
  CALC --> FEES
  CALC --> OUT_NEW_ORDER
end
```

## Invalidate

```mermaid
flowchart LR

subgraph INVALIDATE["TX_INVALIDATE (owner closes order)"]
  direction TB
  PREV["Prev TX: OUT_COND V_prev"]
  CALC["Calc:<br/>Return V_prev to seller<br/>Check owner signature"]
  OUT_BACK["OUT_EXT seller: +V_prev (sell token)"]
  FEES["Fees"]
  PREV -- "IN_COND (prev_hash,out_idx)" --> CALC
  CALC --> OUT_BACK
  CALC --> FEES
end
```
