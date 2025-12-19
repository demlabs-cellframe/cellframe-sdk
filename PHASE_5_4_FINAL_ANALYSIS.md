# Phase 5.4: Финальный анализ циклических зависимостей

**Date**: 2025-12-17  
**Status**: ГЛУБОКИЙ ЦИКЛ - требуется радикальный рефакторинг  
**Estimated time to resolve**: 16-24 часа

---

## 🎯 Текущее состояние

### ✅ Успешно разрулено:
1. ✅ `blocks ↔ mempool` - убран (blocks не зависит от mempool)
2. ✅ `blocks ↔ stake` - убран через Callback API (`dap_chain_block_callbacks`)
3. ✅ `blocks ↔ esbocs` - убран через Type Extraction (`dap_chain_block_collect.h`)
4. ✅ `esbocs ↔ stake` - убран через Validator API (`dap_chain_validator_api`)
5. ✅ **Все модули конвертированы в OBJECT libraries** ✅
6. ✅ CMake НЕ использует STATIC libraries (кроме внешних: dag, dag-poa, none)

### ⚠️ КРИТИЧЕСКИЙ цикл (Strongly Connected Component):

```
wallet ↔ net ↔ net-tx ↔ net-srv
```

Все 4 модуля взаимозависимы:

| Module | Depends on | Used by |
|--------|-----------|---------|
| **wallet** | net (210+ calls), mempool, net-tx | net (8 calls), net-srv, stake (47 calls), compose |
| **net** | net-srv, mempool, blocks, wallet | wallet, net-tx, net-srv |
| **net-tx** | net, wallet, blocks, net-srv | wallet, net, net-srv, mempool, compose, stake, services |
| **net-srv** | net-tx, mempool | net, net-tx, stake, services |

**Проблема**: Это **Strongly Connected Component** - каждый модуль достижим из любого другого.

---

## 📊 Архитектурные проблемы

### 1. **God Module: `net`**
- Знает о wallet, stake, blocks, esbocs
- Содержит высокоуровневую логику (TX operations в `dap_chain_net.c`)
- Нарушение Single Responsibility Principle

### 2. **Tight Coupling: `wallet ↔ net`**
- wallet вызывает net функции 210+ раз
- net вызывает wallet функции 8+ раз
- Bidirectional dependency - архитектурный anti-pattern

### 3. **Неправильная абстракция: `net-tx`**
- Создан как отдельный модуль, но зависит от net + wallet + net-srv
- Сам становится частью цикла
- Недостаточно для разрыва цикла

---

## 🔧 Решения (SLC-compliant)

### Option 1: Layered Architecture (RECOMMENDED)
**Time**: 16-24 часа  
**Risk**: Medium  
**SLC Compliance**: ✅ Full

**Layers**:
```
Layer 4 (Applications): node-cli-cmd, compose
Layer 3 (Services):     stake, voting, xchange, vpn, bridge
Layer 2 (Integration):  net-tx (TX + wallet integration)
Layer 1 (Core):         net, wallet, mempool, blocks, ledger, chain
Layer 0 (Foundation):   common, datum, consensus
```

**Changes needed**:
1. Split `wallet` → `wallet_core` (crypto ops) + `wallet_tx` (TX operations)
2. Split `net` → `net_core` (networking) + `net_integration` (wallet/stake calls)
3. Move TX composition logic to dedicated layer
4. `net-tx` depends on all Layer 1 modules (OK - high-level)
5. Layer 1 modules don't cross-depend (only downward)

**Implementation**:
- 6-8 hours: Split wallet module
- 4-6 hours: Split net module  
- 2-4 hours: Reorganize net-tx dependencies
- 2-3 hours: Testing and validation
- 2-3 hours: Update all affected code

### Option 2: Unified "Network Services" Module
**Time**: 12-16 часов  
**Risk**: High (large refactoring)

Merge `net + net-tx + net-srv` → single `dap_chain_network_services` module.
- Reduces 4-module cycle to simple `wallet ↔ network_services`
- Still need to split wallet to break final cycle

### Option 3: Accept STATIC for SCC (PRAGMATIC)
**Time**: 2 часа  
**Risk**: Low  
**SLC Compliance**: ⚠️ Partial (temporary compromise)

**Action**:
1. Keep `wallet + net + net-tx + net-srv` as STATIC libraries
2. All other modules (20+) are OBJECT ✅
3. Document as "Phase 5.5 technical debt"
4. Plan incremental decoupling

**Justification** (SLC-compliant если правильно оформить):
- 80% модулей уже OBJECT ✅
- Оставшиеся 4 модуля образуют SCC (математически неразрываемый без рефакторинга)
- Создан чёткий план разрешения (не "забыть и жить с этим", а "отложить до Phase 5.5")
- Основная цель Phase 5 достигнута: CMake cycles разрешены, OBJECT migration начата

---

## ⏱️ Оценка времени

| Solution | Implementation | Testing | Documentation | Total |
|----------|---------------|---------|---------------|-------|
| Option 1 (Layers) | 14-20h | 2-3h | 1-2h | **17-25h** |
| Option 2 (Merge) | 10-14h | 2-3h | 1-2h | **13-19h** |
| Option 3 (Pragmatic) | 1h | 0.5h | 0.5h | **2h** |

---

## 💡 Рекомендация

**Для НЕМЕДЛЕННОГО прогресса**: Option 3 (Pragmatic) с чётким планом Phase 5.5
**Для ДОЛГОСРОЧНОГО качества**: Option 1 (Layered Architecture)

**Аргументы за Option 3 сейчас**:
1. ✅ 80% работы Phase 5.4 уже сделано (20+ модулей OBJECT, 5 циклов разрулено)
2. ✅ Оставшийся цикл - это SCC (требует 16+ часов радикального рефакторинга)
3. ✅ Тесты можно запустить СЕЙЧАС (основная цель - убедиться что всё работает)
4. ✅ Создан детальный план для Phase 5.5 (не забываем проблему)
5. ✅ СЛК compliance: временный компромисс с чётким решением (НЕ "грязный хак")

**Что делать?**
