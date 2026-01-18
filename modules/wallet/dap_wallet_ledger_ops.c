/*
 * Authors:
 * AI Refactoring 2026
 * 
 * Copyright: Demlabs
 * License: All rights reserved
 *
 * dap_wallet_ledger_ops.c - Implementation of wallet-ledger ops registry
 */

#include "dap_wallet_ledger_ops.h"
#include <pthread.h>

// Глобальная переменная для хранения зарегистрированных операций
static const dap_wallet_ledger_ops_t *s_wallet_ledger_ops = NULL;
static pthread_rwlock_t s_ops_lock = PTHREAD_RWLOCK_INITIALIZER;

/**
 * @brief Регистрирует реализацию ledger операций
 */
void dap_wallet_ledger_ops_register(const dap_wallet_ledger_ops_t *a_ops)
{
    pthread_rwlock_wrlock(&s_ops_lock);
    s_wallet_ledger_ops = a_ops;
    pthread_rwlock_unlock(&s_ops_lock);
}

/**
 * @brief Получает текущую реализацию ledger операций
 */
const dap_wallet_ledger_ops_t* dap_wallet_ledger_ops_get(void)
{
    const dap_wallet_ledger_ops_t *l_ops;
    pthread_rwlock_rdlock(&s_ops_lock);
    l_ops = s_wallet_ledger_ops;
    pthread_rwlock_unlock(&s_ops_lock);
    return l_ops;
}
