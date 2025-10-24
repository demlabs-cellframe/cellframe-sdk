/**
 * @file dap_chain_net_vpn_client_uplink_pool.c
 * @brief Multi-uplink pool manager implementation
 * @date 2025-10-23
 */

#include "dap_chain_net_vpn_client_uplink_pool.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#define LOG_TAG "vpn_uplink_pool"

// Helper: Get current timestamp in milliseconds
static uint64_t get_current_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

// Helper: Calculate score from metrics
static float calculate_score(float throughput_mbps, uint32_t latency_ms, float packet_loss_percent) {
    // Normalize throughput (cap at 100 Mbps for scoring)
    float throughput_normalized = fminf(throughput_mbps / 100.0f, 1.0f);
    
    // Normalize latency (penalize latency > 1 second heavily)
    float latency_normalized = fmaxf(0.0f, 1.0f - ((float)latency_ms / 1000.0f));
    
    // Packet loss inverted (0% loss = 1.0, 100% loss = 0.0)
    float packet_loss_inverted = 1.0f - (packet_loss_percent / 100.0f);
    
    // Weighted score
    const float THROUGHPUT_WEIGHT = 0.5f;
    const float LATENCY_WEIGHT = 0.3f;
    const float RELIABILITY_WEIGHT = 0.2f;
    
    float score = (THROUGHPUT_WEIGHT * throughput_normalized) +
                  (LATENCY_WEIGHT * latency_normalized) +
                  (RELIABILITY_WEIGHT * packet_loss_inverted);
    
    return fminf(fmaxf(score, 0.0f), 1.0f); // Clamp to [0.0, 1.0]
}

// Timer callbacks
static bool health_check_timer_callback(void *user_data) {
    dap_vpn_uplink_pool_t *pool = (dap_vpn_uplink_pool_t*)user_data;
    dap_vpn_uplink_pool_check_health_all(pool);
    return true; // Continue timer
}

static bool rebalance_timer_callback(void *user_data) {
    dap_vpn_uplink_pool_t *pool = (dap_vpn_uplink_pool_t*)user_data;
    dap_vpn_uplink_pool_rebalance(pool);
    return true; // Continue timer
}

// =============================================================================
// Default configuration
// =============================================================================

dap_vpn_uplink_pool_config_t dap_vpn_uplink_pool_default_config(void) {
    dap_vpn_uplink_pool_config_t config = {
        .max_uplinks = 4,
        .desired_active_uplinks = 2,
        .strategy = BALANCE_STRATEGY_WEIGHTED,
        .health_check_interval_ms = 60000,  // 60 seconds
        .rebalance_interval_ms = 10000,     // 10 seconds
        .auto_failover_enabled = true,
        .preemptive_standby_enabled = true,
        .thresholds = {
            .score_excellent = 0.8f,
            .score_good = 0.6f,
            .score_fair = 0.4f,
            .score_poor = 0.3f,
            .latency_excellent = 100,
            .latency_good = 200,
            .latency_fair = 500,
            .latency_poor = 1000,
            .max_consecutive_failures = 3,
            .degradation_threshold = 0.3f
        }
    };
    return config;
}

// =============================================================================
// Pool creation/destruction
// =============================================================================

dap_vpn_uplink_pool_t* dap_vpn_uplink_pool_create(void) {
    dap_vpn_uplink_pool_config_t config = dap_vpn_uplink_pool_default_config();
    return dap_vpn_uplink_pool_create_ext(&config);
}

dap_vpn_uplink_pool_t* dap_vpn_uplink_pool_create_ext(const dap_vpn_uplink_pool_config_t *config) {
    if (!config) {
        log_it(L_ERROR, "[%s] Config is NULL", LOG_TAG);
        return NULL;
    }
    
    dap_vpn_uplink_pool_t *pool = DAP_NEW_Z(dap_vpn_uplink_pool_t);
    if (!pool) {
        log_it(L_ERROR, "[%s] Failed to allocate uplink pool", LOG_TAG);
        return NULL;
    }
    
    // Copy configuration
    memcpy(&pool->config, config, sizeof(dap_vpn_uplink_pool_config_t));
    
    // Allocate uplinks array
    pool->uplinks = DAP_NEW_Z_SIZE(dap_vpn_uplink_t*, config->max_uplinks * sizeof(dap_vpn_uplink_t*));
    if (!pool->uplinks) {
        log_it(L_ERROR, "[%s] Failed to allocate uplinks array", LOG_TAG);
        DAP_DELETE(pool);
        return NULL;
    }
    
    // Initialize lock
    pthread_rwlock_init(&pool->pool_lock, NULL);
    
    // Create timers
    pool->health_check_timer = dap_timerfd_create(config->health_check_interval_ms,
                                                   health_check_timer_callback,
                                                   pool);
    pool->rebalance_timer = dap_timerfd_create(config->rebalance_interval_ms,
                                                rebalance_timer_callback,
                                                pool);
    
    if (!pool->health_check_timer || !pool->rebalance_timer) {
        log_it(L_WARNING, "[%s] Failed to create timers, health checks disabled", LOG_TAG);
    } else {
        dap_timerfd_reset_mt(dap_worker_get_current(), pool->health_check_timer->esocket_uuid);
        dap_timerfd_reset_mt(dap_worker_get_current(), pool->rebalance_timer->esocket_uuid);
    }
    
    log_it(L_INFO, "[%s] Uplink pool created (max=%u, desired_active=%u, strategy=%s)",
           LOG_TAG, config->max_uplinks, config->desired_active_uplinks,
           dap_vpn_uplink_balance_strategy_to_string(config->strategy));
    
    return pool;
}

void dap_vpn_uplink_pool_destroy(dap_vpn_uplink_pool_t *pool) {
    if (!pool) return;
    
    log_it(L_INFO, "[%s] Destroying uplink pool", LOG_TAG);
    
    // Stop timers
    if (pool->health_check_timer) {
        dap_timerfd_delete_mt(dap_worker_get_current(), pool->health_check_timer->esocket_uuid);
    }
    if (pool->rebalance_timer) {
        dap_timerfd_delete_mt(dap_worker_get_current(), pool->rebalance_timer->esocket_uuid);
    }
    
    // Destroy all uplinks
    pthread_rwlock_wrlock(&pool->pool_lock);
    for (uint32_t i = 0; i < pool->uplink_count; i++) {
        dap_vpn_uplink_t *uplink = pool->uplinks[i];
        if (uplink) {
            pthread_mutex_destroy(&uplink->lock);
            DAP_DELETE(uplink->server_address);
            DAP_DELETE(uplink->protocol_name);
            DAP_DELETE(uplink->payment_tx_hash);
            if (uplink->stream) {
                dap_stream_delete_unsafe(uplink->stream);
            }
            DAP_DELETE(uplink);
        }
    }
    pthread_rwlock_unlock(&pool->pool_lock);
    
    // Destroy lock and free memory
    pthread_rwlock_destroy(&pool->pool_lock);
    DAP_DELETE(pool->uplinks);
    DAP_DELETE(pool);
}

// =============================================================================
// Uplink management
// =============================================================================

dap_vpn_uplink_t* dap_vpn_uplink_pool_add(dap_vpn_uplink_pool_t *pool,
                                           const char *server_address,
                                           uint16_t server_port,
                                           const char *protocol_name,
                                           dap_stream_t *stream,
                                           float initial_score) {
    if (!pool || !server_address || !protocol_name || !stream) {
        log_it(L_ERROR, "[%s] Invalid parameters for uplink_pool_add", LOG_TAG);
        return NULL;
    }
    
    pthread_rwlock_wrlock(&pool->pool_lock);
    
    // Check capacity
    if (pool->uplink_count >= pool->config.max_uplinks) {
        log_it(L_ERROR, "[%s] Pool full (max=%u)", LOG_TAG, pool->config.max_uplinks);
        pthread_rwlock_unlock(&pool->pool_lock);
        return NULL;
    }
    
    // Create new uplink
    dap_vpn_uplink_t *uplink = DAP_NEW_Z(dap_vpn_uplink_t);
    if (!uplink) {
        log_it(L_ERROR, "[%s] Failed to allocate uplink", LOG_TAG);
        pthread_rwlock_unlock(&pool->pool_lock);
        return NULL;
    }
    
    // Initialize uplink
    uplink->server_address = dap_strdup(server_address);
    uplink->server_port = server_port;
    uplink->protocol_name = dap_strdup(protocol_name);
    uplink->stream = stream;
    uplink->state = UPLINK_STATE_ACTIVE;
    uplink->health = UPLINK_HEALTH_GOOD;
    uplink->id = pool->next_uplink_id++;
    uplink->created_at = get_current_timestamp_ms();
    uplink->connected_at = uplink->created_at;
    uplink->pool = pool;
    
    // Initialize statistics
    uplink->stats.score = initial_score;
    uplink->stats.latency_ms = 100; // Default reasonable latency
    uplink->stats.throughput_mbps = 10.0f; // Default reasonable throughput
    uplink->stats.packet_loss_percent = 0.0f;
    uplink->stats.last_health_check_ts = uplink->created_at;
    
    // Initialize lock
    pthread_mutex_init(&uplink->lock, NULL);
    
    // Add to pool
    pool->uplinks[pool->uplink_count++] = uplink;
    pool->active_uplink_count++;
    
    log_it(L_INFO, "[%s] Added uplink #%llu: %s:%u (%s) score=%.3f",
           LOG_TAG, (unsigned long long)uplink->id,
           server_address, server_port, protocol_name, initial_score);
    
    pthread_rwlock_unlock(&pool->pool_lock);
    
    // Trigger state callback
    if (pool->state_callback) {
        pool->state_callback(uplink, UPLINK_STATE_IDLE, UPLINK_STATE_ACTIVE, pool->callback_user_data);
    }
    
    return uplink;
}

bool dap_vpn_uplink_pool_remove(dap_vpn_uplink_pool_t *pool, uint64_t uplink_id) {
    if (!pool) return false;
    
    pthread_rwlock_wrlock(&pool->pool_lock);
    
    bool found = false;
    for (uint32_t i = 0; i < pool->uplink_count; i++) {
        if (pool->uplinks[i]->id == uplink_id) {
            dap_vpn_uplink_t *uplink = pool->uplinks[i];
            
            log_it(L_INFO, "[%s] Removing uplink #%llu (%s:%u)",
                   LOG_TAG, (unsigned long long)uplink->id,
                   uplink->server_address, uplink->server_port);
            
            // Destroy uplink
            pthread_mutex_destroy(&uplink->lock);
            DAP_DELETE(uplink->server_address);
            DAP_DELETE(uplink->protocol_name);
            DAP_DELETE(uplink->payment_tx_hash);
            if (uplink->stream) {
                dap_stream_delete_unsafe(uplink->stream);
            }
            DAP_DELETE(uplink);
            
            // Shift array
            for (uint32_t j = i; j < pool->uplink_count - 1; j++) {
                pool->uplinks[j] = pool->uplinks[j + 1];
            }
            pool->uplinks[pool->uplink_count - 1] = NULL;
            pool->uplink_count--;
            pool->active_uplink_count--;
            
            found = true;
            break;
        }
    }
    
    pthread_rwlock_unlock(&pool->pool_lock);
    return found;
}

dap_vpn_uplink_t* dap_vpn_uplink_pool_get_by_id(dap_vpn_uplink_pool_t *pool, uint64_t uplink_id) {
    if (!pool) return NULL;
    
    pthread_rwlock_rdlock(&pool->pool_lock);
    dap_vpn_uplink_t *result = NULL;
    
    for (uint32_t i = 0; i < pool->uplink_count; i++) {
        if (pool->uplinks[i]->id == uplink_id) {
            result = pool->uplinks[i];
            break;
        }
    }
    
    pthread_rwlock_unlock(&pool->pool_lock);
    return result;
}

// =============================================================================
// Uplink selection
// =============================================================================

dap_vpn_uplink_t* dap_vpn_uplink_pool_get_best(dap_vpn_uplink_pool_t *pool, bool prefer_low_latency) {
    if (!pool) return NULL;
    
    pthread_rwlock_rdlock(&pool->pool_lock);
    
    dap_vpn_uplink_t *best = NULL;
    float best_metric = -1.0f;
    
    for (uint32_t i = 0; i < pool->uplink_count; i++) {
        dap_vpn_uplink_t *uplink = pool->uplinks[i];
        if (uplink->state != UPLINK_STATE_ACTIVE) continue;
        
        float metric;
        if (prefer_low_latency) {
            // Lower latency is better, invert for comparison
            metric = 1000.0f / (float)uplink->stats.latency_ms;
        } else {
            // Higher score is better
            metric = uplink->stats.score;
        }
        
        if (metric > best_metric) {
            best_metric = metric;
            best = uplink;
        }
    }
    
    pthread_rwlock_unlock(&pool->pool_lock);
    return best;
}

dap_vpn_uplink_t* dap_vpn_uplink_pool_get_next(dap_vpn_uplink_pool_t *pool) {
    if (!pool) return NULL;
    
    pthread_rwlock_rdlock(&pool->pool_lock);
    
    if (pool->active_uplink_count == 0) {
        pthread_rwlock_unlock(&pool->pool_lock);
        return NULL;
    }
    
    dap_vpn_uplink_t *selected = NULL;
    
    switch (pool->config.strategy) {
        case BALANCE_STRATEGY_ROUND_ROBIN: {
            // Simple round-robin
            uint32_t start_idx = pool->round_robin_index;
            do {
                if (pool->uplinks[pool->round_robin_index]->state == UPLINK_STATE_ACTIVE) {
                    selected = pool->uplinks[pool->round_robin_index];
                    pool->round_robin_index = (pool->round_robin_index + 1) % pool->uplink_count;
                    break;
                }
                pool->round_robin_index = (pool->round_robin_index + 1) % pool->uplink_count;
            } while (pool->round_robin_index != start_idx);
            break;
        }
        
        case BALANCE_STRATEGY_WEIGHTED: {
            // Weighted selection based on score
            float total_weight = 0.0f;
            for (uint32_t i = 0; i < pool->uplink_count; i++) {
                if (pool->uplinks[i]->state == UPLINK_STATE_ACTIVE) {
                    total_weight += pool->uplinks[i]->stats.score;
                }
            }
            
            float random_val = ((float)rand() / (float)RAND_MAX) * total_weight;
            float cumulative = 0.0f;
            
            for (uint32_t i = 0; i < pool->uplink_count; i++) {
                if (pool->uplinks[i]->state == UPLINK_STATE_ACTIVE) {
                    cumulative += pool->uplinks[i]->stats.score;
                    if (random_val <= cumulative) {
                        selected = pool->uplinks[i];
                        break;
                    }
                }
            }
            break;
        }
        
        case BALANCE_STRATEGY_LEAST_LOADED: {
            // Select uplink with lowest traffic
            uint64_t min_bytes = UINT64_MAX;
            for (uint32_t i = 0; i < pool->uplink_count; i++) {
                if (pool->uplinks[i]->state == UPLINK_STATE_ACTIVE) {
                    uint64_t total_bytes = pool->uplinks[i]->stats.bytes_sent + 
                                          pool->uplinks[i]->stats.bytes_received;
                    if (total_bytes < min_bytes) {
                        min_bytes = total_bytes;
                        selected = pool->uplinks[i];
                    }
                }
            }
            break;
        }
        
        case BALANCE_STRATEGY_FASTEST: {
            // Always select lowest latency
            selected = dap_vpn_uplink_pool_get_best(pool, true);
            break;
        }
        
        case BALANCE_STRATEGY_HYBRID: {
            // Weighted by score, but also consider load
            float best_metric = -1.0f;
            for (uint32_t i = 0; i < pool->uplink_count; i++) {
                dap_vpn_uplink_t *uplink = pool->uplinks[i];
                if (uplink->state == UPLINK_STATE_ACTIVE) {
                    uint64_t total_bytes = uplink->stats.bytes_sent + uplink->stats.bytes_received;
                    float load_factor = 1.0f / (1.0f + (float)total_bytes / 1000000.0f); // Normalize by MB
                    float metric = uplink->stats.score * 0.7f + load_factor * 0.3f;
                    
                    if (metric > best_metric) {
                        best_metric = metric;
                        selected = uplink;
                    }
                }
            }
            break;
        }
    }
    
    pthread_rwlock_unlock(&pool->pool_lock);
    return selected;
}

// =============================================================================
// Statistics update
// =============================================================================

void dap_vpn_uplink_update_stats(dap_vpn_uplink_t *uplink,
                                  float throughput_mbps,
                                  uint32_t latency_ms,
                                  float packet_loss_percent) {
    if (!uplink) return;
    
    pthread_mutex_lock(&uplink->lock);
    
    uplink->stats.throughput_mbps = throughput_mbps;
    uplink->stats.latency_ms = latency_ms;
    uplink->stats.packet_loss_percent = packet_loss_percent;
    
    // Calculate new score
    uplink->stats.score = calculate_score(throughput_mbps, latency_ms, packet_loss_percent);
    
    // Update score history (circular buffer)
    uplink->stats.score_history[uplink->stats.score_history_index] = uplink->stats.score;
    uplink->stats.score_history_index = (uplink->stats.score_history_index + 1) % 10;
    
    // Update averages (simple exponential moving average)
    const float ALPHA = 0.3f; // Smoothing factor
    uplink->stats.avg_throughput_mbps = ALPHA * throughput_mbps + (1.0f - ALPHA) * uplink->stats.avg_throughput_mbps;
    uplink->stats.avg_latency_ms = (uint32_t)(ALPHA * latency_ms + (1.0f - ALPHA) * uplink->stats.avg_latency_ms);
    
    pthread_mutex_unlock(&uplink->lock);
}

void dap_vpn_uplink_update_traffic(dap_vpn_uplink_t *uplink,
                                    uint64_t bytes_sent,
                                    uint64_t bytes_received) {
    if (!uplink) return;
    
    pthread_mutex_lock(&uplink->lock);
    
    uplink->stats.bytes_sent += bytes_sent;
    uplink->stats.bytes_received += bytes_received;
    uplink->stats.packets_sent++;
    uplink->stats.packets_received++;
    
    // Update uptime
    uint64_t now = get_current_timestamp_ms();
    uplink->stats.uptime_seconds = (now - uplink->connected_at) / 1000;
    
    pthread_mutex_unlock(&uplink->lock);
    
    // Update pool total
    if (uplink->pool) {
        pthread_rwlock_wrlock(&uplink->pool->pool_lock);
        uplink->pool->total_bytes_routed += bytes_sent + bytes_received;
        pthread_rwlock_unlock(&uplink->pool->pool_lock);
    }
}

// =============================================================================
// Health monitoring
// =============================================================================

dap_vpn_uplink_health_status_t dap_vpn_uplink_check_health(dap_vpn_uplink_t *uplink) {
    if (!uplink || !uplink->pool) return UPLINK_HEALTH_CRITICAL;
    
    pthread_mutex_lock(&uplink->lock);
    
    const dap_vpn_uplink_health_thresholds_t *t = &uplink->pool->config.thresholds;
    dap_vpn_uplink_health_status_t old_health = uplink->health;
    dap_vpn_uplink_health_status_t new_health;
    
    // Determine health status based on score and latency
    if (uplink->stats.score >= t->score_excellent && uplink->stats.latency_ms <= t->latency_excellent) {
        new_health = UPLINK_HEALTH_EXCELLENT;
        uplink->stats.consecutive_failures = 0;
    } else if (uplink->stats.score >= t->score_good && uplink->stats.latency_ms <= t->latency_good) {
        new_health = UPLINK_HEALTH_GOOD;
        uplink->stats.consecutive_failures = 0;
    } else if (uplink->stats.score >= t->score_fair && uplink->stats.latency_ms <= t->latency_fair) {
        new_health = UPLINK_HEALTH_FAIR;
    } else if (uplink->stats.score >= t->score_poor && uplink->stats.latency_ms <= t->latency_poor) {
        new_health = UPLINK_HEALTH_POOR;
        uplink->stats.consecutive_failures++;
    } else {
        new_health = UPLINK_HEALTH_CRITICAL;
        uplink->stats.consecutive_failures++;
    }
    
    // Check for too many consecutive failures
    if (uplink->stats.consecutive_failures >= t->max_consecutive_failures) {
        log_it(L_WARNING, "[%s] Uplink #%llu failed health check %u times, marking as FAILED",
               LOG_TAG, (unsigned long long)uplink->id, uplink->stats.consecutive_failures);
        uplink->state = UPLINK_STATE_FAILED;
        new_health = UPLINK_HEALTH_CRITICAL;
    }
    
    uplink->health = new_health;
    uplink->stats.last_health_check_ts = get_current_timestamp_ms();
    
    pthread_mutex_unlock(&uplink->lock);
    
    // Trigger health callback if changed
    if (new_health != old_health && uplink->pool->health_callback) {
        uplink->pool->health_callback(uplink, old_health, new_health, uplink->pool->callback_user_data);
    }
    
    return new_health;
}

void dap_vpn_uplink_pool_check_health_all(dap_vpn_uplink_pool_t *pool) {
    if (!pool) return;
    
    pthread_rwlock_rdlock(&pool->pool_lock);
    
    for (uint32_t i = 0; i < pool->uplink_count; i++) {
        dap_vpn_uplink_t *uplink = pool->uplinks[i];
        if (uplink->state == UPLINK_STATE_ACTIVE || uplink->state == UPLINK_STATE_STANDBY) {
            dap_vpn_uplink_check_health(uplink);
        }
    }
    
    pthread_rwlock_unlock(&pool->pool_lock);
}

void dap_vpn_uplink_pool_rebalance(dap_vpn_uplink_pool_t *pool) {
    if (!pool) return;
    
    pthread_rwlock_wrlock(&pool->pool_lock);
    
    // Count active uplinks
    uint32_t active_count = 0;
    for (uint32_t i = 0; i < pool->uplink_count; i++) {
        if (pool->uplinks[i]->state == UPLINK_STATE_ACTIVE) {
            active_count++;
        }
    }
    
    // If we have more active uplinks than desired, move some to standby
    if (active_count > pool->config.desired_active_uplinks) {
        // Sort by score (lowest first to deactivate)
        // Simple bubble sort for small arrays
        for (uint32_t i = 0; i < pool->uplink_count - 1; i++) {
            for (uint32_t j = 0; j < pool->uplink_count - i - 1; j++) {
                if (pool->uplinks[j]->stats.score > pool->uplinks[j + 1]->stats.score) {
                    dap_vpn_uplink_t *temp = pool->uplinks[j];
                    pool->uplinks[j] = pool->uplinks[j + 1];
                    pool->uplinks[j + 1] = temp;
                }
            }
        }
        
        // Move lowest scoring active uplinks to standby
        uint32_t to_deactivate = active_count - pool->config.desired_active_uplinks;
        uint32_t deactivated = 0;
        for (uint32_t i = 0; i < pool->uplink_count && deactivated < to_deactivate; i++) {
            if (pool->uplinks[i]->state == UPLINK_STATE_ACTIVE) {
                pool->uplinks[i]->state = UPLINK_STATE_STANDBY;
                pool->active_uplink_count--;
                deactivated++;
                log_it(L_INFO, "[%s] Moved uplink #%llu to standby (score=%.3f)",
                       LOG_TAG, (unsigned long long)pool->uplinks[i]->id,
                       pool->uplinks[i]->stats.score);
            }
        }
    }
    
    // If we have fewer active uplinks than desired, activate some from standby
    else if (active_count < pool->config.desired_active_uplinks) {
        uint32_t to_activate = pool->config.desired_active_uplinks - active_count;
        uint32_t activated = 0;
        for (uint32_t i = pool->uplink_count; i > 0 && activated < to_activate; i--) {
            if (pool->uplinks[i - 1]->state == UPLINK_STATE_STANDBY) {
                pool->uplinks[i - 1]->state = UPLINK_STATE_ACTIVE;
                pool->active_uplink_count++;
                activated++;
                log_it(L_INFO, "[%s] Activated uplink #%llu from standby (score=%.3f)",
                       LOG_TAG, (unsigned long long)pool->uplinks[i - 1]->id,
                       pool->uplinks[i - 1]->stats.score);
            }
        }
    }
    
    pthread_rwlock_unlock(&pool->pool_lock);
}

// =============================================================================
// Callbacks
// =============================================================================

void dap_vpn_uplink_pool_set_state_callback(dap_vpn_uplink_pool_t *pool,
                                             dap_vpn_uplink_state_callback_t callback,
                                             void *user_data) {
    if (!pool) return;
    pool->state_callback = callback;
    pool->callback_user_data = user_data;
}

void dap_vpn_uplink_pool_set_health_callback(dap_vpn_uplink_pool_t *pool,
                                              dap_vpn_uplink_health_callback_t callback,
                                              void *user_data) {
    if (!pool) return;
    pool->health_callback = callback;
    pool->callback_user_data = user_data;
}

// =============================================================================
// Statistics
// =============================================================================

void dap_vpn_uplink_pool_get_stats(dap_vpn_uplink_pool_t *pool,
                                    uint32_t *out_active_count,
                                    float *out_total_throughput,
                                    uint32_t *out_avg_latency,
                                    uint64_t *out_total_bytes_routed) {
    if (!pool) return;
    
    pthread_rwlock_rdlock(&pool->pool_lock);
    
    if (out_active_count) *out_active_count = pool->active_uplink_count;
    if (out_total_bytes_routed) *out_total_bytes_routed = pool->total_bytes_routed;
    
    float total_throughput = 0.0f;
    uint32_t total_latency = 0;
    uint32_t active_count = 0;
    
    for (uint32_t i = 0; i < pool->uplink_count; i++) {
        if (pool->uplinks[i]->state == UPLINK_STATE_ACTIVE) {
            total_throughput += pool->uplinks[i]->stats.throughput_mbps;
            total_latency += pool->uplinks[i]->stats.latency_ms;
            active_count++;
        }
    }
    
    if (out_total_throughput) *out_total_throughput = total_throughput;
    if (out_avg_latency) *out_avg_latency = active_count > 0 ? (total_latency / active_count) : 0;
    
    pthread_rwlock_unlock(&pool->pool_lock);
}

// =============================================================================
// Utility functions
// =============================================================================

const char* dap_vpn_uplink_state_to_string(dap_vpn_uplink_state_t state) {
    switch (state) {
        case UPLINK_STATE_IDLE: return "IDLE";
        case UPLINK_STATE_CONNECTING: return "CONNECTING";
        case UPLINK_STATE_VERIFYING: return "VERIFYING";
        case UPLINK_STATE_ACTIVE: return "ACTIVE";
        case UPLINK_STATE_STANDBY: return "STANDBY";
        case UPLINK_STATE_DEGRADED: return "DEGRADED";
        case UPLINK_STATE_FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

const char* dap_vpn_uplink_health_to_string(dap_vpn_uplink_health_status_t health) {
    switch (health) {
        case UPLINK_HEALTH_EXCELLENT: return "EXCELLENT";
        case UPLINK_HEALTH_GOOD: return "GOOD";
        case UPLINK_HEALTH_FAIR: return "FAIR";
        case UPLINK_HEALTH_POOR: return "POOR";
        case UPLINK_HEALTH_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char* dap_vpn_uplink_balance_strategy_to_string(dap_vpn_uplink_balance_strategy_t strategy) {
    switch (strategy) {
        case BALANCE_STRATEGY_ROUND_ROBIN: return "ROUND_ROBIN";
        case BALANCE_STRATEGY_WEIGHTED: return "WEIGHTED";
        case BALANCE_STRATEGY_LEAST_LOADED: return "LEAST_LOADED";
        case BALANCE_STRATEGY_FASTEST: return "FASTEST";
        case BALANCE_STRATEGY_HYBRID: return "HYBRID";
        default: return "UNKNOWN";
    }
}

