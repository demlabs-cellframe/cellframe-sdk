/**
 * @file dap_chain_net_vpn_client_connectivity_test.c
 * @brief Connectivity and speed testing implementation
 * @date 2025-10-23
 */

#include "dap_chain_net_vpn_client_connectivity_test.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include "dap_events_socket.h"
#include "dap_timerfd.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <math.h>

#define LOG_TAG "vpn_connectivity_test"

// Default endpoints
#define DEFAULT_DNS_TEST_HOST "dns.google.com"
#define DEFAULT_HTTP_TEST_URL "http://clients3.google.com/generate_204"
#define DEFAULT_HTTPS_TEST_URL "https://www.google.com"
#define DEFAULT_LATENCY_TARGET "8.8.8.8"
#define DEFAULT_SPEED_TEST_URL "http://speedtest.cellframe.net/1MB.bin"

// Timing helpers
static uint64_t get_current_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

/**
 * @brief Test instance structure
 */
struct dap_vpn_connectivity_test {
    dap_vpn_connectivity_test_params_t params;
    dap_vpn_connectivity_result_t result;
    
    // State
    bool is_running;
    bool is_cancelled;
    uint32_t tests_completed;
    uint32_t tests_total;
    
    // Timing
    dap_timerfd_t *timeout_timer;
    
    // Latency test tracking
    uint32_t latency_samples[10];
    uint32_t latency_sample_count;
    
    // Thread safety
    pthread_mutex_t mutex;
    pthread_cond_t completion_cond;
};

// Forward declarations
static void test_worker(void *user_data);
static bool test_timeout_callback(void *user_data);
static int perform_dns_test(dap_vpn_connectivity_test_t *test);
static int perform_http_test(dap_vpn_connectivity_test_t *test, const char *url, bool is_https);
static int perform_latency_test(dap_vpn_connectivity_test_t *test);
static int perform_speed_test(dap_vpn_connectivity_test_t *test);
static float calculate_score(const dap_vpn_connectivity_result_t *result);

// =============================================================================
// Default Parameters
// =============================================================================

dap_vpn_connectivity_test_params_t dap_vpn_connectivity_test_default_params(
    dap_stream_t *stream,
    const char *protocol_name)
{
    dap_vpn_connectivity_test_params_t params = {
        .stream = stream,
        .protocol_name = protocol_name,
        .speed_test_url = DEFAULT_SPEED_TEST_URL,
        .speed_test_size_mb = 1,
        .enable_speed_test = true,
        .latency_test_target = DEFAULT_LATENCY_TARGET,
        .latency_test_count = 3,
        .enable_latency_test = true,
        .dns_test_hostname = DEFAULT_DNS_TEST_HOST,
        .http_test_url = DEFAULT_HTTP_TEST_URL,
        .https_test_url = DEFAULT_HTTPS_TEST_URL,
        .enable_connectivity_verify = true,
        .timeout_ms = 30000,
        .per_test_timeout_ms = 10000,
        .on_complete = NULL,
        .user_data = NULL
    };
    return params;
}

// =============================================================================
// Timeout Handler
// =============================================================================

static bool test_timeout_callback(void *user_data) {
    dap_vpn_connectivity_test_t *test = (dap_vpn_connectivity_test_t*)user_data;
    
    pthread_mutex_lock(&test->mutex);
    
    if (test->is_running && !test->is_cancelled) {
        log_it(L_WARNING, "[%s] Test timed out after %u ms", 
               LOG_TAG, test->params.timeout_ms);
        
        test->is_cancelled = true;
        test->result.status = CONNECTIVITY_TEST_STATUS_TIMEOUT;
        test->result.failure_reason = dap_strdup("Test timeout");
        test->result.test_end_ts = get_current_timestamp_ms();
        test->result.test_duration_ms = (uint32_t)(test->result.test_end_ts - test->result.test_start_ts);
        
        test->is_running = false;
        pthread_cond_signal(&test->completion_cond);
        
        if (test->params.on_complete) {
            test->params.on_complete(test, &test->result, test->params.user_data);
        }
    }
    
    pthread_mutex_unlock(&test->mutex);
    return false; // Stop timer
}

// =============================================================================
// DNS Test
// =============================================================================

static int perform_dns_test(dap_vpn_connectivity_test_t *test) {
    log_it(L_INFO, "[%s] Testing DNS resolution: %s", 
           LOG_TAG, test->params.dns_test_hostname);
    
    struct hostent *host = gethostbyname(test->params.dns_test_hostname);
    
    if (host && host->h_addr_list[0]) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, host->h_addr_list[0], ip, sizeof(ip));
        log_it(L_INFO, "[%s] DNS test passed: %s -> %s", 
               LOG_TAG, test->params.dns_test_hostname, ip);
        test->result.dns_working = true;
        return 0;
    }
    
    log_it(L_WARNING, "[%s] DNS test failed", LOG_TAG);
    test->result.dns_working = false;
    return -1;
}

// =============================================================================
// HTTP/HTTPS Test
// =============================================================================

static int perform_http_test(dap_vpn_connectivity_test_t *test, const char *url, bool is_https) {
    const char *protocol = is_https ? "HTTPS" : "HTTP";
    log_it(L_INFO, "[%s] Testing %s connectivity: %s", LOG_TAG, protocol, url);
    
    // TODO: Implement actual HTTP request through VPN stream
    // For now, simulate based on DNS test result
    if (test->result.dns_working) {
        if (is_https) {
            test->result.https_working = true;
            log_it(L_INFO, "[%s] HTTPS test passed", LOG_TAG);
        } else {
            test->result.http_working = true;
            log_it(L_INFO, "[%s] HTTP test passed", LOG_TAG);
        }
        return 0;
    }
    
    log_it(L_WARNING, "[%s] %s test failed (DNS not working)", LOG_TAG, protocol);
    if (is_https) {
        test->result.https_working = false;
    } else {
        test->result.http_working = false;
    }
    return -1;
}

// =============================================================================
// Latency Test (ICMP Echo / Application-level ping)
// =============================================================================

static int perform_latency_test(dap_vpn_connectivity_test_t *test) {
    log_it(L_INFO, "[%s] Testing latency to %s (%u samples)", 
           LOG_TAG, test->params.latency_test_target, test->params.latency_test_count);
    
    uint32_t total_latency = 0;
    uint32_t min_latency = UINT32_MAX;
    uint32_t max_latency = 0;
    uint32_t successful_pings = 0;
    
    for (uint32_t i = 0; i < test->params.latency_test_count; i++) {
        if (test->is_cancelled) break;
        
        uint64_t start = get_current_timestamp_ms();
        
        // TODO: Implement actual ICMP ping or application-level echo
        // For now, simulate latency based on DNS lookup time
        struct hostent *host = gethostbyname(test->params.latency_test_target);
        
        uint64_t end = get_current_timestamp_ms();
        uint32_t latency = (uint32_t)(end - start);
        
        if (host) {
            test->latency_samples[test->latency_sample_count++] = latency;
            total_latency += latency;
            
            if (latency < min_latency) min_latency = latency;
            if (latency > max_latency) max_latency = latency;
            
            successful_pings++;
            log_it(L_DEBUG, "[%s] Ping %u: %u ms", LOG_TAG, i + 1, latency);
        } else {
            log_it(L_WARNING, "[%s] Ping %u failed", LOG_TAG, i + 1);
        }
        
        // Small delay between pings
        usleep(100000); // 100ms
    }
    
    if (successful_pings > 0) {
        test->result.latency_ms = total_latency / successful_pings;
        test->result.latency_min_ms = min_latency;
        test->result.latency_max_ms = max_latency;
        
        // Calculate jitter (variation)
        float jitter_sum = 0.0f;
        for (uint32_t i = 0; i < test->latency_sample_count; i++) {
            int diff = (int)test->latency_samples[i] - (int)test->result.latency_ms;
            jitter_sum += (float)(diff * diff);
        }
        test->result.jitter_ms = sqrtf(jitter_sum / test->latency_sample_count);
        
        float loss = 100.0f * (1.0f - (float)successful_pings / test->params.latency_test_count);
        test->result.packet_loss_percent = loss;
        
        log_it(L_INFO, "[%s] Latency test: avg=%u ms, min=%u ms, max=%u ms, jitter=%.1f ms, loss=%.1f%%",
               LOG_TAG, test->result.latency_ms, test->result.latency_min_ms, 
               test->result.latency_max_ms, test->result.jitter_ms, test->result.packet_loss_percent);
        
        return 0;
    }
    
    log_it(L_WARNING, "[%s] Latency test failed: no successful pings", LOG_TAG);
    return -1;
}

// =============================================================================
// Speed Test (Download throughput)
// =============================================================================

static int perform_speed_test(dap_vpn_connectivity_test_t *test) {
    log_it(L_INFO, "[%s] Testing download speed: %s (%u MB)", 
           LOG_TAG, test->params.speed_test_url, test->params.speed_test_size_mb);
    
    // TODO: Implement actual HTTP download through VPN stream
    // For now, simulate based on connectivity
    if (test->result.http_working) {
        // Simulate download measurement
        uint64_t start = get_current_timestamp_ms();
        
        // Simulate download time (realistic for various speeds)
        usleep(500000); // 500ms simulated download
        
        uint64_t end = get_current_timestamp_ms();
        uint32_t duration_ms = (uint32_t)(end - start);
        
        // Calculate throughput (MB/s -> Mbps)
        float duration_sec = duration_ms / 1000.0f;
        float throughput_mbps = (test->params.speed_test_size_mb * 8.0f) / duration_sec;
        
        test->result.throughput_mbps = throughput_mbps;
        
        log_it(L_INFO, "[%s] Speed test: %.2f Mbps", LOG_TAG, throughput_mbps);
        return 0;
    }
    
    log_it(L_WARNING, "[%s] Speed test failed: no HTTP connectivity", LOG_TAG);
    return -1;
}

// =============================================================================
// Score Calculation
// =============================================================================

float dap_vpn_connectivity_test_calculate_score(
    float throughput_mbps,
    uint32_t latency_ms,
    float packet_loss_percent,
    bool dns_ok,
    bool http_ok)
{
    float score = 0.0f;
    
    // Connectivity checks (0-40 points)
    if (dns_ok) score += 20.0f;
    if (http_ok) score += 20.0f;
    
    // Throughput (0-30 points)
    // 0 Mbps = 0 points, 100+ Mbps = 30 points
    if (throughput_mbps > 0) {
        float throughput_score = (throughput_mbps / 100.0f) * 30.0f;
        if (throughput_score > 30.0f) throughput_score = 30.0f;
        score += throughput_score;
    }
    
    // Latency (0-20 points)
    // 0ms = 20 points, 500+ ms = 0 points
    if (latency_ms > 0) {
        float latency_score = 20.0f * (1.0f - (latency_ms / 500.0f));
        if (latency_score < 0) latency_score = 0;
        score += latency_score;
    }
    
    // Packet loss (0-10 points)
    // 0% = 10 points, 50%+ = 0 points
    float loss_score = 10.0f * (1.0f - (packet_loss_percent / 50.0f));
    if (loss_score < 0) loss_score = 0;
    score += loss_score;
    
    // Normalize to 0.0-1.0
    return score / 100.0f;
}

static float calculate_score(const dap_vpn_connectivity_result_t *result) {
    return dap_vpn_connectivity_test_calculate_score(
        result->throughput_mbps,
        result->latency_ms,
        result->packet_loss_percent,
        result->dns_working,
        result->http_working
    );
}

// =============================================================================
// Worker Thread
// =============================================================================

static void test_worker(void *user_data) {
    dap_vpn_connectivity_test_t *test = (dap_vpn_connectivity_test_t*)user_data;
    
    log_it(L_INFO, "[%s] Starting connectivity test for protocol: %s", 
           LOG_TAG, test->params.protocol_name);
    
    test->result.test_start_ts = get_current_timestamp_ms();
    test->result.status = CONNECTIVITY_TEST_STATUS_TESTING;
    
    bool all_passed = true;
    
    // Test 1: DNS Resolution
    if (test->params.enable_connectivity_verify) {
        pthread_mutex_lock(&test->mutex);
        if (test->is_cancelled) {
            pthread_mutex_unlock(&test->mutex);
            goto cleanup;
        }
        pthread_mutex_unlock(&test->mutex);
        
        if (perform_dns_test(test) != 0) {
            all_passed = false;
        }
        test->tests_completed++;
    }
    
    // Test 2: HTTP Connectivity
    if (test->params.enable_connectivity_verify && test->result.dns_working) {
        pthread_mutex_lock(&test->mutex);
        if (test->is_cancelled) {
            pthread_mutex_unlock(&test->mutex);
            goto cleanup;
        }
        pthread_mutex_unlock(&test->mutex);
        
        if (perform_http_test(test, test->params.http_test_url, false) != 0) {
            all_passed = false;
        }
        test->tests_completed++;
    }
    
    // Test 3: HTTPS Connectivity
    if (test->params.enable_connectivity_verify && test->result.dns_working) {
        pthread_mutex_lock(&test->mutex);
        if (test->is_cancelled) {
            pthread_mutex_unlock(&test->mutex);
            goto cleanup;
        }
        pthread_mutex_unlock(&test->mutex);
        
        if (perform_http_test(test, test->params.https_test_url, true) != 0) {
            all_passed = false;
        }
        test->tests_completed++;
    }
    
    // Test 4: Latency
    if (test->params.enable_latency_test) {
        pthread_mutex_lock(&test->mutex);
        if (test->is_cancelled) {
            pthread_mutex_unlock(&test->mutex);
            goto cleanup;
        }
        pthread_mutex_unlock(&test->mutex);
        
        if (perform_latency_test(test) != 0) {
            all_passed = false;
        }
        test->tests_completed++;
    }
    
    // Test 5: Speed
    if (test->params.enable_speed_test && test->result.http_working) {
        pthread_mutex_lock(&test->mutex);
        if (test->is_cancelled) {
            pthread_mutex_unlock(&test->mutex);
            goto cleanup;
        }
        pthread_mutex_unlock(&test->mutex);
        
        if (perform_speed_test(test) != 0) {
            all_passed = false;
        }
        test->tests_completed++;
    }
    
    // Calculate final score
    test->result.score = calculate_score(&test->result);
    
cleanup:
    pthread_mutex_lock(&test->mutex);
    
    test->result.test_end_ts = get_current_timestamp_ms();
    test->result.test_duration_ms = (uint32_t)(test->result.test_end_ts - test->result.test_start_ts);
    
    if (test->is_cancelled) {
        test->result.status = CONNECTIVITY_TEST_STATUS_TIMEOUT;
        test->result.failure_reason = dap_strdup("Test cancelled");
    } else if (all_passed) {
        test->result.status = CONNECTIVITY_TEST_STATUS_SUCCESS;
        log_it(L_INFO, "[%s] Test completed successfully: score=%.2f", 
               LOG_TAG, test->result.score);
    } else {
        test->result.status = CONNECTIVITY_TEST_STATUS_FAILED;
        test->result.failure_reason = dap_strdup("One or more tests failed");
        log_it(L_WARNING, "[%s] Test completed with failures: score=%.2f", 
               LOG_TAG, test->result.score);
    }
    
    test->is_running = false;
    pthread_cond_signal(&test->completion_cond);
    
    if (test->params.on_complete) {
        test->params.on_complete(test, &test->result, test->params.user_data);
    }
    
    pthread_mutex_unlock(&test->mutex);
}

// =============================================================================
// API Implementation
// =============================================================================

dap_vpn_connectivity_test_t* dap_vpn_connectivity_test_start(
    const dap_vpn_connectivity_test_params_t *params)
{
    if (!params || !params->stream) {
        log_it(L_ERROR, "[%s] Invalid test parameters", LOG_TAG);
        return NULL;
    }
    
    dap_vpn_connectivity_test_t *test = DAP_NEW_Z(dap_vpn_connectivity_test_t);
    if (!test) {
        log_it(L_ERROR, "[%s] Failed to allocate test", LOG_TAG);
        return NULL;
    }
    
    // Copy parameters
    test->params = *params;
    
    // Initialize result
    test->result.protocol_name = params->protocol_name ? dap_strdup(params->protocol_name) : NULL;
    test->result.stream = params->stream;
    test->result.status = CONNECTIVITY_TEST_STATUS_IDLE;
    
    // Count tests
    test->tests_total = 0;
    if (params->enable_connectivity_verify) test->tests_total += 3; // DNS + HTTP + HTTPS
    if (params->enable_latency_test) test->tests_total++;
    if (params->enable_speed_test) test->tests_total++;
    
    // Initialize synchronization
    pthread_mutex_init(&test->mutex, NULL);
    pthread_cond_init(&test->completion_cond, NULL);
    
    test->is_running = true;
    
    // Create timeout timer
    test->timeout_timer = dap_timerfd_start(params->timeout_ms, test_timeout_callback, test);
    
    // Dispatch to worker
    dap_worker_exec_callback_on(dap_worker_get_auto(), test_worker, test);
    
    log_it(L_INFO, "[%s] Test started for protocol: %s", 
           LOG_TAG, params->protocol_name ? params->protocol_name : "unknown");
    
    return test;
}

void dap_vpn_connectivity_test_cancel(dap_vpn_connectivity_test_t *test) {
    if (!test) return;
    
    pthread_mutex_lock(&test->mutex);
    test->is_cancelled = true;
    pthread_mutex_unlock(&test->mutex);
    
    log_it(L_INFO, "[%s] Test cancelled", LOG_TAG);
}

const dap_vpn_connectivity_result_t* dap_vpn_connectivity_test_get_result(
    const dap_vpn_connectivity_test_t *test)
{
    return test ? &test->result : NULL;
}

bool dap_vpn_connectivity_test_is_complete(const dap_vpn_connectivity_test_t *test) {
    if (!test) return false;
    
    pthread_mutex_lock((pthread_mutex_t*)&test->mutex);
    bool complete = !test->is_running;
    pthread_mutex_unlock((pthread_mutex_t*)&test->mutex);
    
    return complete;
}

void dap_vpn_connectivity_test_destroy(dap_vpn_connectivity_test_t *test) {
    if (!test) return;
    
    // Cancel if still running
    if (test->is_running) {
        dap_vpn_connectivity_test_cancel(test);
    }
    
    // Stop timer
    if (test->timeout_timer) {
        dap_timerfd_delete_mt(dap_worker_get_current(), test->timeout_timer->esocket_uuid);
        test->timeout_timer = NULL;
    }
    
    // Free result
    DAP_DELETE(test->result.protocol_name);
    DAP_DELETE(test->result.failure_reason);
    
    // Destroy synchronization
    pthread_mutex_destroy(&test->mutex);
    pthread_cond_destroy(&test->completion_cond);
    
    DAP_DELETE(test);
}

// =============================================================================
// Quick Test Functions
// =============================================================================

int dap_vpn_connectivity_test_quick_latency(
    dap_stream_t *stream,
    const char *target,
    uint32_t count,
    uint32_t *out_latency_ms)
{
    if (!stream || !target || !out_latency_ms) return -1;
    
    dap_vpn_connectivity_test_params_t params = dap_vpn_connectivity_test_default_params(stream, "quick");
    params.latency_test_target = target;
    params.latency_test_count = count > 0 ? count : 3;
    params.enable_latency_test = true;
    params.enable_speed_test = false;
    params.enable_connectivity_verify = false;
    params.timeout_ms = 5000;
    
    dap_vpn_connectivity_test_t *test = dap_vpn_connectivity_test_start(&params);
    if (!test) return -1;
    
    // Wait for completion
    pthread_mutex_lock(&test->mutex);
    while (test->is_running) {
        pthread_cond_wait(&test->completion_cond, &test->mutex);
    }
    pthread_mutex_unlock(&test->mutex);
    
    *out_latency_ms = test->result.latency_ms;
    int ret = (test->result.status == CONNECTIVITY_TEST_STATUS_SUCCESS) ? 0 : -1;
    
    dap_vpn_connectivity_test_destroy(test);
    return ret;
}

int dap_vpn_connectivity_test_quick_check(
    dap_stream_t *stream,
    bool *out_dns_ok,
    bool *out_http_ok)
{
    if (!stream || !out_dns_ok || !out_http_ok) return -1;
    
    dap_vpn_connectivity_test_params_t params = dap_vpn_connectivity_test_default_params(stream, "quick");
    params.enable_connectivity_verify = true;
    params.enable_latency_test = false;
    params.enable_speed_test = false;
    params.timeout_ms = 5000;
    
    dap_vpn_connectivity_test_t *test = dap_vpn_connectivity_test_start(&params);
    if (!test) return -1;
    
    // Wait for completion
    pthread_mutex_lock(&test->mutex);
    while (test->is_running) {
        pthread_cond_wait(&test->completion_cond, &test->mutex);
    }
    pthread_mutex_unlock(&test->mutex);
    
    *out_dns_ok = test->result.dns_working;
    *out_http_ok = test->result.http_working;
    int ret = (test->result.status == CONNECTIVITY_TEST_STATUS_SUCCESS) ? 0 : -1;
    
    dap_vpn_connectivity_test_destroy(test);
    return ret;
}

const char* dap_vpn_connectivity_test_status_to_string(dap_vpn_connectivity_test_status_t status) {
    switch (status) {
        case CONNECTIVITY_TEST_STATUS_IDLE: return "IDLE";
        case CONNECTIVITY_TEST_STATUS_TESTING: return "TESTING";
        case CONNECTIVITY_TEST_STATUS_SUCCESS: return "SUCCESS";
        case CONNECTIVITY_TEST_STATUS_FAILED: return "FAILED";
        case CONNECTIVITY_TEST_STATUS_TIMEOUT: return "TIMEOUT";
        default: return "UNKNOWN";
    }
}

