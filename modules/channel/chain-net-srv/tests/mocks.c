#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "dap_test.h"

// Minimal weak mocks to satisfy linker; behavior will be extended per test

__attribute__((weak)) void log_it(int level, const char *fmt, ...) { (void)level; (void)fmt; }

// Real headers to match signatures
#include "dap_time.h"
#include "dap_timerfd.h"
#include "dap_worker.h"
#include "dap_events_socket.h"
#include "dap_global_db.h"
#include "dap_stream.h"
#include "dap_stream_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net_srv_pkt.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_enc_key.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_mempool.h"
// forward decls via common headers

// Match GDB sync signatures
// Simple in-memory KV for last set to let get_sync read it back
static char s_gdb_mem_group[128];
static char s_gdb_mem_key[256];
static uint8_t s_gdb_mem_value[512];
static size_t s_gdb_mem_size = 0;
__attribute__((weak)) byte_t *dap_global_db_get_sync(const char *group, const char *key, size_t *ret_size, bool *is_pinned, dap_nanotime_t *ts)
{
    (void)is_pinned; (void)ts;
    if (group && key && strcmp(group, s_gdb_mem_group) == 0 && strcmp(key, s_gdb_mem_key) == 0 && s_gdb_mem_size) {
        if (ret_size) *ret_size = s_gdb_mem_size;
        return s_gdb_mem_value;
    }
    if (ret_size) *ret_size = 0;
    return NULL;
}

__attribute__((weak)) int dap_global_db_set_sync(const char *group, const char *key, const void *data, size_t data_size, bool pin)
{ (void)group; (void)key; (void)data; (void)data_size; (void)pin; return 0; }
// async set used by s_set_usage_data_to_gdb
static char s_gdb_last_group[128];
static char s_gdb_last_key[256];
static size_t s_gdb_last_size = 0;
int __wrap_dap_global_db_set(const char *group, const char *key, const void *value, const size_t value_length, bool pin, dap_global_db_callback_result_t cb, void *arg)
{
    (void)pin;
    if (group) snprintf(s_gdb_last_group, sizeof(s_gdb_last_group), "%s", group);
    if (key) snprintf(s_gdb_last_key, sizeof(s_gdb_last_key), "%s", key);
    s_gdb_last_size = value_length;
    // store into in-memory KV for future get
    if (group) snprintf(s_gdb_mem_group, sizeof(s_gdb_mem_group), "%s", group);
    if (key) snprintf(s_gdb_mem_key, sizeof(s_gdb_mem_key), "%s", key);
    if (value && value_length <= sizeof(s_gdb_mem_value)) {
        memcpy(s_gdb_mem_value, value, value_length);
        s_gdb_mem_size = value_length;
    } else {
        s_gdb_mem_size = 0;
    }
    if (cb) cb(NULL, DAP_GLOBAL_DB_RC_SUCCESS, group, key, value, value_length, 0, false, arg);
    return DAP_GLOBAL_DB_RC_SUCCESS;
}
const char *test_gdb_last_group(void) { return s_gdb_last_group; }
const char *test_gdb_last_key(void) { return s_gdb_last_key; }
size_t test_gdb_last_size(void) { return s_gdb_last_size; }

__attribute__((weak)) int dap_global_db_del_sync(const char *group, const char *key)
{ (void)group; (void)key; return 0; }

// Match timerfd signatures
// forward state used by timer wrapper
static int g_receipt_timer_fire_count;
static dap_timerfd_callback_t g_receipt_timer_cb = NULL;
static void *g_receipt_timer_arg = NULL;
dap_timerfd_t* __wrap_dap_timerfd_start_on_worker(dap_worker_t * a_worker, uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg)
{ 
    (void)a_worker; (void)a_timeout_ms;
    // Defer callback to be executed by test to avoid use-after-free ordering
    if (a_callback && g_receipt_timer_fire_count > 0) {
        g_receipt_timer_cb = a_callback;
        g_receipt_timer_arg = a_callback_arg;
    }
    return (dap_timerfd_t*)(uintptr_t)0x1; 
}

__attribute__((weak)) void dap_timerfd_delete_mt(dap_worker_t *a_worker, dap_events_socket_uuid_t a_uuid)
{ (void)a_worker; (void)a_uuid; }

void __wrap_dap_timerfd_delete_unsafe(dap_timerfd_t *a_timerfd)
{ (void)a_timerfd; }

int __wrap_dap_worker_exec_callback_on(dap_worker_t * a_worker, dap_worker_callback_t a_callback, void *a_arg)
{ (void)a_worker; if (a_callback) a_callback(a_arg); return 0; }

// Provide channel lookup by uuid: возвращаем последний канал, использованный при отправке
static dap_stream_ch_t *s_last_ch_for_lookup = NULL;
dap_stream_ch_t *__wrap_dap_stream_ch_find_by_uuid_unsafe(dap_stream_worker_t *a_stream_worker, dap_stream_ch_uuid_t a_uuid)
{
    (void)a_stream_worker; (void)a_uuid; 
    return s_last_ch_for_lookup; 
}

// Capture outgoing packets for assertions

typedef struct {
    uint8_t last_type;
    size_t last_size;
    uint8_t last_buf[256];
} outbox_t;
static outbox_t g_outbox;

// Control flags for scenario-specific behavior
static int g_force_net_offline = 0;
static int g_ledger_return_null = 0;
static int g_ban_active = 0;
static int g_mempool_status = DAP_CHAIN_MEMPOOl_RET_STATUS_SUCCESS;
static int g_receipt_timer_fire_count = 0;
static int g_force_net_not_found = 0;
static int g_force_srv_not_found = 0;
static int g_custom_data_mode = 0; // 0: disabled, 1: echo, 2: no-output
static int g_force_wrong_pkey_hash = 0;
static int g_force_role_error = 0;

// Setters used by tests
void test_set_net_offline(int v) { g_force_net_offline = v; }
void test_set_ledger_return_null(int v) { g_ledger_return_null = v; }
void test_set_ban_active(int v) { g_ban_active = v; }
void test_set_mempool_status(int v) { g_mempool_status = v; }
void test_set_receipt_timer_fire_count(int v) { g_receipt_timer_fire_count = v; }
void test_fire_receipt_timers(void) {
    if (!g_receipt_timer_cb || g_receipt_timer_fire_count <= 0)
        return;
    for (int i = 0; i < g_receipt_timer_fire_count; i++) {
        bool again = ((bool (*)(void*))g_receipt_timer_cb)(g_receipt_timer_arg);
        if (!again) { g_receipt_timer_fire_count = 0; break; }
    }
}
void test_set_net_not_found(int v) { g_force_net_not_found = v; }
void test_set_srv_not_found(int v) { g_force_srv_not_found = v; }
void test_set_custom_data_mode(int v) { g_custom_data_mode = v; }
void test_set_wrong_pkey_hash(int v) { g_force_wrong_pkey_hash = v; }
void test_set_role_error(int v) { g_force_role_error = v; }

// Wraps for low-level functions
size_t __wrap_dap_stream_pkt_write_unsafe(dap_stream_t * a_stream, uint8_t a_type, const void * data, size_t a_data_size)
{ (void)a_stream; (void)a_type; (void)data; return a_data_size; }

size_t __wrap_dap_stream_ch_pkt_write_unsafe(dap_stream_ch_t * a_ch,  uint8_t a_type, const void * a_data, size_t a_data_size)
{
    s_last_ch_for_lookup = a_ch;
    g_outbox.last_type = a_type;
    g_outbox.last_size = a_data_size;
    size_t to_copy = a_data && a_data_size < sizeof(g_outbox.last_buf) ? a_data_size : sizeof(g_outbox.last_buf);
    if (a_data && to_copy)
        memcpy(g_outbox.last_buf, a_data, to_copy);
    dap_test_msg("wrap write: ch=%p type=0x%02X data=%p size=%zu", (void*)a_ch, a_type, a_data, a_data_size);
    return a_data_size;
}

ssize_t __wrap_dap_events_socket_write_unsafe(dap_events_socket_t *a_es, const void *a_buf, size_t a_buf_size)
{ (void)a_es; (void)a_buf; return (ssize_t)a_buf_size; }

size_t __wrap_dap_enc_code(void *a_key, const void *a_in, size_t a_in_size, void *a_out, size_t a_out_size, int a_type)
{ (void)a_key; if (a_out && a_in && a_out_size >= a_in_size) { memcpy(a_out, a_in, a_in_size); } return a_in_size; }

size_t __wrap_dap_enc_key_get_enc_size(int a_type, size_t a_size)
{ (void)a_type; return a_size; }

// Helpers for tests
uint8_t test_outbox_last_type(void) { return g_outbox.last_type; }
size_t test_outbox_last_size(void) { return g_outbox.last_size; }
void test_outbox_reset(void) { g_outbox.last_type = 0; g_outbox.last_size = 0; }
size_t test_outbox_copy(void *dst, size_t max_size)
{
    size_t n = g_outbox.last_size < max_size ? g_outbox.last_size : max_size;
    if (dst && n)
        memcpy(dst, g_outbox.last_buf, n);
    return n;
}

// Helpers to decode last error code if payload is error struct
uint32_t test_outbox_last_error_code(void)
{
    if (g_outbox.last_type != DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR)
        return 0;
    if (g_outbox.last_size >= sizeof(dap_stream_ch_chain_net_srv_pkt_error_t)) {
        const dap_stream_ch_chain_net_srv_pkt_error_t *err = (const dap_stream_ch_chain_net_srv_pkt_error_t *)g_outbox.last_buf;
        return err->code;
    }
    if (g_outbox.last_size >= sizeof(uint32_t)) {
        uint32_t code = 0;
        memcpy(&code, g_outbox.last_buf, sizeof(uint32_t));
        return code;
    }
    return 0;
}

static inline const dap_stream_ch_chain_net_srv_pkt_success_hdr_t *s_last_success_hdr(void)
{
    if (g_outbox.last_type != DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS)
        return NULL;
    if (g_outbox.last_size < sizeof(dap_stream_ch_chain_net_srv_pkt_success_hdr_t))
        return NULL;
    return (const dap_stream_ch_chain_net_srv_pkt_success_hdr_t *)g_outbox.last_buf;
}

uint32_t test_outbox_last_success_usage_id(void)
{
    const dap_stream_ch_chain_net_srv_pkt_success_hdr_t *h = s_last_success_hdr();
    return h ? h->usage_id : 0;
}

uint64_t test_outbox_last_success_net_id(void)
{
    const dap_stream_ch_chain_net_srv_pkt_success_hdr_t *h = s_last_success_hdr();
    return h ? h->net_id.uint64 : 0;
}

uint64_t test_outbox_last_success_srv_uid(void)
{
    const dap_stream_ch_chain_net_srv_pkt_success_hdr_t *h = s_last_success_hdr();
    return h ? h->srv_uid.uint64 : 0;
}

// ===== Wrapped mocks for FREE scenario =====
static dap_chain_net_srv_t g_mock_srv = {0};
static dap_chain_net_t g_mock_net = {0};
static dap_chain_net_srv_price_t g_mock_price = {0};
static dap_chain_datum_tx_t g_mock_tx = {0};
static int s_save_remain_calls = 0;
static void s_save_remain_service_stub(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_client)
{ (void)a_srv; (void)a_usage_id; (void)a_client; s_save_remain_calls++; }
int test_save_remain_calls(void) { return s_save_remain_calls; }
static dap_stream_ch_chain_net_srv_remain_service_store_t* s_get_remain_service_stub(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t* a_client)
{ (void)a_srv; (void)a_usage_id; (void)a_client; return NULL; }

static void* s_custom_data_cb(dap_chain_net_srv_t *a_srv, dap_chain_net_srv_usage_t *a_usage, const void *in, size_t in_size, size_t *out_size)
{
    (void)a_srv; (void)a_usage;
    if (g_custom_data_mode == 1 && in && in_size) {
        byte_t *buf = (byte_t*)malloc(in_size);
        if (buf) memcpy(buf, in, in_size);
        if (out_size) *out_size = in_size;
        return buf;
    }
    if (out_size) *out_size = 0;
    return NULL;
}

dap_chain_net_srv_t *__wrap_dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid)
{
    if (g_force_srv_not_found)
        return NULL;
    g_mock_srv.uid.uint64 = a_uid.uint64; // reflect requested uid
    g_mock_srv.allow_free_srv = true;
    g_mock_srv.grace_period = DAP_CHAIN_NET_SRV_GRACE_PERIOD_DEFAULT;
    g_mock_srv.callbacks.get_remain_service = s_get_remain_service_stub;
    g_mock_srv.callbacks.custom_data = g_custom_data_mode ? s_custom_data_cb : NULL;
    g_mock_srv.callbacks.custom_data = NULL; // может быть переопределён тестом через setter позже
    g_mock_srv.callbacks.save_remain_service = s_save_remain_service_stub;
    // Provide minimal non-NULL cert to avoid NULL deref in s_get_ban_group
    static dap_cert_t dummy_cert = {0};
    memcpy(dummy_cert.name, "dummy-cert", sizeof("dummy-cert"));
    g_mock_price.receipt_sign_cert = &dummy_cert;
    return &g_mock_srv;
}

dap_chain_net_t *__wrap_dap_chain_net_by_id(dap_chain_net_id_t a_id)
{
    (void)a_id;
    if (g_force_net_not_found)
        return NULL;
    if (!g_mock_net.pub.name[0]) {
        snprintf(g_mock_net.pub.name, sizeof(g_mock_net.pub.name), "%s", "testnet");
        g_mock_net.pub.id.uint64 = 0xAABBCCDDu;
        g_mock_net.pub.ledger = (dap_ledger_t*)(uintptr_t)0x1; // non-NULL marker
    }
    return &g_mock_net;
}

dap_chain_net_state_t __wrap_dap_chain_net_get_state(dap_chain_net_t *a_net)
{
    (void)a_net; return g_force_net_offline ? NET_STATE_OFFLINE : NET_STATE_ONLINE;
}

dap_chain_node_role_t __wrap_dap_chain_net_get_role(dap_chain_net_t *a_net)
{
    (void)a_net; dap_chain_node_role_t r = { .enums = g_force_role_error ? (NODE_ROLE_MASTER + 1) : NODE_ROLE_MASTER }; return r;
}

dap_chain_net_srv_price_t *__wrap_dap_chain_net_srv_get_price_from_order(dap_chain_net_srv_t *a_srv, const char *a_section, dap_chain_hash_fast_t *a_order_hash)
{
    (void)a_srv; (void)a_section; (void)a_order_hash;
    // Allocate price on heap so that real code can free it safely
    dap_chain_net_srv_price_t *price = (dap_chain_net_srv_price_t*)calloc(1, sizeof(dap_chain_net_srv_price_t));
    if (!price) return NULL;
    price->net = &g_mock_net;
    static dap_cert_t dummy_cert2 = {0};
    memcpy(dummy_cert2.name, "dummy-cert", sizeof("dummy-cert"));
    price->receipt_sign_cert = &dummy_cert2;
    // Heuristic: order_hash[0] == 0xAA => FREE, otherwise PAY
    if (a_order_hash && ((const uint8_t*)a_order_hash)[0] == 0xAA)
        price->value_datoshi = GET_256_FROM_64(0);
    else
        price->value_datoshi = GET_256_FROM_64(1);
    price->units = 1;
    price->units_uid.enm = SERV_UNIT_SEC;
    snprintf(price->token, sizeof(price->token), "%s", "TEST");
    return price;
}

// Return a dummy serialized pub key to avoid NULL deref in s_get_ban_group
byte_t *__wrap_dap_enc_key_serialize_pub_key(dap_enc_key_t *a_key, size_t *a_key_size)
{
    (void)a_key;
    static const byte_t buf[8] = {1,2,3,4,5,6,7,8};
    byte_t *out = (byte_t*)malloc(sizeof(buf));
    if (out)
        memcpy(out, buf, sizeof(buf));
    if (a_key_size) *a_key_size = sizeof(buf);
    return out;
}

// Ledger lookup mock: safe stub, не обращается к реальному ledger
dap_chain_datum_tx_t *__wrap_dap_ledger_tx_find_datum_by_hash(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash,
                                                             dap_ledger_tx_item_t **a_item_out, bool a_unspent_only)
{
    (void)a_ledger; (void)a_tx_hash; (void)a_item_out; (void)a_unspent_only;
    return g_ledger_return_null ? NULL : &g_mock_tx;
}

// Упростим поиск tx в леджере: возвращаем "найдено" по установленному флагу/по заполненности хеша
dap_chain_datum_tx_t *__wrap_dap_ledger_tx_find_by_hash(dap_ledger_t *a_ledger, const dap_hash_fast_t *a_hash)
{
    (void)a_ledger;
    static dap_chain_datum_tx_t dummy_tx = {0};
    // если хеш не нулевой — считаем, что tx найден (для GRACE-пути)
    bool blank = true;
    for (size_t i = 0; i < sizeof(a_hash->raw); i++) if (a_hash->raw[i]) { blank = false; break; }
    return blank ? NULL : &dummy_tx;
}

// Provide out_cond for SRV_PAY subtype when требуется
dap_chain_tx_out_cond_t *__wrap_dap_chain_datum_tx_out_cond_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_subtype_t a_cond_subtype, int *a_out_num)
{
    (void)a_tx; if (a_out_num) *a_out_num = 0;
    static dap_chain_tx_out_cond_t cond = {0};
    cond.header.subtype = a_cond_subtype;
    // смоделировать клиентский pkey_hash
    if (!g_force_wrong_pkey_hash) {
        memset(cond.subtype.srv_pay.pkey_hash.raw, 0xAB, sizeof(cond.subtype.srv_pay.pkey_hash.raw));
    } else {
        memset(cond.subtype.srv_pay.pkey_hash.raw, 0xCD, sizeof(cond.subtype.srv_pay.pkey_hash.raw));
    }
    return &cond;
}

// Возвращаем фиктивную вторую подпись, чтобы пройти NULL‑проверку
dap_sign_t *__wrap_dap_chain_datum_tx_receipt_sign_get(dap_chain_datum_tx_receipt_t *a_receipt, size_t a_receipt_size , uint16_t sign_position)
{
    (void)a_receipt; (void)a_receipt_size; (void)sign_position;
    static dap_sign_t dummy = {0};
    return &dummy;
}

// Return ban info when enabled: non-NULL buffer with future timestamp 
byte_t *__wrap_dap_global_db_get_sync(const char *group, const char *key, size_t *ret_size, bool *is_pinned, dap_nanotime_t *ts)
{
    (void)group; (void)key; (void)is_pinned; (void)ts;
    if (!g_ban_active) {
        if (ret_size) *ret_size = 0;
        return NULL;
    }
    static dap_time_t until_ts = 0;
    until_ts = time(NULL) + 3600; // banned for 1 hour
    if (ret_size) *ret_size = sizeof(until_ts);
    return (byte_t*)&until_ts;
}

char *__wrap_dap_chain_mempool_tx_create_cond_input(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
        const dap_chain_addr_t *a_addr_to, dap_enc_key_t *a_key_tx_sign, dap_chain_datum_tx_receipt_t *a_receipt, const char *a_hash_out_type, int *a_ret_status)
{
    (void)a_net; (void)a_tx_prev_hash; (void)a_addr_to; (void)a_key_tx_sign; (void)a_receipt; (void)a_hash_out_type;
    if (a_ret_status) *a_ret_status = g_mempool_status;
    if (g_mempool_status == DAP_CHAIN_MEMPOOl_RET_STATUS_SUCCESS) {
        static char hash_str[] = "txin_dummy_hash";
        return hash_str;
    }
    return NULL;
}

// Issue first receipt stub to avoid NULL deref; returns minimally valid receipt
dap_chain_datum_tx_receipt_t *__wrap_dap_chain_net_srv_issue_receipt(dap_chain_net_srv_t *a_srv,
        dap_chain_net_srv_price_t * a_price, const void * a_ext, size_t a_ext_size, dap_hash_fast_t *a_prev_tx_hash)
{
    (void)a_srv; (void)a_ext; (void)a_ext_size; (void)a_prev_tx_hash;
    dap_chain_datum_tx_receipt_t *r = (dap_chain_datum_tx_receipt_t*)calloc(1, sizeof(dap_chain_datum_tx_receipt_t));
    if (!r) return NULL;
    r->size = sizeof(dap_chain_datum_tx_receipt_t);
    r->receipt_info.version = 2;
    if (a_price) {
        r->receipt_info.units_type = a_price->units_uid;
        r->receipt_info.units = a_price->units;
        r->receipt_info.value_datoshi = a_price->value_datoshi;
    } else {
        r->receipt_info.units_type.enm = SERV_UNIT_SEC;
        r->receipt_info.units = 1;
        r->receipt_info.value_datoshi = GET_256_FROM_64(1);
    }
    dap_test_msg("mock issue_receipt: r=%p size=%llu units=%llu", (void*)r, (unsigned long long)r->size, (unsigned long long)r->receipt_info.units);
    return r;
}

// Wrap creator to guarantee non-NULL prev hash inside even if called directly
// provide prototype for real symbol to avoid implicit int
dap_chain_datum_tx_receipt_t *__real_dap_chain_datum_tx_receipt_create( dap_chain_net_srv_uid_t a_srv_uid,
        dap_chain_net_srv_price_unit_uid_t a_units_type, uint64_t a_units, uint256_t a_value_datoshi,
        const void * a_ext, size_t a_ext_size, dap_hash_fast_t *a_prev_tx_hash);
dap_chain_datum_tx_receipt_t *__wrap_dap_chain_datum_tx_receipt_create( dap_chain_net_srv_uid_t a_srv_uid,
        dap_chain_net_srv_price_unit_uid_t a_units_type, uint64_t a_units, uint256_t a_value_datoshi,
        const void * a_ext, size_t a_ext_size, dap_hash_fast_t *a_prev_tx_hash)
{
    dap_hash_fast_t zero = {0};
    if (!a_prev_tx_hash)
        a_prev_tx_hash = &zero;
    return __real_dap_chain_datum_tx_receipt_create(a_srv_uid, a_units_type, a_units, a_value_datoshi, a_ext, a_ext_size, a_prev_tx_hash);
}
