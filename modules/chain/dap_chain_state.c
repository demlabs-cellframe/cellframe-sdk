#include "dap_chain_state.h"

#include "dap_common.h"
#include "dap_crc64.h"
#include "dap_strfuncs.h"

#include <pthread.h>
#include <string.h>

#define LOG_TAG "dap_chain_state"

// Writes are buffered; the header is flushed once per period and the reader
// takes the tip from the last record, so a header that lags the records (or a
// crash-torn tail) never invalidates the index.
#define DAP_CHAIN_STATE_SAVE_PERIOD 10

struct dap_chain_state {
    dap_chain_t *chain;
    dap_chain_cell_id_t cell_id;
    pthread_mutex_t lock;
    pthread_rwlock_t datums_lock;
    dap_chain_state_datum_t *datums;
    _Atomic uint64_t tx_count;
    FILE *file;
    uint64_t records;
    uint64_t crc_state;
    uint64_t last_num;
    uint64_t last_count;
    dap_chain_hash_fast_t last_hash;
    time_t last_save;
    bool file_failed;
};

static const char s_chain_state_magic[8] = { 'C', 'F', 'C', 'H', 'N', 'S', 'T', '2' };

dap_chain_state_t *dap_chain_state_create(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id)
{
    if (!a_chain)
        return NULL;
    dap_chain_state_t *l_state = DAP_NEW_Z(dap_chain_state_t);
    if (!l_state) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_state->chain = a_chain;
    l_state->cell_id = a_cell_id;
    l_state->crc_state = DAP_CHAIN_STATE_CRC_INIT;
    pthread_mutex_init(&l_state->lock, NULL);
    pthread_rwlock_init(&l_state->datums_lock, NULL);
    return l_state;
}

void dap_chain_state_destroy(dap_chain_state_t *a_state)
{
    if (!a_state)
        return;
    pthread_mutex_lock(&a_state->lock);
    if (a_state->file)
        fclose(a_state->file);
    a_state->file = NULL;
    pthread_mutex_unlock(&a_state->lock);
    dap_chain_state_datums_clear(a_state);
    pthread_rwlock_destroy(&a_state->datums_lock);
    pthread_mutex_destroy(&a_state->lock);
    DAP_DELETE(a_state);
}

char *dap_chain_state_path(dap_chain_state_t *a_state)
{
    if (!a_state || !a_state->chain)
        return NULL;
    const char *l_dir = dap_chain_get_path(a_state->chain);
    if (!l_dir || !*l_dir)
        return NULL;
    return dap_strdup_printf("%s/%0" DAP_UINT64_FORMAT_x ".dchaincell.state",
                             l_dir, a_state->cell_id.uint64);
}

// Called with the state lock held.
static void s_write_header_locked(dap_chain_state_t *a_state, bool a_sync)
{
    FILE *l_file = a_state->file;
    if (!l_file)
        return;
    dap_chain_state_hdr_t l_hdr = {
        .version = DAP_CHAIN_STATE_VERSION,
        .header_size = sizeof(l_hdr),
        .net_id = a_state->chain->net_id.uint64,
        .cell_id = a_state->cell_id.uint64,
        .last_block_num = a_state->last_num,
        .blocks_count = a_state->last_count,
        .ts_saved = (uint64_t)time(NULL),
        .records_count = a_state->records,
        .records_crc64 = a_state->records
                ? (a_state->crc_state ^ DAP_CHAIN_STATE_CRC_XOROUT) : 0,
        .last_block_hash = a_state->last_hash
    };
    memcpy(l_hdr.magic, s_chain_state_magic, sizeof(l_hdr.magic));
    l_hdr.crc64 = crc64((const uint8_t *)&l_hdr, sizeof(l_hdr));
    bool l_ok = fflush(l_file) == 0
            && fseek(l_file, 0, SEEK_SET) == 0
            && fwrite(&l_hdr, sizeof(l_hdr), 1, l_file) == 1
            && fflush(l_file) == 0;
    if (l_ok && a_sync) {
        fsync(fileno(l_file));
        ftruncate(fileno(l_file), (off_t)(sizeof(l_hdr)
                + a_state->records * sizeof(dap_chain_state_rec_t)));
    }
    fseek(l_file, 0, SEEK_END);
}

// Called with the state lock held.
static void s_ensure_file_locked(dap_chain_state_t *a_state)
{
    if (a_state->file || a_state->file_failed)
        return;
    char *l_path = dap_chain_state_path(a_state);
    a_state->file = l_path ? fopen(l_path, "wb") : NULL;
    if (!a_state->file) {
        a_state->file_failed = true;
        log_it(L_WARNING, "Chain state: can't open %s for writing", l_path ? l_path : "-");
    } else {
        a_state->records = 0;
        a_state->crc_state = DAP_CHAIN_STATE_CRC_INIT;
    }
    DAP_DELETE(l_path);
}

int dap_chain_state_read(dap_chain_state_t *a_state, dap_chain_state_hdr_t *a_hdr)
{
    if (!a_state || !a_hdr)
        return -1;
    // Serialized against note_block/flush: 'chain cache show/verify' reads at
    // runtime while the writer may be mid-flush.
    pthread_mutex_lock(&a_state->lock);
    char *l_path = dap_chain_state_path(a_state);
    FILE *l_file = l_path ? fopen(l_path, "rb") : NULL;
    DAP_DELETE(l_path);
    if (!l_file) {
        pthread_mutex_unlock(&a_state->lock);
        return -1;
    }
    bool l_ok = fread(a_hdr, sizeof(*a_hdr), 1, l_file) == 1;
    if (!l_ok || memcmp(a_hdr->magic, s_chain_state_magic, sizeof(a_hdr->magic))
            || a_hdr->version != DAP_CHAIN_STATE_VERSION
            || a_hdr->header_size != sizeof(*a_hdr)) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -3;
    }
    if (a_hdr->net_id != a_state->chain->net_id.uint64
            || a_hdr->cell_id != a_state->cell_id.uint64 || !a_hdr->last_block_num) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -4;
    }
    uint64_t l_crc = a_hdr->crc64;
    a_hdr->crc64 = 0;
    l_ok = crc64((const uint8_t *)a_hdr, sizeof(*a_hdr)) == l_crc;
    a_hdr->crc64 = l_crc;
    if (!l_ok) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -5;
    }
    if (fseek(l_file, 0, SEEK_END) != 0) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -6;
    }
    off_t l_size = ftello(l_file);
    if (l_size < 0 || (uint64_t)l_size < sizeof(*a_hdr)) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -7;
    }
    // The header is flushed periodically, so the file may hold a few records it
    // does not describe yet (a crash can also leave a torn record). Trust the
    // records: the usable count is the file size in whole records, and the tip
    // is the LAST record, not the header.
    uint64_t l_records_in_file = (uint64_t)(l_size - sizeof(*a_hdr)) / sizeof(dap_chain_state_rec_t);
    if (!l_records_in_file || a_hdr->records_count > l_records_in_file) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -8;
    }
    dap_chain_state_rec_t l_last = {};
    off_t l_last_off = (off_t)(sizeof(*a_hdr)
            + (l_records_in_file - 1) * sizeof(dap_chain_state_rec_t));
    l_ok = fseek(l_file, l_last_off, SEEK_SET) == 0
            && fread(&l_last, sizeof(l_last), 1, l_file) == 1;
    if (!l_ok || dap_hash_fast_is_blank(&l_last.hash)) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -9;
    }
    a_hdr->records_count = l_records_in_file;
    a_hdr->last_block_num = l_last.num;
    a_hdr->last_block_hash = l_last.hash;
    fclose(l_file);
    pthread_mutex_unlock(&a_state->lock);
    return 0;
}

bool dap_chain_state_last_record(dap_chain_state_t *a_state, dap_chain_state_rec_t *a_out)
{
    if (!a_state || !a_out)
        return false;
    pthread_mutex_lock(&a_state->lock);
    bool l_ret = false;
    char *l_path = dap_chain_state_path(a_state);
    FILE *l_file = l_path ? fopen(l_path, "rb") : NULL;
    DAP_DELETE(l_path);
    if (l_file) {
        bool l_ok = fseek(l_file, 0, SEEK_END) == 0;
        off_t l_size = l_ok ? ftello(l_file) : -1;
        uint64_t l_records = l_size > (off_t)sizeof(dap_chain_state_hdr_t)
                ? (uint64_t)(l_size - sizeof(dap_chain_state_hdr_t)) / sizeof(dap_chain_state_rec_t) : 0;
        if (l_records) {
            off_t l_off = (off_t)(sizeof(dap_chain_state_hdr_t)
                    + (l_records - 1) * sizeof(dap_chain_state_rec_t));
            l_ret = fseek(l_file, l_off, SEEK_SET) == 0
                    && fread(a_out, sizeof(*a_out), 1, l_file) == 1;
        }
        fclose(l_file);
    }
    pthread_mutex_unlock(&a_state->lock);
    return l_ret;
}

void dap_chain_state_note_block(dap_chain_state_t *a_state, uint64_t a_num, uint64_t a_blocks_count,
                                time_t a_ts, uint64_t a_size, uint64_t a_offset,
                                const dap_chain_hash_fast_t *a_hash,
                                const dap_chain_hash_fast_t *a_prev_hash, bool a_index_record,
                                uint32_t a_datum_count)
{
    if (!a_state)
        return;
    bool l_sync = false;
    pthread_mutex_lock(&a_state->lock);
    if (a_num >= a_state->last_num) {
        a_state->last_num = a_num;
        a_state->last_count = a_blocks_count;
        if (a_hash)
            a_state->last_hash = *a_hash;
    }
    if (a_index_record && a_state->chain->is_mapped && !a_state->file_failed && a_hash) {
        s_ensure_file_locked(a_state);
        if (a_state->file) {
            dap_chain_state_rec_t l_rec = {
                .num = a_num,
                .ts = (uint64_t)a_ts,
                .size = a_size,
                .offset = a_offset,
                .hash = *a_hash,
                .prev_hash = a_prev_hash ? *a_prev_hash : (dap_chain_hash_fast_t){},
                .datum_count = (uint16_t)(a_datum_count > UINT16_MAX ? UINT16_MAX : a_datum_count)
            };
            if (fwrite(&l_rec, sizeof(l_rec), 1, a_state->file) == 1) {
                a_state->crc_state = crc64_update(a_state->crc_state,
                        (const uint8_t *)&l_rec, sizeof(l_rec));
                a_state->records++;
            }
        }
    }
    time_t l_now = time(NULL);
    if (l_now - a_state->last_save >= DAP_CHAIN_STATE_SAVE_PERIOD) {
        a_state->last_save = l_now;
        l_sync = true;
    }
    // The header is not rewritten per block: one fflush syscall per accepted
    // block made a full scan noticeably slower. Readers take the tip from the
    // last record and treat the header as a lower bound, so an interval of
    // unflushed header state is harmless.
    if (l_sync)
        s_write_header_locked(a_state, true);
    pthread_mutex_unlock(&a_state->lock);
}

int dap_chain_state_flush(dap_chain_state_t *a_state, bool a_sync)
{
    if (!a_state)
        return -1;
    pthread_mutex_lock(&a_state->lock);
    if (a_state->file)
        s_write_header_locked(a_state, a_sync);
    bool l_ok = a_state->file != NULL;
    pthread_mutex_unlock(&a_state->lock);
    return l_ok ? 0 : -2;
}

void dap_chain_state_drop(dap_chain_state_t *a_state)
{
    if (!a_state)
        return;
    pthread_mutex_lock(&a_state->lock);
    if (a_state->file) {
        fclose(a_state->file);
        a_state->file = NULL;
    }
    char *l_path = dap_chain_state_path(a_state);
    if (l_path)
        remove(l_path);
    DAP_DELETE(l_path);
    a_state->records = 0;
    a_state->crc_state = DAP_CHAIN_STATE_CRC_INIT;
    a_state->last_num = 0;
    a_state->last_count = 0;
    memset(&a_state->last_hash, 0, sizeof(a_state->last_hash));
    a_state->file_failed = true;
    pthread_mutex_unlock(&a_state->lock);
}


void dap_chain_state_datum_add(dap_chain_state_t *a_state, const dap_chain_state_datum_t *a_rec)
{
    if (!a_state || !a_rec)
        return;
    dap_chain_state_datum_t *l_new = DAP_NEW_Z(dap_chain_state_datum_t);
    if (!l_new)
        return;
    *l_new = *a_rec;
    // The uthash handle belongs to the table, not to the caller's record.
    memset(&l_new->hh, 0, sizeof(l_new->hh));
    dap_chain_state_datum_t *l_dup = NULL;
    pthread_rwlock_wrlock(&a_state->datums_lock);
    HASH_FIND(hh, a_state->datums, &l_new->datum_hash, sizeof(l_new->datum_hash), l_dup);
    if (l_dup) {
        pthread_rwlock_unlock(&a_state->datums_lock);
        DAP_DELETE(l_new);
        return;
    }
    HASH_ADD(hh, a_state->datums, datum_hash, sizeof(l_new->datum_hash), l_new);
    pthread_rwlock_unlock(&a_state->datums_lock);
}

bool dap_chain_state_datum_find(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_hash,
                                dap_chain_state_datum_t *a_out)
{
    if (!a_state || !a_hash || !a_out)
        return false;
    dap_chain_state_datum_t *l_found = NULL;
    pthread_rwlock_rdlock(&a_state->datums_lock);
    HASH_FIND(hh, a_state->datums, a_hash, sizeof(*a_hash), l_found);
    if (l_found)
        *a_out = *l_found;
    pthread_rwlock_unlock(&a_state->datums_lock);
    return l_found != NULL;
}

void dap_chain_state_datum_remove(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_hash)
{
    if (!a_state || !a_hash)
        return;
    dap_chain_state_datum_t *l_found = NULL;
    pthread_rwlock_wrlock(&a_state->datums_lock);
    HASH_FIND(hh, a_state->datums, a_hash, sizeof(*a_hash), l_found);
    if (l_found) {
        HASH_DEL(a_state->datums, l_found);
        DAP_DELETE(l_found);
    }
    pthread_rwlock_unlock(&a_state->datums_lock);
}

void dap_chain_state_datums_clear(dap_chain_state_t *a_state)
{
    if (!a_state)
        return;
    dap_chain_state_datum_t *l_it = NULL, *l_tmp = NULL;
    pthread_rwlock_wrlock(&a_state->datums_lock);
    HASH_ITER(hh, a_state->datums, l_it, l_tmp) {
        HASH_DEL(a_state->datums, l_it);
        DAP_DELETE(l_it);
    }
    pthread_rwlock_unlock(&a_state->datums_lock);
}

size_t dap_chain_state_datum_count(dap_chain_state_t *a_state)
{
    if (!a_state)
        return 0;
    pthread_rwlock_rdlock(&a_state->datums_lock);
    size_t l_count = HASH_COUNT(a_state->datums);
    pthread_rwlock_unlock(&a_state->datums_lock);
    return l_count;
}

static bool s_datum_step(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_cur,
                         bool a_next, bool a_from_edge, dap_chain_state_datum_t *a_out)
{
    if (!a_state || !a_out)
        return false;
    dap_chain_state_datum_t *l_found = NULL, *l_step = NULL;
    pthread_rwlock_rdlock(&a_state->datums_lock);
    if (a_from_edge) {
        l_step = a_next ? a_state->datums : HASH_LAST(a_state->datums);
    } else if (a_cur) {
        HASH_FIND(hh, a_state->datums, a_cur, sizeof(*a_cur), l_found);
        if (l_found)
            l_step = a_next ? l_found->hh.next : l_found->hh.prev;
    }
    if (l_step)
        *a_out = *l_step;
    pthread_rwlock_unlock(&a_state->datums_lock);
    return l_step != NULL;
}

bool dap_chain_state_datum_first(dap_chain_state_t *a_state, dap_chain_state_datum_t *a_out)
{
    return s_datum_step(a_state, NULL, true, true, a_out);
}

bool dap_chain_state_datum_last(dap_chain_state_t *a_state, dap_chain_state_datum_t *a_out)
{
    return s_datum_step(a_state, NULL, false, true, a_out);
}

bool dap_chain_state_datum_next(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_cur,
                                dap_chain_state_datum_t *a_out)
{
    return s_datum_step(a_state, a_cur, true, false, a_out);
}

bool dap_chain_state_datum_prev(dap_chain_state_t *a_state, const dap_chain_hash_fast_t *a_cur,
                                dap_chain_state_datum_t *a_out)
{
    return s_datum_step(a_state, a_cur, false, false, a_out);
}

void dap_chain_state_tx_count_set(dap_chain_state_t *a_state, uint64_t a_value)
{
    if (a_state)
        atomic_store(&a_state->tx_count, a_value);
}

uint64_t dap_chain_state_tx_count_get(dap_chain_state_t *a_state)
{
    return a_state ? atomic_load(&a_state->tx_count) : 0;
}

uint64_t dap_chain_state_tx_count_add(dap_chain_state_t *a_state, int64_t a_delta)
{
    if (!a_state)
        return 0;
    if (a_delta < 0) {
        // Saturate at zero: a re-applied rollback must not wrap the unsigned
        // counter to UINT64_MAX.
        uint64_t l_cur = atomic_load(&a_state->tx_count);
        uint64_t l_dec = (uint64_t)(-(a_delta + 1)) + 1;
        if (l_cur < l_dec) {
            atomic_store(&a_state->tx_count, 0);
            return l_cur;
        }
    }
    return atomic_fetch_add(&a_state->tx_count, (uint64_t)a_delta);
}

int dap_chain_state_info(dap_chain_state_t *a_state, char *a_buf, size_t a_buf_size)
{
    if (!a_state || !a_buf || !a_buf_size)
        return -1;
    char *l_path = dap_chain_state_path(a_state);
    dap_chain_state_hdr_t l_hdr = {};
    int l_rc = dap_chain_state_read(a_state, &l_hdr);
    if (!l_rc) {
        uint64_t l_now = (uint64_t)time(NULL);
        snprintf(a_buf, a_buf_size,
                 "sidecar %s: valid, records %" DAP_UINT64_FORMAT_U ", tip %" DAP_UINT64_FORMAT_U
                 ", age %" DAP_UINT64_FORMAT_U " s",
                 l_path ? l_path : "-", l_hdr.records_count, l_hdr.last_block_num,
                 l_now > l_hdr.ts_saved ? l_now - l_hdr.ts_saved : 0);
    } else {
        snprintf(a_buf, a_buf_size, "sidecar %s: absent or invalid (code %d)",
                 l_path ? l_path : "-", l_rc);
    }
    DAP_DELETE(l_path);
    return l_rc;
}
