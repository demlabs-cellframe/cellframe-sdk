#include "dap_chain_state.h"

#include "dap_common.h"
#include "dap_crc64.h"
#include "dap_strfuncs.h"

#include <pthread.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>     // _commit/_fileno in the portable fsync lens below
#endif

#define LOG_TAG "dap_chain_state"

// Flush a file's buffers to the storage device. Windows has no fsync and
// commits the descriptor with _commit instead; naming fsync there is a compile
// error (-Werror=implicit-function-declaration) on the MinGW build. Same lens
// as s_ledger_file_sync() in dap_chain_ledger.c.
static inline int s_chain_state_file_sync(FILE *a_file)
{
#ifdef _WIN32
    return _commit(_fileno(a_file));
#else
    return fsync(fileno(a_file));
#endif
}

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
        .tx_count = atomic_load(&a_state->tx_count),
        .last_block_hash = a_state->last_hash
    };
    memcpy(l_hdr.magic, s_chain_state_magic, sizeof(l_hdr.magic));
    l_hdr.crc64 = crc64((const uint8_t *)&l_hdr, sizeof(l_hdr));
    bool l_ok = fflush(l_file) == 0
            && fseeko(l_file, 0, SEEK_SET) == 0
            && fwrite(&l_hdr, sizeof(l_hdr), 1, l_file) == 1
            && fflush(l_file) == 0;
    if (l_ok && a_sync) {
        s_chain_state_file_sync(l_file);
        ftruncate(fileno(l_file), (off_t)(sizeof(l_hdr)
                + a_state->records * sizeof(dap_chain_state_rec_t)));
    }
    fseeko(l_file, 0, SEEK_END);
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
        a_state->last_num = 0;
        a_state->last_count = 0;
        a_state->last_hash = (dap_chain_hash_fast_t){};
        // Lay out the header BEFORE the first record. Without this the first
        // record was written at offset 0 and the next periodic header flush
        // overwrote its first 120 bytes: the file then started with an all-zero
        // record (and the first block was missing from the index), which made
        // every continuity check fail on the next start.
        s_write_header_locked(a_state, false);
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
    if (fseeko(l_file, 0, SEEK_END) != 0) {
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
    l_ok = fseeko(l_file, l_last_off, SEEK_SET) == 0
            && fread(&l_last, sizeof(l_last), 1, l_file) == 1;
    if (!l_ok || dap_hash_fast_is_blank(&l_last.hash)) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -9;
    }
    a_hdr->records_count = l_records_in_file;
    a_hdr->last_block_num = l_last.num;
    a_hdr->last_block_hash = l_last.hash;
    // The first record is validated too: a zero/torn record at the head (left by a
    // crash during the very first append) makes every continuity check fail and
    // would keep the node scanning forever. Reject the index explicitly instead, so
    // the caller rescans and rebuilds it.
    dap_chain_state_rec_t l_first = {};
    if (fseeko(l_file, sizeof(*a_hdr), SEEK_SET) == 0
            && fread(&l_first, sizeof(l_first), 1, l_file) == 1
            && (!l_first.num || !l_first.size || dap_hash_fast_is_blank(&l_first.hash))) {
        fclose(l_file);
        pthread_mutex_unlock(&a_state->lock);
        return -10;
    }
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
        bool l_ok = fseeko(l_file, 0, SEEK_END) == 0;
        off_t l_size = l_ok ? ftello(l_file) : -1;
        uint64_t l_records = l_size > (off_t)sizeof(dap_chain_state_hdr_t)
                ? (uint64_t)(l_size - sizeof(dap_chain_state_hdr_t)) / sizeof(dap_chain_state_rec_t) : 0;
        if (l_records) {
            off_t l_off = (off_t)(sizeof(dap_chain_state_hdr_t)
                    + (l_records - 1) * sizeof(dap_chain_state_rec_t));
            l_ret = fseeko(l_file, l_off, SEEK_SET) == 0
                    && fread(a_out, sizeof(*a_out), 1, l_file) == 1;
        }
        fclose(l_file);
    }
    pthread_mutex_unlock(&a_state->lock);
    return l_ret;
}

int dap_chain_state_for_each_record(dap_chain_state_t *a_state,
        bool (*a_cb)(void *a_arg, const dap_chain_state_rec_t *a_rec), void *a_arg)
{
    if (!a_state || !a_cb)
        return -1;
    char *l_path = dap_chain_state_path(a_state);
    FILE *l_file = l_path ? fopen(l_path, "rb") : NULL;
    DAP_DELETE(l_path);
    if (!l_file)
        return -2;
    if (fseeko(l_file, sizeof(dap_chain_state_hdr_t), SEEK_SET)) {
        fclose(l_file);
        return -3;
    }
    dap_chain_state_rec_t l_rec;
    int l_ret = 0;
    while (fread(&l_rec, sizeof(l_rec), 1, l_file) == 1) {
        if (!a_cb(a_arg, &l_rec)) {
            l_ret = -4;
            break;
        }
    }
    fclose(l_file);
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
    // Non-mapped chains: the file offset is known only during the load pass
    // (the loader publishes it). A live block without an offset is not indexed;
    // the next start resumes at the end of the index and reads that tail. This
    // also covers mapped blocks accepted from the network while loading: their
    // pointer is not in the cell map, so they have no file offset yet.
    // A record with a zero number/size or a blank hash is never a real block and
    // would break the index continuity check on the next start.
    bool l_indexable = a_index_record && a_offset != 0 && a_num && a_size
            && a_hash && !dap_hash_fast_is_blank(a_hash);
    if (a_index_record && !l_indexable) {
        // A main-branch block that cannot be indexed leaves a hole the next start
        // would reject as non-contiguous: say why, a few times per process.
        static _Atomic uint32_t s_skip_logged;
        if (atomic_fetch_add(&s_skip_logged, 1) < 10)
            log_it(L_WARNING, "Chain state: block %" DAP_UINT64_FORMAT_U " is not indexed "
                   "(offset %" DAP_UINT64_FORMAT_U ", size %" DAP_UINT64_FORMAT_U ", hash %s)",
                   a_num, a_offset, a_size,
                   (a_hash && !dap_hash_fast_is_blank(a_hash)) ? dap_hash_fast_to_str_static(a_hash) : "blank");
    }
    if (a_state->chain->is_mapped || l_indexable) {
        if (a_num >= a_state->last_num) {
            a_state->last_num = a_num;
            a_state->last_count = a_blocks_count;
            if (a_hash)
                a_state->last_hash = *a_hash;
        }
    }
    if (l_indexable && !a_state->file_failed && a_hash) {
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

/* ---- per-network state cache: id-addressed entries ---- */
typedef struct s_kv_entry {
    uint64_t id;
    char *name;
    uint8_t *value;
    size_t value_len;
    dap_nanotime_t ts;
    UT_hash_handle hh;       // by id
    UT_hash_handle hh_name;  // by name
} s_kv_entry_t;

struct dap_chain_state_kv {
    uint64_t net_id;
    pthread_rwlock_t lock;
    s_kv_entry_t *by_id;
    s_kv_entry_t *by_name;
    uint64_t next_id;
};

typedef struct s_kv_reg {
    dap_chain_state_kv_t kv;
    struct s_kv_reg *next;
} s_kv_reg_t;

static s_kv_reg_t *s_kv_regs = NULL;
static pthread_mutex_t s_kv_regs_lock = PTHREAD_MUTEX_INITIALIZER;

dap_chain_state_kv_t *dap_chain_state_kv_for_net(uint64_t a_net_id)
{
    pthread_mutex_lock(&s_kv_regs_lock);
    for (s_kv_reg_t *l_it = s_kv_regs; l_it; l_it = l_it->next) {
        if (l_it->kv.net_id == a_net_id) {
            pthread_mutex_unlock(&s_kv_regs_lock);
            return &l_it->kv;
        }
    }
    s_kv_reg_t *l_new = DAP_NEW_Z(s_kv_reg_t);
    if (l_new) {
        l_new->kv.net_id = a_net_id;
        l_new->kv.next_id = 1;
        pthread_rwlock_init(&l_new->kv.lock, NULL);
        l_new->next = s_kv_regs;
        s_kv_regs = l_new;
    }
    pthread_mutex_unlock(&s_kv_regs_lock);
    return l_new ? &l_new->kv : NULL;
}

uint64_t dap_chain_state_kv_key_id(dap_chain_state_kv_t *a_kv, const char *a_name, bool a_create)
{
    if (!a_kv || !a_name)
        return 0;
    // Lookup by NAME, and it has to use the handle the entries are stored with:
    // HASH_FIND_STR expands to HASH_FIND(hh, ...), i.e. it searches the hh handle
    // (the by-id table), where the key is the numeric id - a name can never match
    // there. The by-name table is threaded on hh_name. With the wrong macro every
    // lookup missed, so each access to an existing key minted a NEW id for the
    // same name: the snapshot carried the same entries twice after one restart,
    // three times after two, ... (82481 -> 164969 -> 329945 -> 659897 entries
    // live on cf-mm-0), which is what grew the payload past the loader's size cap
    // and sent the node into a full rescan. The by-name table exists precisely so
    // this resolution is O(1) per access.
    pthread_rwlock_rdlock(&a_kv->lock);
    s_kv_entry_t *l_e = NULL;
    HASH_FIND(hh_name, a_kv->by_name, a_name, (unsigned)strlen(a_name), l_e);
    uint64_t l_id = l_e ? l_e->id : 0;
    pthread_rwlock_unlock(&a_kv->lock);
    if (l_id || !a_create)
        return l_id;
    pthread_rwlock_wrlock(&a_kv->lock);
    HASH_FIND(hh_name, a_kv->by_name, a_name, (unsigned)strlen(a_name), l_e);
    if (l_e) {
        l_id = l_e->id;
    } else {
        s_kv_entry_t *l_new = DAP_NEW_Z(s_kv_entry_t);
        if (l_new) {
            l_new->name = dap_strdup(a_name);
            if (!l_new->name) {
                DAP_DELETE(l_new);
            } else {
                l_new->id = a_kv->next_id++;
                l_new->ts = dap_nanotime_now();
                HASH_ADD(hh, a_kv->by_id, id, sizeof(uint64_t), l_new);
                HASH_ADD_KEYPTR(hh_name, a_kv->by_name, l_new->name, strlen(l_new->name), l_new);
                l_id = l_new->id;
            }
        }
    }
    pthread_rwlock_unlock(&a_kv->lock);
    return l_id;
}

int dap_chain_state_kv_set(dap_chain_state_kv_t *a_kv, uint64_t a_id, const void *a_value, size_t a_value_len)
{
    if (!a_kv || !a_id || (!a_value && a_value_len))
        return -1;
    uint8_t *l_value = a_value_len ? DAP_DUP_SIZE((uint8_t *)a_value, a_value_len) : NULL;
    if (a_value_len && !l_value)
        return -2;
    pthread_rwlock_wrlock(&a_kv->lock);
    s_kv_entry_t *l_e = NULL;
    HASH_FIND(hh, a_kv->by_id, &a_id, sizeof(uint64_t), l_e);
    if (!l_e) {
        pthread_rwlock_unlock(&a_kv->lock);
        DAP_DEL_Z(l_value);
        return -3;
    }
    DAP_DEL_Z(l_e->value);
    l_e->value = l_value;
    l_e->value_len = a_value_len;
    l_e->ts = dap_nanotime_now();
    pthread_rwlock_unlock(&a_kv->lock);
    return 0;
}

const void *dap_chain_state_kv_get(dap_chain_state_kv_t *a_kv, uint64_t a_id, size_t *a_value_len)
{
    if (!a_kv || !a_id)
        return NULL;
    pthread_rwlock_rdlock(&a_kv->lock);
    s_kv_entry_t *l_e = NULL;
    HASH_FIND(hh, a_kv->by_id, &a_id, sizeof(uint64_t), l_e);
    if (l_e && a_value_len)
        *a_value_len = l_e->value_len;
    const void *l_ret = l_e ? l_e->value : NULL;
    pthread_rwlock_unlock(&a_kv->lock);
    return l_ret;
}

int dap_chain_state_kv_del(dap_chain_state_kv_t *a_kv, uint64_t a_id)
{
    if (!a_kv || !a_id)
        return -1;
    pthread_rwlock_wrlock(&a_kv->lock);
    s_kv_entry_t *l_e = NULL;
    HASH_FIND(hh, a_kv->by_id, &a_id, sizeof(uint64_t), l_e);
    if (l_e) {
        // Two tables, two handles: HASH_DEL(head, el) always deletes the hh
        // handle (HASH_DELETE expands to HASH_DELETE_HH(hh, head, &el->hh)), so
        // the second call deleted the SAME element from by_id a second time and
        // never touched by_name. The consequences were not just a wrong count:
        // the double unlink corrupts the by_id chain, and once the element is
        // the last one HASH_DELETE_HH frees the table and NULLs the head it was
        // given - i.e. it wiped by_id (the "head" of the by_name call) while
        // by_name still held entries. Entries then stayed reachable by name after
        // their memory was freed (use-after-free, double free on the next delete
        // of that name), and once the name table was orphaned the name lookup
        // missed again and re-minted ids - the same duplicate growth the lookup
        // fix addressed. HASH_DELETE_HH is what deletes from the by-name table,
        // because the handle is passed explicitly.
        HASH_DELETE_HH(hh_name, a_kv->by_name, &l_e->hh_name);
        HASH_DEL(a_kv->by_id, l_e);
        DAP_DEL_Z(l_e->value);
        DAP_DELETE(l_e->name);
        DAP_DELETE(l_e);
    }
    pthread_rwlock_unlock(&a_kv->lock);
    return l_e ? 0 : -2;
}

const char *dap_chain_state_kv_name(dap_chain_state_kv_t *a_kv, uint64_t a_id)
{
    if (!a_kv || !a_id)
        return NULL;
    pthread_rwlock_rdlock(&a_kv->lock);
    s_kv_entry_t *l_e = NULL;
    HASH_FIND(hh, a_kv->by_id, &a_id, sizeof(uint64_t), l_e);
    const char *l_ret = l_e ? l_e->name : NULL;
    pthread_rwlock_unlock(&a_kv->lock);
    return l_ret;
}

size_t dap_chain_state_kv_count(dap_chain_state_kv_t *a_kv)
{
    if (!a_kv)
        return 0;
    pthread_rwlock_rdlock(&a_kv->lock);
    size_t l_ret = HASH_COUNT(a_kv->by_id);
    pthread_rwlock_unlock(&a_kv->lock);
    return l_ret;
}

int dap_chain_state_kv_clear(dap_chain_state_kv_t *a_kv)
{
    if (!a_kv)
        return -1;
    pthread_rwlock_wrlock(&a_kv->lock);
    s_kv_entry_t *l_e = NULL, *l_tmp = NULL;
    size_t l_n = 0;
    HASH_ITER(hh, a_kv->by_id, l_e, l_tmp) {
        // Same two-handle rule as dap_chain_state_kv_del(): the by-name table
        // must be unlinked through its own handle, or it keeps pointers to freed
        // entries (and the second HASH_DEL re-unlinks by_id instead).
        HASH_DELETE_HH(hh_name, a_kv->by_name, &l_e->hh_name);
        HASH_DEL(a_kv->by_id, l_e);
        DAP_DEL_Z(l_e->value);
        DAP_DELETE(l_e->name);
        DAP_DELETE(l_e);
        ++l_n;
    }
    pthread_rwlock_unlock(&a_kv->lock);
    return (int)l_n;
}

int dap_chain_state_kv_foreach(dap_chain_state_kv_t *a_kv, dap_chain_state_kv_cb_t a_cb, void *a_arg)
{
    if (!a_kv || !a_cb)
        return -1;
    pthread_rwlock_rdlock(&a_kv->lock);
    for (s_kv_entry_t *l_e = a_kv->by_id; l_e; l_e = l_e->hh.next) {
        if (!a_cb(a_arg, l_e->id, l_e->name)) {
            pthread_rwlock_unlock(&a_kv->lock);
            return -1;
        }
    }
    pthread_rwlock_unlock(&a_kv->lock);
    return 0;
}

int dap_chain_state_kv_dump(uint64_t a_net_id, dap_string_t *a_out)
{
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(a_net_id);
    if (!l_kv || !a_out)
        return -1;
    pthread_rwlock_rdlock(&l_kv->lock);
    struct DAP_PACKED { uint64_t net_id, next_id; uint32_t count; } l_hdr = {
        a_net_id, l_kv->next_id, (uint32_t)HASH_COUNT(l_kv->by_id) };
    bool l_ok = dap_string_append_len(a_out, (const char *)&l_hdr, sizeof(l_hdr)) != NULL;
    for (s_kv_entry_t *l_e = l_kv->by_id; l_ok && l_e; l_e = l_e->hh.next) {
        uint32_t l_nlen = (uint32_t)(strlen(l_e->name) + 1);
        uint32_t l_vlen = (uint32_t)l_e->value_len;
        uint64_t l_ts = (uint64_t)l_e->ts;
        l_ok = dap_string_append_len(a_out, (const char *)&l_e->id, sizeof(l_e->id))
                && dap_string_append_len(a_out, (const char *)&l_ts, sizeof(l_ts))
                && dap_string_append_len(a_out, (const char *)&l_nlen, sizeof(l_nlen))
                && dap_string_append_len(a_out, (const char *)&l_vlen, sizeof(l_vlen))
                && dap_string_append_len(a_out, l_e->name, l_nlen)
                && (!l_vlen || dap_string_append_len(a_out, (const char *)l_e->value, l_vlen));
    }
    pthread_rwlock_unlock(&l_kv->lock);
    return l_ok ? 0 : -2;
}

int dap_chain_state_kv_load(const uint8_t *a_data, size_t a_size)
{
    if (!a_data || a_size < sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint32_t))
        return -1;
    const uint8_t *l_ptr = a_data, *l_end = a_data + a_size;
    uint64_t l_net_id = 0, l_next_id = 0;
    uint32_t l_count = 0;
    memcpy(&l_net_id, l_ptr, sizeof(l_net_id)); l_ptr += sizeof(l_net_id);
    memcpy(&l_next_id, l_ptr, sizeof(l_next_id)); l_ptr += sizeof(l_next_id);
    memcpy(&l_count, l_ptr, sizeof(l_count)); l_ptr += sizeof(l_count);
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(l_net_id);
    if (!l_kv)
        return -2;
    size_t l_loaded = 0;
    for (uint32_t i = 0; i < l_count; ++i) {
        uint64_t l_id = 0, l_ts = 0;
        uint32_t l_nlen = 0, l_vlen = 0;
        if ((size_t)(l_end - l_ptr) < sizeof(l_id) + sizeof(l_ts) + sizeof(l_nlen) + sizeof(l_vlen))
            return -3;
        memcpy(&l_id, l_ptr, sizeof(l_id)); l_ptr += sizeof(l_id);
        memcpy(&l_ts, l_ptr, sizeof(l_ts)); l_ptr += sizeof(l_ts);
        memcpy(&l_nlen, l_ptr, sizeof(l_nlen)); l_ptr += sizeof(l_nlen);
        memcpy(&l_vlen, l_ptr, sizeof(l_vlen)); l_ptr += sizeof(l_vlen);
        // Compare against the remaining bytes one field at a time: the sum of two
        // 32-bit lengths overflows size_t on a 32-bit build, and the check would
        // then pass while l_ptr[l_nlen - 1] reads far past the buffer.
        size_t l_rem = (size_t)(l_end - l_ptr);
        if (!l_id || !l_nlen || (size_t)l_nlen > l_rem || (size_t)l_vlen > l_rem - l_nlen
                || l_ptr[l_nlen - 1])
            return -4;
        const char *l_name = (const char *)l_ptr;
        l_ptr += l_nlen;
        const uint8_t *l_value = l_ptr;
        l_ptr += l_vlen;
        uint64_t l_new_id = dap_chain_state_kv_key_id(l_kv, l_name, true);
        if (!l_new_id)
            return -5;
        dap_chain_state_kv_set(l_kv, l_new_id, l_value, l_vlen);
        ++l_loaded;
    }
    pthread_rwlock_wrlock(&l_kv->lock);
        // IDs come from the dump: keep the counter ahead of everything restored.
        // The value is not trusted - it is read from a file, and a bogus/attacker
        // supplied counter at UINT64_MAX would wrap on the next ++ and hand out
        // ids that are already occupied (two entries with one id, kv_set/kv_del
        // then act on the wrong one). Only a value the restored entries actually
        // justify is adopted.
        if (l_next_id > l_kv->next_id && l_next_id != UINT64_MAX)
            l_kv->next_id = l_next_id;
        pthread_rwlock_unlock(&l_kv->lock);
        log_it(L_NOTICE, "Chain state: restored %zu state-cache entries for net 0x%016" DAP_UINT64_FORMAT_x,
               l_loaded, l_net_id);
        return l_ptr == l_end ? 0 : -6;
}

/* ---- string facade over the id-addressed cache ----
 * Existing service code keeps its (group, key) names; each group maps to one
 * KV namespace, and every access resolves the name to an id once and then works
 * by id. State is dumped/loaded by snapshots, not by the GlobalDB.
 */
#include "dap_chain_state_cache.h"

// Resolves a group name to its namespace and records the group for the scoped
// snapshot dump (defined with the scoping helpers below the facade).
static uint64_t s_cache_ns(const char *a_group);

int dap_chain_state_cache_set(const char *a_group, const char *a_key, const void *a_value, size_t a_value_len)
{
    if (!a_group || !a_key)
        return -1;
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(s_cache_ns(a_group));
    if (!l_kv)
        return -2;
    uint64_t l_id = dap_chain_state_kv_key_id(l_kv, a_key, true);
    return l_id ? dap_chain_state_kv_set(l_kv, l_id, a_value, a_value_len) : -3;
}

int dap_chain_state_cache_del(const char *a_group, const char *a_key)
{
    if (!a_group || !a_key)
        return -1;
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(s_cache_ns(a_group));
    uint64_t l_id = l_kv ? dap_chain_state_kv_key_id(l_kv, a_key, false) : 0;
    return l_id ? dap_chain_state_kv_del(l_kv, l_id) : -2;
}

const uint8_t *dap_chain_state_cache_get(const char *a_group, const char *a_key, size_t *a_value_len)
{
    if (!a_group || !a_key)
        return NULL;
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(s_cache_ns(a_group));
    uint64_t l_id = l_kv ? dap_chain_state_kv_key_id(l_kv, a_key, false) : 0;
    return l_id ? (const uint8_t *)dap_chain_state_kv_get(l_kv, l_id, a_value_len) : NULL;
}

dap_global_db_obj_t *dap_chain_state_cache_get_all(const char *a_group, size_t *a_count)
{
    if (a_count)
        *a_count = 0;
    if (!a_group)
        return NULL;
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(s_cache_ns(a_group));
    if (!l_kv)
        return NULL;
    pthread_rwlock_rdlock(&l_kv->lock);
    size_t l_n = HASH_COUNT(l_kv->by_id);
    dap_global_db_obj_t *l_objs = l_n ? DAP_NEW_Z_COUNT(dap_global_db_obj_t, l_n) : NULL;
    size_t i = 0;
    for (s_kv_entry_t *l_e = l_kv->by_id; l_objs && l_e && i < l_n; l_e = l_e->hh.next) {
        l_objs[i].key = dap_strdup(l_e->name);
        l_objs[i].value = l_e->value_len ? DAP_DUP_SIZE(l_e->value, l_e->value_len) : NULL;
        l_objs[i].value_len = l_e->value_len;
        l_objs[i].timestamp = l_e->ts;
        if (!l_objs[i].key || (l_e->value_len && !l_objs[i].value)) {
            DAP_DEL_Z(l_objs[i].key);
            DAP_DEL_Z(l_objs[i].value);
            break;
        }
        ++i;
    }
    pthread_rwlock_unlock(&l_kv->lock);
    if (a_count)
        *a_count = i;
    return l_objs;
}

size_t dap_chain_state_cache_count(const char *a_group)
{
    if (!a_group)
        return 0;
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(s_cache_ns(a_group));
    return l_kv ? dap_chain_state_kv_count(l_kv) : 0;
}

int dap_chain_state_cache_clear(const char *a_group)
{
    if (!a_group)
        return -1;
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(s_cache_ns(a_group));
    return l_kv ? dap_chain_state_kv_clear(l_kv) : -2;
}

/* Group -> network ownership.
 * The cache is keyed by group NAME, and the names say which network a registry
 * belongs to: every network-specific one embeds the net name as a dot-delimited
 * segment ("scorpion.service.orders", "local.dex-cache.scorpion.hist"), while
 * node-global registries name no network ("local.wallet_shared"). The host
 * registers its network names here, so ownership is decided by matching segments
 * - no guessing: a group that matches no registered network stays global.
 *
 * Why it matters: without this EVERY namespace was dumped into EVERY network's
 * snapshot. On cf-mm-0 the section was byte-identical in both profiles (20.8 MB
 * each); in the bloated era it was 2.33 GB, the same order of magnitude that
 * pushed the payload past the loader's cap. A namespace written into the wrong
 * network's file duplicates bytes and mixes one network's registry into another.
 */
#define DAP_CHAIN_STATE_GROUP_NETS_MAX 8
#define DAP_CHAIN_STATE_GROUP_NET_NAME_MAX 64

static size_t s_group_nets_registered = 0;
static char s_group_nets[DAP_CHAIN_STATE_GROUP_NETS_MAX][DAP_CHAIN_STATE_GROUP_NET_NAME_MAX];
// Group name recorded per namespace, so a dump can tell per-network registries
// from node-global ones. Filled the first time a group is used.
static char s_ns_group_name[DAP_CHAIN_STATE_GROUP_NETS_MAX][DAP_CHAIN_STATE_GROUP_NET_NAME_MAX];
static pthread_mutex_t s_group_nets_lock = PTHREAD_MUTEX_INITIALIZER;

void dap_chain_state_cache_set_net_names(const char *const *a_names, size_t a_count)
{
    pthread_mutex_lock(&s_group_nets_lock);
    s_group_nets_registered = 0;
    for (size_t i = 0; a_names && i < a_count && s_group_nets_registered < DAP_CHAIN_STATE_GROUP_NETS_MAX; ++i) {
        if (!a_names[i] || !*a_names[i] || strlen(a_names[i]) >= DAP_CHAIN_STATE_GROUP_NET_NAME_MAX)
            continue;
        dap_strncpy(s_group_nets[s_group_nets_registered], a_names[i], DAP_CHAIN_STATE_GROUP_NET_NAME_MAX - 1);
        ++s_group_nets_registered;
    }
    pthread_mutex_unlock(&s_group_nets_lock);
    log_it(L_INFO, "Chain state: %zu network name(s) registered for cache scoping", s_group_nets_registered);
}

// Records the group a namespace belongs to (first use wins).
static void s_ns_group_record(uint64_t a_ns, const char *a_group)
{
    if (!a_ns || !a_group || !*a_group || strlen(a_group) >= DAP_CHAIN_STATE_GROUP_NET_NAME_MAX)
        return;
    pthread_mutex_lock(&s_group_nets_lock);
    char *l_slot = s_ns_group_name[a_ns % DAP_CHAIN_STATE_GROUP_NETS_MAX];
    if (!*l_slot)
        dap_strncpy(l_slot, a_group, DAP_CHAIN_STATE_GROUP_NET_NAME_MAX - 1);
    pthread_mutex_unlock(&s_group_nets_lock);
}

static uint64_t s_cache_ns(const char *a_group)
{
    dap_hash_fast_t l_hash = {};
    dap_hash_fast(a_group, strlen(a_group), &l_hash);
    uint64_t l_ns = 0;
    memcpy(&l_ns, &l_hash, sizeof(l_ns));
    if (!l_ns)
        l_ns = 1;
    s_ns_group_record(l_ns, a_group);
    return l_ns;
}

// Should this namespace go into the snapshot of network a_net_name? Global
// namespaces go into all of them; a per-network namespace only into its own.
static bool s_ns_belongs_to_net(uint64_t a_ns, const char *a_net_name)
{
    if (!a_net_name || !*a_net_name)
        return true;   // no scoping requested: keep everything
    char l_group[DAP_CHAIN_STATE_GROUP_NET_NAME_MAX] = { 0 };
    pthread_mutex_lock(&s_group_nets_lock);
    dap_strncpy(l_group, s_ns_group_name[a_ns % DAP_CHAIN_STATE_GROUP_NETS_MAX], sizeof(l_group) - 1);
    size_t l_nets = s_group_nets_registered;
    char l_nets_copy[DAP_CHAIN_STATE_GROUP_NETS_MAX][DAP_CHAIN_STATE_GROUP_NET_NAME_MAX];
    memcpy(l_nets_copy, s_group_nets, sizeof(l_nets_copy));
    pthread_mutex_unlock(&s_group_nets_lock);
    if (!l_group[0])
        return true;   // unknown group: treat as node-global rather than drop state
    // Walk the group's segments: a segment equal to one of the registered
    // networks makes the group network-specific.
    bool l_per_net = false, l_matches_this_net = false;
    const char *l_seg = l_group;
    while (l_seg && *l_seg) {
        const char *l_dot = strchr(l_seg, '.');
        size_t l_len = l_dot ? (size_t)(l_dot - l_seg) : strlen(l_seg);
        for (size_t i = 0; i < l_nets; ++i) {
            if (strlen(l_nets_copy[i]) != l_len || strncmp(l_nets_copy[i], l_seg, l_len))
                continue;
            l_per_net = true;
            if (strlen(a_net_name) == l_len && !strncmp(a_net_name, l_seg, l_len))
                l_matches_this_net = true;
        }
        l_seg = l_dot ? l_dot + 1 : NULL;
    }
    if (!l_per_net)
        return true;    // names no network: node-global
    return l_matches_this_net;
}

// Dump for one network. a_net_name == NULL keeps every namespace (the historic
// behaviour, used by diagnostics); a name restricts the dump to node-global
// namespaces plus those that name that network. The count is written after the
// namespaces are known to fit, so it always matches what follows.
static int s_cache_dump_scoped(dap_string_t *a_out, const char *a_net_name)
{
    if (!a_out)
        return -1;
    pthread_mutex_lock(&s_kv_regs_lock);
    // Pass 1: how many namespaces are actually going in.
    uint32_t l_selected = 0;
    for (s_kv_reg_t *l_it = s_kv_regs; l_it; l_it = l_it->next)
        if (s_ns_belongs_to_net(l_it->kv.net_id, a_net_name))
            ++l_selected;
    bool l_ok = dap_string_append_len(a_out, (const char *)&l_selected, sizeof(l_selected)) != NULL;
    for (s_kv_reg_t *l_it = s_kv_regs; l_ok && l_it; l_it = l_it->next) {
        dap_chain_state_kv_t *l_kv = &l_it->kv;
        if (!s_ns_belongs_to_net(l_kv->net_id, a_net_name))
            continue;
        pthread_rwlock_rdlock(&l_kv->lock);
        size_t l_entries = HASH_COUNT(l_kv->by_id);
        struct DAP_PACKED { uint64_t ns, next_id; uint32_t count; } l_hdr = {
            l_kv->net_id, l_kv->next_id, (uint32_t)l_entries };
        l_ok = dap_string_append_len(a_out, (const char *)&l_hdr, sizeof(l_hdr)) != NULL;
        // Even an empty namespace is dumped: its next_id is the counter a later
        // live entry continues from, and dropping the namespace would restart it.
        for (s_kv_entry_t *l_e = l_kv->by_id; l_ok && l_e; l_e = l_e->hh.next) {
            uint32_t l_nlen = (uint32_t)(strlen(l_e->name) + 1);
            uint32_t l_vlen = (uint32_t)l_e->value_len;
            uint64_t l_ts = (uint64_t)l_e->ts;
            l_ok = dap_string_append_len(a_out, (const char *)&l_e->id, sizeof(l_e->id))
                    && dap_string_append_len(a_out, (const char *)&l_ts, sizeof(l_ts))
                    && dap_string_append_len(a_out, (const char *)&l_nlen, sizeof(l_nlen))
                    && dap_string_append_len(a_out, (const char *)&l_vlen, sizeof(l_vlen))
                    && dap_string_append_len(a_out, l_e->name, l_nlen)
                    && (!l_vlen || dap_string_append_len(a_out, (const char *)l_e->value, l_vlen));
        }
        pthread_rwlock_unlock(&l_kv->lock);
    }
    pthread_mutex_unlock(&s_kv_regs_lock);
    return l_ok ? 0 : -2;
}

int dap_chain_state_cache_dump_all(dap_string_t *a_out)
{
    return s_cache_dump_scoped(a_out, NULL);
}

int dap_chain_state_cache_dump_net(dap_string_t *a_out, const char *a_net_name)
{
    return s_cache_dump_scoped(a_out, a_net_name);
}

int dap_chain_state_cache_load_all(const uint8_t *a_data, size_t a_size)
{
    if (!a_data || a_size < sizeof(uint32_t))
        return -1;
    const uint8_t *l_ptr = a_data, *l_end = a_data + a_size;
    uint32_t l_count = 0;
    memcpy(&l_count, l_ptr, sizeof(l_count)); l_ptr += sizeof(l_count);
    size_t l_loaded = 0;
    for (uint32_t n = 0; n < l_count; ++n) {
        uint64_t l_ns = 0, l_next_id = 0;
        uint32_t l_n_entries = 0;
        if ((size_t)(l_end - l_ptr) < sizeof(l_ns) + sizeof(l_next_id) + sizeof(l_n_entries))
            return -2;
        memcpy(&l_ns, l_ptr, sizeof(l_ns)); l_ptr += sizeof(l_ns);
        memcpy(&l_next_id, l_ptr, sizeof(l_next_id)); l_ptr += sizeof(l_next_id);
        memcpy(&l_n_entries, l_ptr, sizeof(l_n_entries)); l_ptr += sizeof(l_n_entries);
        dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(l_ns);
        if (!l_kv)
            return -3;
        for (uint32_t i = 0; i < l_n_entries; ++i) {
            uint64_t l_id = 0, l_ts = 0;
            uint32_t l_nlen = 0, l_vlen = 0;
            if ((size_t)(l_end - l_ptr) < sizeof(l_id) + sizeof(l_ts) + sizeof(l_nlen) + sizeof(l_vlen))
                return -4;
            memcpy(&l_id, l_ptr, sizeof(l_id)); l_ptr += sizeof(l_id);
            memcpy(&l_ts, l_ptr, sizeof(l_ts)); l_ptr += sizeof(l_ts);
            memcpy(&l_nlen, l_ptr, sizeof(l_nlen)); l_ptr += sizeof(l_nlen);
            memcpy(&l_vlen, l_ptr, sizeof(l_vlen)); l_ptr += sizeof(l_vlen);
            // Field-by-field compare: the sum of two 32-bit lengths overflows a
            // 32-bit size_t and would let l_ptr[l_nlen - 1] read out of bounds.
            size_t l_rem = (size_t)(l_end - l_ptr);
            if (!l_nlen || (size_t)l_nlen > l_rem || (size_t)l_vlen > l_rem - l_nlen
                    || l_ptr[l_nlen - 1])
                return -5;
            const char *l_name = (const char *)l_ptr;
            l_ptr += l_nlen;
            const uint8_t *l_value = l_ptr;
            l_ptr += l_vlen;
            uint64_t l_new_id = dap_chain_state_kv_key_id(l_kv, l_name, true);
            if (!l_new_id)
                return -6;
            dap_chain_state_kv_set(l_kv, l_new_id, l_value, l_vlen);
            ++l_loaded;
        }
        pthread_rwlock_wrlock(&l_kv->lock);
        // Same rule as the per-net load: never adopt a counter that would wrap.
        if (l_next_id > l_kv->next_id && l_next_id != UINT64_MAX)
            l_kv->next_id = l_next_id;
        pthread_rwlock_unlock(&l_kv->lock);
    }
    log_it(L_NOTICE, "Chain state: restored %zu state-cache entries (%u namespaces)", l_loaded, l_count);
    return l_ptr == l_end ? 0 : -7;
}

dap_store_obj_t *dap_chain_state_cache_get_all_raw(const char *a_group, size_t *a_count)
{
    if (a_count)
        *a_count = 0;
    if (!a_group)
        return NULL;
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(s_cache_ns(a_group));
    if (!l_kv)
        return NULL;
    pthread_rwlock_rdlock(&l_kv->lock);
    size_t l_n = HASH_COUNT(l_kv->by_id);
    dap_store_obj_t *l_objs = l_n ? DAP_NEW_Z_COUNT(dap_store_obj_t, l_n) : NULL;
    size_t i = 0;
    for (s_kv_entry_t *l_e = l_kv->by_id; l_objs && l_e && i < l_n; l_e = l_e->hh.next) {
        l_objs[i].group = dap_strdup(a_group);
        l_objs[i].key = dap_strdup(l_e->name);
        l_objs[i].value = l_e->value_len ? DAP_DUP_SIZE(l_e->value, l_e->value_len) : NULL;
        l_objs[i].value_len = l_e->value_len;
        l_objs[i].timestamp = l_e->ts;
        if (!l_objs[i].group || !l_objs[i].key || (l_e->value_len && !l_objs[i].value)) {
            DAP_DEL_Z(l_objs[i].group);
            DAP_DEL_Z(l_objs[i].key);
            DAP_DEL_Z(l_objs[i].value);
            break;
        }
        ++i;
    }
    pthread_rwlock_unlock(&l_kv->lock);
    if (a_count)
        *a_count = i;
    return l_objs;
}

void dap_chain_state_cache_raw_free(dap_store_obj_t *a_objs, size_t a_count)
{
    // The count can be non-zero with a NULL array: the wallet-shared filter path
    // sets count=1 and builds its entries from the filter instead of reading the
    // cache, then calls this to clean up. Indexing NULL here was a live SEGV.
    if (!a_objs)
        return;
    for (size_t i = 0; i < a_count; ++i) {
        DAP_DEL_Z(a_objs[i].group);
        DAP_DEL_Z(a_objs[i].key);
        DAP_DEL_Z(a_objs[i].value);
    }
    DAP_DEL_Z(a_objs);
}

int dap_chain_state_cache_set_bin(const char *a_group, const void *a_key, size_t a_key_len,
                                  const void *a_value, size_t a_value_len)
{
    if (!a_group || !a_key || !a_key_len)
        return -1;
    uint64_t l_id = 0;
    size_t l_take = a_key_len < sizeof(l_id) ? a_key_len : sizeof(l_id);
    memcpy(&l_id, a_key, l_take);
    l_id ^= (uint64_t)a_key_len << 56;
    if (!l_id)
        l_id = 1;
    dap_chain_state_kv_t *l_kv = dap_chain_state_kv_for_net(s_cache_ns(a_group));
    if (!l_kv)
        return -2;
    // The readable name exists only for the snapshot output; the call site works
    // with the id and the binary key.
    char *l_name = dap_strdup_printf("#%" DAP_UINT64_FORMAT_x, l_id);
    if (!l_name)
        return -2;
    uint64_t l_created_id = dap_chain_state_kv_key_id(l_kv, l_name, true);
    DAP_DELETE(l_name);
    if (!l_created_id)
        return -3;
    const void *l_store = a_value ? a_value : a_key;
    size_t l_store_len = a_value ? a_value_len : a_key_len;
    return dap_chain_state_kv_set(l_kv, l_created_id, l_store, l_store_len);
}

int dap_chain_state_adopt_file(dap_chain_state_t *a_state, uint64_t a_anchor_num)
{
    if (!a_state)
        return -1;
    pthread_mutex_lock(&a_state->lock);
    int l_ret = 0;
    char *l_path = dap_chain_state_path(a_state);
    FILE *l_file = l_path ? fopen(l_path, "r+b") : NULL;
    DAP_DELETE(l_path);
    if (!l_file) {
        l_ret = -2;
        goto out;
    }
    if (fseeko(l_file, 0, SEEK_END) || ftello(l_file) < (off_t)sizeof(dap_chain_state_hdr_t)) {
        fclose(l_file);
        l_ret = -3;
        goto out;
    }
    off_t l_size = ftello(l_file);
    uint64_t l_records = (uint64_t)(l_size - sizeof(dap_chain_state_hdr_t)) / sizeof(dap_chain_state_rec_t);
    if (!l_records) {
        fclose(l_file);
        l_ret = -3;
        goto out;
    }
    dap_chain_state_rec_t l_rec = {};
    if (fseeko(l_file, sizeof(dap_chain_state_hdr_t), SEEK_SET)
            || fread(&l_rec, sizeof(l_rec), 1, l_file) != 1) {
        fclose(l_file);
        l_ret = -3;
        goto out;
    }
    // Keep only the records up to the anchor: the loader re-applies the blocks
    // above it and would append duplicate records for them otherwise.
    uint64_t l_first_num = l_rec.num;
    uint64_t l_keep = l_records;
    if (a_anchor_num >= l_first_num && a_anchor_num - l_first_num < l_records)
        l_keep = a_anchor_num - l_first_num + 1;
    else if (a_anchor_num < l_first_num)
        l_keep = 0;
    uint64_t l_crc = DAP_CHAIN_STATE_CRC_INIT;
    if (fseeko(l_file, sizeof(dap_chain_state_hdr_t), SEEK_SET)) {
        fclose(l_file);
        l_ret = -3;
        goto out;
    }
    for (uint64_t i = 0; i < l_keep; ++i) {
        if (fread(&l_rec, sizeof(l_rec), 1, l_file) != 1) {
            fclose(l_file);
            l_ret = -4;
            goto out;
        }
        l_crc = crc64_update(l_crc, (const uint8_t *)&l_rec, sizeof(l_rec));
    }
    if (l_keep < l_records) {
        fflush(l_file);
        if (ftruncate(fileno(l_file), (off_t)(sizeof(dap_chain_state_hdr_t) + l_keep * sizeof(dap_chain_state_rec_t))))
            log_it(L_WARNING, "Chain state: can't trim the index tail (%s)", dap_strerror(errno));
    }
    a_state->file = l_file;
    a_state->records = l_keep;
    a_state->crc_state = l_crc;
    a_state->last_num = l_keep ? l_rec.num : 0;
    a_state->last_count = a_state->last_num;
    a_state->last_hash = l_keep ? l_rec.hash : (dap_chain_hash_fast_t){};
    a_state->file_failed = false;
    // Publish the trimmed count at once: the on-disk header still describes the
    // dropped tail until the next periodic flush, and a crash in that window would
    // make the reader reject its own index.
    s_write_header_locked(a_state, true);
out:
    pthread_mutex_unlock(&a_state->lock);
    return l_ret;
}
