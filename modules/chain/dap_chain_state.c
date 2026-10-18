#include "dap_chain_state.h"

#include "dap_common.h"
#include "dap_crc64.h"
#include "dap_strfuncs.h"

#include <pthread.h>
#include <string.h>

#define LOG_TAG "dap_chain_state"

// Writes are buffered; the header is rewritten on every append (so it always
// matches the records) and fsynced + trimmed once per period.
#define DAP_CHAIN_STATE_SAVE_PERIOD 10

struct dap_chain_state {
    dap_chain_t *chain;
    dap_chain_cell_id_t cell_id;
    pthread_mutex_t lock;
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
    char *l_path = dap_chain_state_path(a_state);
    FILE *l_file = l_path ? fopen(l_path, "rb") : NULL;
    DAP_DELETE(l_path);
    if (!l_file)
        return -1;
    if (fread(a_hdr, sizeof(*a_hdr), 1, l_file) != 1) {
        fclose(l_file);
        return -2;
    }
    if (memcmp(a_hdr->magic, s_chain_state_magic, sizeof(a_hdr->magic))
            || a_hdr->version != DAP_CHAIN_STATE_VERSION
            || a_hdr->header_size != sizeof(*a_hdr))
        { fclose(l_file); return -3; }
    if (a_hdr->net_id != a_state->chain->net_id.uint64
            || a_hdr->cell_id != a_state->cell_id.uint64 || !a_hdr->last_block_num)
        { fclose(l_file); return -4; }
    uint64_t l_crc = a_hdr->crc64;
    a_hdr->crc64 = 0;
    bool l_ok = crc64((const uint8_t *)a_hdr, sizeof(*a_hdr)) == l_crc;
    a_hdr->crc64 = l_crc;
    if (!l_ok)
        { fclose(l_file); return -5; }
    if (fseek(l_file, 0, SEEK_END) != 0) {
        fclose(l_file);
        return -6;
    }
    off_t l_size = ftello(l_file);
    if (l_size < 0 || (uint64_t)l_size != sizeof(*a_hdr)
            + a_hdr->records_count * sizeof(dap_chain_state_rec_t)) {
        fclose(l_file);
        return -7;
    }
    if (a_hdr->records_count) {
        dap_chain_state_rec_t l_last = {};
        off_t l_off = (off_t)(sizeof(*a_hdr)
                + (a_hdr->records_count - 1) * sizeof(dap_chain_state_rec_t));
        l_ok = fseek(l_file, l_off, SEEK_SET) == 0
                && fread(&l_last, sizeof(l_last), 1, l_file) == 1
                && l_last.num == a_hdr->last_block_num
                && dap_hash_fast_compare(&l_last.hash, &a_hdr->last_block_hash);
        if (!l_ok) {
            fclose(l_file);
            return -8;
        }
    }
    fclose(l_file);
    return 0;
}

void dap_chain_state_note_block(dap_chain_state_t *a_state, uint64_t a_num, uint64_t a_blocks_count,
                                time_t a_ts, uint64_t a_size, uint64_t a_offset,
                                const dap_chain_hash_fast_t *a_hash,
                                const dap_chain_hash_fast_t *a_prev_hash, bool a_index_record)
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
                .prev_hash = a_prev_hash ? *a_prev_hash : (dap_chain_hash_fast_t){}
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
    s_write_header_locked(a_state, l_sync);
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
