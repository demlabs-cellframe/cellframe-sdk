#ifndef __SPHINCSPLUS_PARAMS__
#define __SPHINCSPLUS_PARAMS__

#include <stdint.h>
#include <dap_common.h>

// not change, only add
typedef enum sphincsplus_config {
    SPHINCSPLUS_CONFIG_MIN_ARG,
    SPHINCSPLUS_HARAKA_128F,
    SPHINCSPLUS_HARAKA_128S,
    SPHINCSPLUS_HARAKA_192F,
    SPHINCSPLUS_HARAKA_192S,
    SPHINCSPLUS_HARAKA_256F,
    SPHINCSPLUS_HARAKA_256S,
    SPHINCSPLUS_SHA2_128F,
    SPHINCSPLUS_SHA2_128S,
    SPHINCSPLUS_SHA2_192F,
    SPHINCSPLUS_SHA2_192S,
    SPHINCSPLUS_SHA2_256F,
    SPHINCSPLUS_SHA2_256S,
    SPHINCSPLUS_SHAKE_128F,
    SPHINCSPLUS_SHAKE_128S,
    SPHINCSPLUS_SHAKE_192F,
    SPHINCSPLUS_SHAKE_192S,
    SPHINCSPLUS_SHAKE_256F,
    SPHINCSPLUS_SHAKE_256S,
    SPHINCSPLUS_CONFIG_MAX_ARG,
} sphincsplus_config_t;

typedef enum sphincsplus_difficulty {
    SPHINCSPLUS_SIMPLE,
    SPHINCSPLUS_ROBUST,
} sphincsplus_difficulty_t;

typedef struct sphincsplus_offsets {
    uint32_t spx_offset_layer;
    uint32_t spx_offset_tree;
    uint32_t spx_offset_type;
    uint32_t spx_offset_kp_addr2;
    uint32_t spx_offset_kp_addr1;
    uint32_t spx_offset_chain_addr;
    uint32_t spx_offset_hash_addr;
    uint32_t spx_offset_tree_hgt;
    uint32_t spx_offset_tree_index;
} sphincsplus_offsets_t;

typedef struct sphincsplus_base_params {
    sphincsplus_config_t config;
    uint32_t spx_n;
    uint32_t spx_full_height;
    uint32_t spx_d;
    uint32_t spx_fors_height;
    uint32_t spx_fors_trees;
    uint32_t spx_wots_w;
    uint32_t spx_addr_bytes;
    uint8_t spx_sha512;
    sphincsplus_offsets_t offsets;
    sphincsplus_difficulty_t difficulty;
} DAP_ALIGN_PACKED sphincsplus_base_params_t;

typedef struct sphincsplus_params {
    sphincsplus_base_params_t base_params;
    uint32_t spx_wots_logw;
    uint32_t spx_wots_len1;
    uint32_t spx_wots_len2;
    uint32_t spx_wots_len;
    uint32_t spx_wots_bytes;
    uint32_t spx_wots_pk_bytes;
    uint32_t spx_tree_height;
    uint32_t spx_fors_msg_bytes;
    uint32_t spx_fors_bytes;
    uint32_t spx_fors_pk_bytes;
    uint32_t spx_bytes;
    uint32_t spx_pk_bytes;
    uint32_t spx_sk_bytes;
    uint32_t spx_tree_bits;
    uint32_t spx_tree_bytes;
    uint32_t spx_leaf_bits;
    uint32_t spx_leaf_bytes;
    uint32_t spx_dgst_bytes;
    uint32_t spx_shax_output_bytes;
    uint32_t spx_shax_block_bytes;
} sphincsplus_params_t;

typedef struct sphincsplus_private_key {
  sphincsplus_base_params_t params;
  uint8_t *data;
} sphincsplus_private_key_t;

typedef struct sphincsplus_public_key {
  sphincsplus_base_params_t params;
  uint8_t *data;
} sphincsplus_public_key_t;

typedef struct sphincsplus_signature {
  sphincsplus_base_params_t sig_params;
  uint64_t sig_len;
  uint8_t *sig_data;
} sphincsplus_signature_t;

int sphincsplus_set_config(sphincsplus_config_t a_config);
int sphincsplus_set_params(const sphincsplus_base_params_t *a_base_params);
int sphincsplus_get_params(sphincsplus_config_t a_config, sphincsplus_base_params_t *a_params);
int sphincsplus_check_params(const sphincsplus_base_params_t *a_base_params);

#endif  // __SPHINCSPLUS_PARAMS__


