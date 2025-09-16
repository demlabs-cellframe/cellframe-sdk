#ifndef SPX_HASH_H
#define SPX_HASH_H

#include <stdint.h>
#include "context.h"
#include "params.h"

#define initialize_hash_function SPX_NAMESPACE(initialize_hash_function)
void initialize_hash_function(spx_ctx *ctx);

#define prf_addr SPX_NAMESPACE(prf_addr)
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8]);

#define gen_message_random SPX_NAMESPACE(gen_message_random)
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx);

#define hash_message SPX_NAMESPACE(hash_message)
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx);

#ifdef SPHINCSPLUS_FLEX
void initialize_hash_function_haraka(spx_ctx *ctx);
void initialize_hash_function_sha2(spx_ctx *ctx);
void initialize_hash_function_shake(spx_ctx *ctx);

void prf_addr_haraka(unsigned char *out, const spx_ctx *ctx, const uint32_t addr[8]);
void prf_addr_sha2(unsigned char *out, const spx_ctx *ctx, const uint32_t addr[8]);
void prf_addr_shake(unsigned char *out, const spx_ctx *ctx, const uint32_t addr[8]);

void gen_message_random_haraka(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx);
void gen_message_random_sha2(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx);
void gen_message_random_shake(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx);

void hash_message_haraka(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx);
void hash_message_sha2(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx);
void hash_message_shake(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx);
#endif
#endif
