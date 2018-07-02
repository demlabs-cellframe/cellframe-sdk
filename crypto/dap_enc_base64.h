#ifndef _DAP_ENC_BASE64_H_
#define _DAP_ENC_BASE64_H_
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum dap_enc_b64_standard{DAP_ENC_STANDARD_B64,

                               DAP_ENC_STANDARD_B64_URLSAFE,

                               } dap_enc_b64_standard_t;

size_t dap_enc_base64_decode(const char * in, size_t in_size, void * out, dap_enc_b64_standard_t standard);
size_t dap_enc_base64_encode(const void * in, size_t in_size, char * out, dap_enc_b64_standard_t standard);

#ifdef __cplusplus
}
#endif

#endif
