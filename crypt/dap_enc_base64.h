#ifndef _DAP_ENC_BASE64_H_
#define _DAP_ENC_BASE64_H_
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t dap_enc_base64_decode(const char * in, size_t in_size,void * out);
size_t dap_enc_base64_encode(const void * in, size_t in_size,char * out);

#ifdef __cplusplus
}
#endif

#endif
