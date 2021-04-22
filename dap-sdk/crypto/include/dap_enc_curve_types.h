#ifndef _DAP_ENC_CURVE_TYPES_
#define _DAP_ENC_CURVE_TYPES_

typedef enum dap_enc_curve_types{
    DAP_ENC_CYRVE_TYPE_SECP256k1,
    DAP_ENC_CURVE_TYPE_NIST256p1,
    DAP_ENC_CURVE_TYPE_ED25519,
    DAP_ENC_CURVE_TYPE_ED25519Blake2b,
    DAP_ENC_CURVE_TYPE_CURVE25519
}dap_enc_curve_types_t;

#endif // _DAP_ENC_CURVE_TYPES_
