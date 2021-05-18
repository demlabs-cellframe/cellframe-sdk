SOURCES += $$PWD/src/bio.c \
            $$PWD/src/crl.c \
            $$PWD/src/internal.c \
            $$PWD/src/keys.c \
            $$PWD/src/ocsp.c \
            $$PWD/src/sniffer.c \
            $$PWD/src/ssl.c \
            $$PWD/src/tls.c \
            $$PWD/src/tls13.c \
            $$PWD/src/wolfio.c

SOURCES += $$PWD/wolfcrypt/src/aes.c \
          $$PWD/wolfcrypt/src/des3.c \
          $$PWD/wolfcrypt/src/fp_mul_comba_28.i \
          $$PWD/wolfcrypt/src/fp_sqr_comba_64.i \
          $$PWD/wolfcrypt/src/pkcs7.c \
          $$PWD/wolfcrypt/src/sp_c32.c \
          $$PWD/wolfcrypt/src/aes_asm.S \
          $$PWD/wolfcrypt/src/dh.c \
          $$PWD/wolfcrypt/src/fp_mul_comba_3.i \
          $$PWD/wolfcrypt/src/fp_sqr_comba_7.i \
          $$PWD/wolfcrypt/src/poly1305.c \
          $$PWD/wolfcrypt/src/sp_c64.c \
          $$PWD/wolfcrypt/src/aes_asm.asm \
          $$PWD/wolfcrypt/src/dsa.c \
          $$PWD/wolfcrypt/src/fp_mul_comba_32.i \
          $$PWD/wolfcrypt/src/fp_sqr_comba_8.i \
          $$PWD/wolfcrypt/src/poly1305_asm.S \
          $$PWD/wolfcrypt/src/sp_cortexm.c \
          $$PWD/wolfcrypt/src/aes_gcm_asm.S \
          $$PWD/wolfcrypt/src/ecc.c \
          $$PWD/wolfcrypt/src/fp_mul_comba_4.i \
          $$PWD/wolfcrypt/src/fp_sqr_comba_9.i \
          $$PWD/wolfcrypt/src/sp_dsp32.c \
          $$PWD/wolfcrypt/src/rc4.c \
          $$PWD/wolfcrypt/src/ecc_fp.c \
          $$PWD/wolfcrypt/src/fp_mul_comba_48.i \
          $$PWD/wolfcrypt/src/fp_sqr_comba_small_set.i \
          $$PWD/wolfcrypt/src/pwdbased.c \
          $$PWD/wolfcrypt/src/sp_int.c \
          $$PWD/wolfcrypt/src/asm.c \
          $$PWD/wolfcrypt/src/ed25519.c \
          $$PWD/wolfcrypt/src/fp_mul_comba_6.i \
          $$PWD/wolfcrypt/src/ge_448.c \
          $$PWD/wolfcrypt/src/rabbit.c \
          $$PWD/wolfcrypt/src/sp_x86_64.c \
          $$PWD/wolfcrypt/src/asn.c \
          $$PWD/wolfcrypt/src/ed448.c \
          $$PWD/wolfcrypt/src/fp_mul_comba_64.i \
          $$PWD/wolfcrypt/src/ge_low_mem.c \
          $$PWD/wolfcrypt/src/random.c \
          $$PWD/wolfcrypt/src/sp_x86_64_asm.S \
          $$PWD/wolfcrypt/src/async.c \
          $$PWD/wolfcrypt/src/error.c \
          $$PWD/wolfcrypt/src/fp_mul_comba_7.i \
          $$PWD/wolfcrypt/src/ge_operations.c \
          $$PWD/wolfcrypt/src/rc2.c \
          $$PWD/wolfcrypt/src/srp.c \
          $$PWD/wolfcrypt/src/blake2b.c\
          $$PWD/wolfcrypt/src/evp.c\
          $$PWD/wolfcrypt/src/fp_mul_comba_8.i\
          $$PWD/wolfcrypt/src/hash.c\
          $$PWD/wolfcrypt/src/ripemd.c\
          $$PWD/wolfcrypt/src/tfm.c\
          $$PWD/wolfcrypt/src/blake2s.c\
          $$PWD/wolfcrypt/src/fe_448.c\
          $$PWD/wolfcrypt/src/fp_mul_comba_9.i\
          $$PWD/wolfcrypt/src/hc128.c\
          $$PWD/wolfcrypt/src/rsa.c\
          $$PWD/wolfcrypt/src/wc_dsp.c\
          $$PWD/wolfcrypt/src/camellia.c\
          $$PWD/wolfcrypt/src/fe_low_mem.c\
          $$PWD/wolfcrypt/src/fp_mul_comba_small_set.i\
          $$PWD/wolfcrypt/src/hmac.c\
          $$PWD/wolfcrypt/src/selftest.c\
          $$PWD/wolfcrypt/src/wc_encrypt.c\
          $$PWD/wolfcrypt/src/chacha.c\
          $$PWD/wolfcrypt/src/fe_operations.c\
          $$PWD/wolfcrypt/src/fp_sqr_comba_12.i\
          $$PWD/wolfcrypt/src/idea.c\
          $$PWD/wolfcrypt/src/sha.c\
          $$PWD/wolfcrypt/src/wc_pkcs11.c\
          $$PWD/wolfcrypt/src/chacha20_poly1305.c\
          $$PWD/wolfcrypt/src/fe_x25519_128.i\
          $$PWD/wolfcrypt/src/fp_sqr_comba_17.i\
          $$PWD/wolfcrypt/src/include.am\
          $$PWD/wolfcrypt/src/sha256.c\
          $$PWD/wolfcrypt/src/wc_port.c\
          $$PWD/wolfcrypt/src/chacha_asm.S\
          $$PWD/wolfcrypt/src/fe_x25519_asm.S\
          $$PWD/wolfcrypt/src/fp_sqr_comba_20.i\
          $$PWD/wolfcrypt/src/integer.c\
          $$PWD/wolfcrypt/src/sha256_asm.S\
          $$PWD/wolfcrypt/src/wolfcrypt_first.c\
          $$PWD/wolfcrypt/src/cmac.c\
          $$PWD/wolfcrypt/src/fips.c\
          $$PWD/wolfcrypt/src/fp_sqr_comba_24.i\
          $$PWD/wolfcrypt/src/logging.c\
          $$PWD/wolfcrypt/src/sha3.c\
          $$PWD/wolfcrypt/src/wolfcrypt_last.c\
          $$PWD/wolfcrypt/src/coding.c\
          $$PWD/wolfcrypt/src/fips_test.c\
          $$PWD/wolfcrypt/src/fp_sqr_comba_28.i\
          $$PWD/wolfcrypt/src/md2.c\
          $$PWD/wolfcrypt/src/sha512.c\
          $$PWD/wolfcrypt/src/wolfevent.c\
          $$PWD/wolfcrypt/src/compress.c\
          $$PWD/wolfcrypt/src/fp_mont_small.i\
          $$PWD/wolfcrypt/src/fp_sqr_comba_3.i\
          $$PWD/wolfcrypt/src/md4.c\
          $$PWD/wolfcrypt/src/sha512_asm.S\
          $$PWD/wolfcrypt/src/wolfmath.c\
          $$PWD/wolfcrypt/src/cpuid.c	\
          $$PWD/wolfcrypt/src/fp_mul_comba_12.i\
          $$PWD/wolfcrypt/src/fp_sqr_comba_32.i\
          $$PWD/wolfcrypt/src/md5.c	\
          $$PWD/wolfcrypt/src/signature.c\
          $$PWD/wolfcrypt/src/cryptocb.c\
          $$PWD/wolfcrypt/src/fp_mul_comba_17.i\
          $$PWD/wolfcrypt/src/fp_sqr_comba_4.i\
          $$PWD/wolfcrypt/src/memory.c\
          $$PWD/wolfcrypt/src/sp_arm32.c\
          $$PWD/wolfcrypt/src/curve25519.c\
          $$PWD/wolfcrypt/src/fp_mul_comba_20.i	\
          $$PWD/wolfcrypt/src/fp_sqr_comba_48.i\
          $$PWD/wolfcrypt/src/misc.c\
          $$PWD/wolfcrypt/src/sp_arm64.c\
          $$PWD/wolfcrypt/src/curve448.c\
          $$PWD/wolfcrypt/src/fp_mul_comba_24.i\
          $$PWD/wolfcrypt/src/fp_sqr_comba_6.i\
          $$PWD/wolfcrypt/src/pkcs12.c\
          $$PWD/wolfcrypt/src/sp_armthumb.c

HEADERS += $$PWD/wolfssl/callbacks.h \
           $$PWD/wolfssl/crl.h \
           $$PWD/wolfssl/internal.h \
           $$PWD/wolfssl/options.h \
           $$PWD/wolfssl/sniffer_error.h \
           $$PWD/wolfssl/test.h \
           $$PWD/wolfssl/wolfio.h \
           $$PWD/wolfssl/certs_test.h \
           $$PWD/wolfssl/error-ssl.h \
           $$PWD/wolfssl/ocsp.h \
           $$PWD/wolfssl/sniffer.h \
           $$PWD/wolfssl/ssl.h \
           $$PWD/wolfssl/version.h

INCLUDEPATH += $$PWD
