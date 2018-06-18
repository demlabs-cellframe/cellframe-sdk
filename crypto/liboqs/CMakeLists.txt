SUBDIRS = ${SRCDIR}

BUILT_SOURCES = links
lib_LTLIBRARIES = liboqs.la
liboqs_la_SOURCES =
liboqs_la_LIBADD =  src/common/libcommon.la
liboqs_la_LIBADD += src/crypto/aes/libaes.la
liboqs_la_LIBADD += src/crypto/rand/librand.la
liboqs_la_LIBADD += src/crypto/rand_urandom_aesctr/librandaesctr.la
liboqs_la_LIBADD += src/crypto/rand_urandom_chacha20/librandchacha20.la
liboqs_la_LIBADD += src/crypto/sha3/libsha3.la
liboqs_la_LIBADD += src/kex/libkex.la
if USE_KEX_RLWE_NEWHOPE_AVX2
liboqs_la_LIBADD += src/kex_rlwe_newhope/avx2/libnewhope_avx2.la
endif
if USE_KEX_LWE_FRODO
liboqs_la_LIBADD += src/kex_lwe_frodo/libfrodo.la
endif
if USE_KEX_NTRU
liboqs_la_LIBADD += src/kex_ntru/libntru.la
endif
liboqs_la_LIBADD += src/kex_rlwe_bcns15/libbcns15.la
if USE_KEX_RLWE_MSRLN16
liboqs_la_LIBADD += src/kex_rlwe_msrln16/libmsrln16.la
endif
if USE_KEX_RLWE_NEWHOPE
liboqs_la_LIBADD += src/kex_rlwe_newhope/libnewhope.la
endif
if USE_KEX_SIDH_MSR
liboqs_la_LIBADD += src/kex_sidh_msr/libsidhmsr.la
endif

liboqs_la_LIBADD += src/sig/libsig.la

if USE_MCBITS
liboqs_la_LIBADD += src/kex_code_mcbits/libmcbits.la
endif
if USE_SIDH_IQC
liboqs_la_LIBADD += src/kex_sidh_iqc_ref/libsidhiqc.la
endif

if USE_SIG_PICNIC
liboqs_la_LIBADD += src/sig_picnic/libpicnic_i.la
endif

installheaderdir=$(includedir)/oqs
installheader_HEADERS=config.h \
	common/oqs.h \
	common/common.h \
	crypto/aes/aes.h \
	crypto/rand/rand.h \
	crypto/rand_urandom_aesctr/rand_urandom_aesctr.h \
	crypto/rand_urandom_chacha20/rand_urandom_chacha20.h \
	crypto/sha3/sha3.h \
	kex/kex.h \
	kex_lwe_frodo/kex_lwe_frodo.h \
	kex_ntru/kex_ntru.h \
	kex_rlwe_bcns15/kex_rlwe_bcns15.h \
	kex_rlwe_msrln16/kex_rlwe_msrln16.h \
	kex_rlwe_newhope/kex_rlwe_newhope.h \
	kex_sidh_msr/kex_sidh_msr.h \
	sig/sig.h

install-exec-local:
if USE_KEX_RLWE_NEWHOPE_AVX2
	bash patches/apply-patch.sh kex_rlwe_newhope_avx2
endif

install-exec-hook:
	mkdir -p $(includedir)/oqs
if USE_KEX_RLWE_NEWHOPE_AVX2
	cp src/kex_rlwe_newhope/avx2/kex_rlwe_newhope_avx2.h $(includedir)/oqs
	bash patches/cleanup-patch.sh kex_rlwe_newhope/avx2
endif
if USE_OPENSSL
	cp src/sig_picnic/external/Picnic-master/picnic.h $(includedir)/oqs
endif
if USE_MCBITS
	cp src/kex_code_mcbits/kex_code_mcbits.h $(includedir)/oqs
endif
if USE_SIDH_IQC
	cp src/kex_sidh_iqc_ref/kex_sidh_iqc_ref.h $(includedir)/oqs
endif

noinst_bin_PROGRAMS = test_kex test_aes test_rand test_sha3
if USE_KEX_LWE_FRODO
noinst_bin_PROGRAMS += minimal_kex_oqs
endif
if USE_SIG_PICNIC
noinst_bin_PROGRAMS += test_sig minimal_sig_oqs
endif

noinst_bindir=$(prefix)/tests
test_kex_LDADD =  liboqs.la -lm
test_kex_SOURCES = src/kex/test_kex.c
test_kex_CPPFLAGS = -I./include
test_kex_CPPFLAGS += $(AM_CPPFLAGS)
if USE_MCBITS
test_kex_LDADD += -L${SODIUM_DIR}/lib -lsodium
endif
if USE_OPENSSL
test_kex_LDADD += -L$(OPENSSL_DIR)/lib -lcrypto
endif
if USE_SIDH_IQC
test_kex_LDADD += -L$(GMP_DIR)/lib -lgmp
endif

if USE_SIG_PICNIC
test_sig_LDADD =  liboqs.la -lm
test_sig_SOURCES = src/sig/test_sig.c
test_sig_CPPFLAGS = -I./include
test_sig_CPPFLAGS += $(AM_CPPFLAGS)
if USE_OPENSSL
test_sig_LDADD += -L$(OPENSSL_DIR)/lib -lcrypto
endif

minimal_sig_oqs_LDADD =  liboqs.la -lm
minimal_sig_oqs_SOURCES = src/sig/minimal_sig_oqs.c
minimal_sig_oqs_CPPFLAGS = -I./include
minimal_sig_oqs_CPPFLAGS += $(AM_CPPFLAGS)
if USE_OPENSSL
minimal_sig_oqs_LDADD += -L$(OPENSSL_DIR)/lib -lcrypto
endif

endif # USE_SIG_PICNIC

if USE_KEX_LWE_FRODO
minimal_kex_oqs_LDADD =  liboqs.la -lm
minimal_kex_oqs_SOURCES = src/kex/minimal_kex_oqs.c
minimal_kex_oqs_CPPFLAGS = -I./include
minimal_kex_oqs_CPPFLAGS += $(AM_CPPFLAGS)
if USE_MCBITS
minimal_kex_oqs_LDADD += -L${SODIUM_DIR}/lib -lsodium
endif
if USE_OPENSSL
minimal_kex_oqs_LDADD += -L$(OPENSSL_DIR)/lib -lcrypto
endif
if USE_SIDH_IQC
minimal_kex_oqs_LDADD += -L$(GMP_DIR)/lib -lgmp
endif

endif # USE_KEX_LWE_FRODO


links:
	$(MKDIR_P) include/oqs
	cp -f config.h include/oqs
	cp -f common/oqs.h include/oqs
	cp -f common/common.h include/oqs
	cp -f crypto/aes/aes.h include/oqs
	cp -f crypto/rand/rand.h include/oqs
	cp -f crypto/rand_urandom_aesctr/rand_urandom_aesctr.h include/oqs
	cp -f crypto/rand_urandom_chacha20/rand_urandom_chacha20.h include/oqs
	cp -f crypto/sha3/sha3.h include/oqs
	cp -f kex/kex.h include/oqs
	cp -f kex_lwe_frodo/kex_lwe_frodo.h include/oqs
	cp -f kex_ntru/kex_ntru.h include/oqs
	cp -f rc/kex_rlwe_bcns15/kex_rlwe_bcns15.h include/oqs
	cp -f kex_rlwe_msrln16/kex_rlwe_msrln16.h include/oqs
	cp -f kex_rlwe_newhope/kex_rlwe_newhope.h include/oqs
	cp -f kex_sidh_msr/kex_sidh_msr.h include/oqs
	cp -f sig/sig.h include/oqs
	cp -f sig_picnic/sig_picnic.h include/oqs
	$(LN_S) -f .libs/liboqs.a


