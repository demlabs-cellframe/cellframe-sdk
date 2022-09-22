HEADERS += $$PWD/aes256ctr.h \
           $$PWD/cbd.h \
	   $$PWD/fips202_kyber.h \
           $$PWD/indcpa.h \
           $$PWD/kem.h \
           $$PWD/kyber512.h \
	   $$PWD/ntt_kyber.h \
           $$PWD/params.h \
	   $$PWD/poly_kyber.h \
           $$PWD/polyvec.h \
	   $$PWD/reduce_kyber.h \
           $$PWD/sha2.h \
           $$PWD/speed_print.h \
           $$PWD/symmetric.h \
           $$PWD/verify.h


SOURCES += $$PWD/aes256ctr.c \
           $$PWD/cbd.c \
	   $$PWD/fips202_kyber.c \
           $$PWD/indcpa.c \
           $$PWD/kem.c \
	   $$PWD/ntt_kyber.c \
	   $$PWD/poly_kyber.c \
           $$PWD/polyvec.c \
	   $$PWD/reduce_kyber.c \
	   $$PWD/sha256_kyber.c \
	   $$PWD/sha512_kyber.c \
           $$PWD/symmetric-aes.c \
           $$PWD/symmetric-shake.c \
           $$PWD/verify.c

INCLUDEPATH += $$PWD
