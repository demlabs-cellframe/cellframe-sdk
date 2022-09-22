HEADERS += $$PWD/aes256ctr.h \
           $$PWD/cbd.h \
           $$PWD/fips202.h \
           $$PWD/indcpa.h \
           $$PWD/kem.h \
           $$PWD/kyber512.h \
           $$PWD/ntt.h \
           $$PWD/params.h \
           $$PWD/poly.h \
           $$PWD/polyvec.h \
           $$PWD/reduce.h \
           $$PWD/sha2.h \
           $$PWD/speed_print.h \
           $$PWD/symmetric.h \
           $$PWD/verify.h


SOURCES += $$PWD/aes256ctr.c \
           $$PWD/cbd.c \
           $$PWD/fips202.c \
           $$PWD/indcpa.c \
           $$PWD/kem.c \
           $$PWD/ntt.c \
           $$PWD/poly.c \
           $$PWD/polyvec.c \
           $$PWD/reduce.c \
           $$PWD/sha256.c \
           $$PWD/sha512.c \
           $$PWD/symmetric-aes.c \
           $$PWD/symmetric-shake.c \
           $$PWD/verify.c

INCLUDEPATH += $$PWD
