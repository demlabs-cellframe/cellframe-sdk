INCLUDEPATH += $$PWD

HEADERS += $$PWD/bliss_b.h \
           $$PWD/bliss_b_params.h \
           $$PWD/ntt_api.h \
           $$PWD/sampler.h \
           $$PWD/bliss_tables.h \

SOURCES += $$PWD/bliss_b_keys.c \
           $$PWD/bliss_b_params.c \
           $$PWD/bliss_b_signatures.c \
           $$PWD/bliss_b_utils.c \
           $$PWD/entropy.c \
           $$PWD/ntt_api_blzzd.c \
           $$PWD/ntt_blzzd.c \
           $$PWD/sampler.c \
           $$PWD/bliss_tables.c \
