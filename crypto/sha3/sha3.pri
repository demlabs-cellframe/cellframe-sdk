INCLUDEPATH += $$PWD

HEADERS += $$PWD/fips202.h \
	$$PWD/align.h \
	$$PWD/brg_endian.h \
	$$PWD/KeccakHash.h \
	$$PWD/KeccakP-1600-reference.h \
	$$PWD/KeccakSponge-common.h \
	$$PWD/KeccakSpongeWidth1600.h
	
SOURCES += $$PWD/fips202.c \
	$$PWD/KeccakHash.c \
	$$PWD/KeccakP-1600-reference.c \
	$$PWD/KeccakSpongeWidth1600.c
	