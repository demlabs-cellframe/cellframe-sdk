all: libdap-XKCP-plainc-native.a
libdap-XKCP-plainc-native.a: bin/libdap-XKCP-plainc-native.a
libdap-XKCP-plainc-native.a.pack: bin/libdap-XKCP-plainc-native.a.tar.gz

BINDIR = bin/.build/libdap-XKCP-plainc-native.a
$(BINDIR):
	mkdir -p $(BINDIR)

MAKE ?= gmake
CC ?= gcc
AR ?= ar

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    ASMFLAGS :=
endif
ifeq ($(UNAME_S),Darwin)
    ASMFLAGS := -x assembler-with-cpp -Wa,-defsym,old_gas_syntax=1 -Wa,-defsym,no_plt=1
endif
ifneq (,$(findstring mingw32,$(CC)))
    ASMFLAGS := -x assembler-with-cpp -Wa,-defsym,old_gas_syntax=1 -Wa,-defsym,no_plt=1
endif
ifneq (,$(findstring MINGW,$(UNAME_S)))
    ASMFLAGS := -x assembler-with-cpp -Wa,-defsym,old_gas_syntax=1 -Wa,-defsym,no_plt=1
endif
ifneq (,$(findstring MSYS_NT,$(UNAME_S)))
    ASMFLAGS := -x assembler-with-cpp -Wa,-defsym,old_gas_syntax=1 -Wa,-defsym,no_plt=1
endif
UNAME_M := $(shell uname -m)

HEADERS := $(HEADERS) bin/.build/libdap-XKCP-plainc-native.a/config.h
SOURCES := $(SOURCES) bin/.build/libdap-XKCP-plainc-native.a/config.h
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ibin/.build/libdap-XKCP-plainc-native.a/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/high/Keccak/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/high/Keccak/FIPS202/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/common/
CFLAGS := $(CFLAGS) -fomit-frame-pointer
CFLAGS := $(CFLAGS) -O2
CFLAGS := $(CFLAGS) -g0
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/low/KeccakP-1600/common/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/low/KeccakP-1600/plain-64bits/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/low/common/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/low/KeccakP-1600/plain-64bits/ua/
HEADERS := $(HEADERS) lib/high/Keccak/KeccakSponge.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSponge.h
HEADERS := $(HEADERS) lib/high/Keccak/FIPS202/SimpleFIPS202.h
SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/SimpleFIPS202.h
HEADERS := $(HEADERS) lib/high/Keccak/FIPS202/KeccakHash.h
SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/KeccakHash.h
HEADERS := $(HEADERS) lib/common/brg_endian.h
SOURCES := $(SOURCES) lib/common/brg_endian.h
HEADERS := $(HEADERS) lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-SnP.h
HEADERS := $(HEADERS) lib/low/common/SnP-Relaned.h
SOURCES := $(SOURCES) lib/low/common/SnP-Relaned.h
HEADERS := $(HEADERS) lib/low/KeccakP-1600/plain-64bits/ua/KeccakP-1600-opt64-config.h
SOURCES := $(SOURCES) lib/low/KeccakP-1600/plain-64bits/ua/KeccakP-1600-opt64-config.h
HEADERS := $(HEADERS) lib/common/align.h
SOURCES := $(SOURCES) lib/common/align.h
INCLUDES := $(INCLUDES) lib/high/Keccak/KeccakSponge.inc
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSponge.inc
INCLUDES := $(INCLUDES) lib/low/KeccakP-1600/common/KeccakP-1600-unrolling.macros
SOURCES := $(SOURCES) lib/low/KeccakP-1600/common/KeccakP-1600-unrolling.macros
INCLUDES := $(INCLUDES) lib/low/KeccakP-1600/common/KeccakP-1600-64.macros
SOURCES := $(SOURCES) lib/low/KeccakP-1600/common/KeccakP-1600-64.macros

SOURCES := $(SOURCES) lib/high/Keccak/KeccakSponge.c
$(BINDIR)/KeccakSponge.o: lib/high/Keccak/KeccakSponge.c $(HEADERS) $(INCLUDES)
	$(CC) $(INCLUDEFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)  -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakSponge.o

SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/SimpleFIPS202.c
$(BINDIR)/SimpleFIPS202.o: lib/high/Keccak/FIPS202/SimpleFIPS202.c $(HEADERS) $(INCLUDES)
	$(CC) $(INCLUDEFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)  -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/SimpleFIPS202.o

SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/KeccakHash.c
$(BINDIR)/KeccakHash.o: lib/high/Keccak/FIPS202/KeccakHash.c $(HEADERS) $(INCLUDES)
	$(CC) $(INCLUDEFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)  -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakHash.o

SOURCES := $(SOURCES) lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c
$(BINDIR)/KeccakP-1600-opt64.o: lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c $(HEADERS) $(INCLUDES)
	$(CC) $(INCLUDEFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)  -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-1600-opt64.o

bin/libdap-XKCP-plainc-native.a: $(BINDIR) $(OBJECTS)
	mkdir -p $(dir $@)
	mkdir -p $@.headers
	cp -f $(HEADERS) $@.headers/
	$(AR) rcsv $@ $(OBJECTS)

bin/libdap-XKCP-plainc-native.a.tar.gz: $(SOURCES)
	mkdir -p bin/.pack/libdap-XKCP-plainc-native.a
	rm -rf bin/.pack/libdap-XKCP-plainc-native.a/*
	cp $(SOURCES) bin/.pack/libdap-XKCP-plainc-native.a/
	cd bin/.pack/ ; tar -czf ../../bin/libdap-XKCP-plainc-native.a.tar.gz libdap-XKCP-plainc-native.a/*

