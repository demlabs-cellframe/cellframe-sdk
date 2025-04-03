all: libdap-XKCP-x8664-native.a
libdap-XKCP-x8664-native.a: bin/libdap-XKCP-x8664-native.a
libdap-XKCP-x8664-native.a.pack: bin/libdap-XKCP-x8664-native.a.tar.gz

BINDIR = bin/.build/libdap-XKCP-x8664-native.a
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

HEADERS := $(HEADERS) bin/.build/libdap-XKCP-x8664-native.a/config.h
SOURCES := $(SOURCES) bin/.build/libdap-XKCP-x8664-native.a/config.h
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ibin/.build/libdap-XKCP-x8664-native.a/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/high/Keccak/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/high/Keccak/FIPS202/
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/common/
CFLAGS := $(CFLAGS) -fomit-frame-pointer
CFLAGS := $(CFLAGS) -O2
CFLAGS := $(CFLAGS) -g0
ifneq ($(UNAME_M),aarch64)
            ifneq ($(UNAME_S),Darwin)
            ifneq ($(UNAME_M),riscv64)
            ifneq ($(UNAME_M),riscv32)
CFLAGS := $(CFLAGS) -march=native
endif
            endif
            endif
            endif
INCLUDEFLAGS := $(INCLUDEFLAGS) -Ilib/low/KeccakP-1600/AVX2/
HEADERS := $(HEADERS) lib/high/Keccak/KeccakSponge.h
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSponge.h
HEADERS := $(HEADERS) lib/high/Keccak/FIPS202/SimpleFIPS202.h
SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/SimpleFIPS202.h
HEADERS := $(HEADERS) lib/high/Keccak/FIPS202/KeccakHash.h
SOURCES := $(SOURCES) lib/high/Keccak/FIPS202/KeccakHash.h
HEADERS := $(HEADERS) lib/common/brg_endian.h
SOURCES := $(SOURCES) lib/common/brg_endian.h
HEADERS := $(HEADERS) lib/low/KeccakP-1600/AVX2/KeccakP-1600-SnP.h
SOURCES := $(SOURCES) lib/low/KeccakP-1600/AVX2/KeccakP-1600-SnP.h
HEADERS := $(HEADERS) lib/common/align.h
SOURCES := $(SOURCES) lib/common/align.h
INCLUDES := $(INCLUDES) lib/high/Keccak/KeccakSponge.inc
SOURCES := $(SOURCES) lib/high/Keccak/KeccakSponge.inc

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

SOURCES := $(SOURCES) lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s
$(BINDIR)/KeccakP-1600-AVX2.o: lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s $(HEADERS) $(INCLUDES)
	$(CC) $(INCLUDEFLAGS) $(ASMFLAGS) $(EXTRA_ASMFLAGS) -Wa,-defsym,old_gas_syntax=1 -Wa,-defsym,no_plt=1 -c $< -o $@
OBJECTS := $(OBJECTS) $(BINDIR)/KeccakP-1600-AVX2.o

bin/libdap-XKCP-x8664-native.a: $(BINDIR) $(OBJECTS)
	mkdir -p $(dir $@)
	mkdir -p $@.headers
	cp -f $(HEADERS) $@.headers/
	$(AR) rcsv $@ $(OBJECTS)

bin/libdap-XKCP-x8664-native.a.tar.gz: $(SOURCES)
	mkdir -p bin/.pack/libdap-XKCP-x8664-native.a
	rm -rf bin/.pack/libdap-XKCP-x8664-native.a/*
	cp $(SOURCES) bin/.pack/libdap-XKCP-x8664-native.a/
	cd bin/.pack/ ; tar -czf ../../bin/libdap-XKCP-x8664-native.a.tar.gz libdap-XKCP-x8664-native.a/*

