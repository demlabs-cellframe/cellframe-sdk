# HashFusion Makefile
# April 2017
#
#     Author: brian.monahan@hpe.com
#        
#     (c) Copyright 2017 Hewlett Packard Enterprise Development LP 
#  
#     Redistribution and use in source and binary forms, with or without
#     modification, are permitted provided that the following conditions are
#     met: 
#  
#     1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer. 
#  
#     2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution. 
#  
#     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#     IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
#     TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#     PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#     HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#     TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#     PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#     LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#     NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#     SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

SHELL = /bin/sh

PWD   =  $(shell pwd)
CC   ?=  gcc # gcc clang

# Variables
PROG    := hmt

# Source Directories
LIBDIR  :=  $(PWD)/lib
APPDIR  :=  $(PWD)/app

# Set source directory paths
VPATH =  $(LIBDIR) $(APPDIR)

# Binary/Object Directories
BINDIR  :=  $(PWD)/bin
OBJDIR  :=  $(PWD)/obj

# Library paths and compiler options
CRYPTO   :=  -L/usr/local/lib -L/usr/local/ssl/lib -lcrypto
LDOPTS   :=  -ldl -lm $(CRYPTO) # -lm -lssl 

INCLUDES :=  -iquote$(LIBDIR) -I/usr/local/ssl/include
CODEOPTS :=  -D SUPPRESS_REQUIRES_CHECKING -D SUPPRESS_NEEDS_CHECKING -D USE_MALLOC_AND_FREE #
COPTS    :=  -O3 -finline-functions $(CODEOPTS) # -finline-functions -O2 -O3

CFLAGS   :=  -std=c99 $(COPTS) -Werror -Winline $(INCLUDES) # -Wall -g

APPS     :=  $(wildcard $(APPDIR)/*.c)
LIBS     :=  $(wildcard $(LIBDIR)/*.c)

ALL_APPS :=  $(PROG)

OBJS     :=  $(LIBS:$(LIBDIR)/%.c=$(OBJDIR)/%.o)    # standard lib objects

# Empty .SUFFIXES rule to defeat built-in rules
.SUFFIXES: ;

# PHONY targets (i.e. commands)
.PHONY: help build rebuild clean

help  :
	@echo
	@echo "  clean    : Cleans directory"
	@echo "  build    : Build $(PROG)"
	@echo "  rebuild  : First clean directory then build"

build :
	@make clean
	@make hmt

clean :
	@echo "Cleaning ..."
	@rm -rf $(BINDIR)
	@rm -rf $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p $(OBJDIR)
	@rm -f *.exe *.plist *.o *.s *.bc *.stackdump a.out

hmt :: $(OBJDIR)/hmt.o $(OBJS)
	@echo 
	@echo Linking objects for: $@
	@$(CC) -o  $@ $^ $(LDOPTS)
	@mkdir -p  $(BINDIR)
	@mv $@ $(BINDIR)
	@echo Contents of: $(BINDIR)
	@ls -l $(BINDIR)
	@echo 

$(OBJDIR)/%.o :: %.c utils.h
	@echo Compiling lib object $@
	@mkdir -p $(OBJDIR)
	@$(CC) -o $@ $(CFLAGS) -c $<

