SOURCES += $$PWD/apprentice.c \
          $$PWD/apptype.c \
          $$PWD/ascmagic.c \
          $$PWD/asctime_r.c \
          $$PWD/asprintf.c \
          $$PWD/buffer.c \
          $$PWD/cdf.c \
          $$PWD/cdf_time.c \
          $$PWD/compress.c \
          $$PWD/ctime_r.c \
          $$PWD/der.c \
          $$PWD/encoding.c\
          $$PWD/fmtcheck.c\
          $$PWD/fsmagic.c\
          $$PWD/funcs.c\
          $$PWD/getline.c\
          $$PWD/getopt_long.c\
          $$PWD/is_tar.c\
          $$PWD/is_csv.c \
          $$PWD/is_json.c \
          $$PWD/magic.c\
          $$PWD/pread.c\
          $$PWD/print.c\
          $$PWD/readcdf.c\
          $$PWD/readelf.c\
          $$PWD/softmagic.c\
          $$PWD/strcasestr.c\
 #         $$PWD/strlcat.c\
#          $$PWD/strlcpy.c\
          $$PWD/vasprintf.c\

HEADERS+= $$PWD/cdf.h\
          $$PWD/der.h\
          $$PWD/elfclass.h\
          $$PWD/file.h\
          $$PWD/file_opts.h\
          $$PWD/magic.h\
          $$PWD/mygetopt.h\
          $$PWD/readelf.h\
          $$PWD/tar.h\
          $$PWD/config.h

INCLUDEPATH += $$PWD
DEFINES += HAVE_CONFIG_H
QMAKE_LIBDIR_FLAGS += -L/opt/homebrew/lib
LIBS += -lz -lbz2 -llzma
