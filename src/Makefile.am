AM_CFLAGS = $(MORE_CFLAGS)
AM_CPPFLAGS = $(MORE_CPPFLAGS)
AM_LDFLAGS = $(MORE_LDFLAGS)

bin_PROGRAMS = l3tc
dist_man_MANS = l3tc.8

noinst_LTLIBRARIES = libstr_htab.la libba_htab.la liblogging.la libcommon.la libcompress.la libdebug.la

libdebug_la_SOURCES  = debug.h debug.c
libdebug_la_CPPFLAGS = $(AM_CFLAGS)
libdebug_la_LIBADD =  $(AM_LDFLAGS)

liblogging_la_SOURCES  = log.h log.c
liblogging_la_CPPFLAGS = $(AM_CFLAGS)
liblogging_la_LIBADD =  $(AM_LDFLAGS)

libstr_htab_la_SOURCES  = log.h str_htab.h str_htab.c
libstr_htab_la_CPPFLAGS = $(AM_CFLAGS)
libstr_htab_la_LIBADD =  $(AM_LDFLAGS)

libba_htab_la_SOURCES  = log.h ba_htab.h ba_htab.c
libba_htab_la_CPPFLAGS = $(AM_CFLAGS)
libba_htab_la_LIBADD =  $(AM_LDFLAGS)

libcommon_la_SOURCES  = common.h common.c
libcommon_la_CPPFLAGS = $(AM_CFLAGS)
libcommon_la_LIBADD =  $(AM_LDFLAGS)


# compression START
libcompress_la_SOURCES  = compress.h

if USE_ZSTD
compress_cflags = @ZSTD_CFLAGS@
compress_ldflags = @ZSTD_LIBS@
libcompress_la_SOURCES  += zstd_compress.c
endif

if USE_ZLIB
compress_cflags = @ZLIB_CFLAGS@
compress_ldflags = @ZLIB_LIBS@
libcompress_la_SOURCES  += zlib_compress.c
endif

libcompress_la_CPPFLAGS = $(AM_CFLAGS) $(compress_cflags)
libcompress_la_LIBADD =  $(AM_LDFLAGS) $(compress_ldflags)
# compression END


## TODO:5000 When you want to add more files, add them below.
## TODO:5000 Automake will find dependencies by itself. Run
## TODO:5000 ./autogen.sh after modifying this file.

l3tc_SOURCES  = constants.h tun.c tun.h io.c io.h l3tc.h l3tc.c $(libdebug_la_SOURCES) $(liblogging_la_SOURCES) $(libcommon_la_SOURCES) $(libba_htab_la_SOURCES) $(libcompress_la_SOURCES)
l3tc_CFLAGS   = $(AM_CFLAGS)  $(compress_cflags)
l3tc_LDFLAGS  = $(AM_LDFLAGS)  $(compress_ldflags)

## TODO:2004 Each time you have used `PKG_CHECK_MODULES` macro
## TODO:2004 in `configure.ac`, you get two variables that
## TODO:2004 you can substitute like above.
