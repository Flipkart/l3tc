AM_CFLAGS = $(MORE_CFLAGS)
AM_CPPFLAGS = $(MORE_CPPFLAGS)
AM_LDFLAGS = $(MORE_LDFLAGS)

bin_PROGRAMS = l3tc
dist_man_MANS = l3tc.8

noinst_LTLIBRARIES = libstr_htab.la libba_htab.la liblogging.la

liblogging_la_SOURCES  = log.h log.c
liblogging_la_CPPFLAGS = $(AM_CFLAGS)
liblogging_la_LIBADD =  $(AM_LDFLAGS)

libstr_htab_la_SOURCES  = log.h str_htab.h str_htab.c
libstr_htab_la_CPPFLAGS = $(AM_CFLAGS)
libstr_htab_la_LIBADD =  $(AM_LDFLAGS)

libba_htab_la_SOURCES  = log.h ba_htab.h ba_htab.c
libba_htab_la_CPPFLAGS = $(AM_CFLAGS)
libba_htab_la_LIBADD =  $(AM_LDFLAGS)

## TODO:5000 When you want to add more files, add them below.
## TODO:5000 Automake will find dependencies by itself. Run
## TODO:5000 ./autogen.sh after modifying this file.

l3tc_SOURCES  = log.h str_htab.h common.h tun.c tun.h l3tc.h l3tc.c
l3tc_CFLAGS   = $(AM_CFLAGS) @ZLIB_CFLAGS@
l3tc_LDFLAGS  = $(AM_LDFLAGS) @ZLIB_LIBS@
l3tc_LDADD    = liblogging.la libstr_htab.la libba_htab.la

## TODO:2004 Each time you have used `PKG_CHECK_MODULES` macro
## TODO:2004 in `configure.ac`, you get two variables that
## TODO:2004 you can substitute like above.
