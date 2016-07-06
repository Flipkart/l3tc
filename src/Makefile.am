AM_CFLAGS = $(MORE_CFLAGS)
AM_CPPFLAGS = $(MORE_CPPFLAGS)
AM_LDFLAGS = $(MORE_LDFLAGS)

bin_PROGRAMS = l3tc
dist_man_MANS = l3tc.8

## TODO:5000 When you want to add more files, add them below.
## TODO:5000 Automake will find dependencies by itself. Run
## TODO:5000 ./autogen.sh after modifying this file.

l3tc_SOURCES  = common.h log.c log.h tun.c tun.h l3tc.h l3tc.c
l3tc_CFLAGS   = $(AM_CFLAGS) @ZLIB_CFLAGS@
l3tc_LDFLAGS  = $(AM_LDFLAGS) @ZLIB_LIBS@

## TODO:2004 Each time you have used `PKG_CHECK_MODULES` macro
## TODO:2004 in `configure.ac`, you get two variables that
## TODO:2004 you can substitute like above.
