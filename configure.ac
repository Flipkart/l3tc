#                                               -*- Autoconf -*-
AC_PREREQ([2.64])

AC_INIT([l3tc],
        [m4_esyscmd_s([./get-version])],
        [singh.janmejay@gmail.com])
AC_CONFIG_SRCDIR([src/log.c])
AC_CONFIG_HEADER([config.h])
AC_GNU_SOURCE
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile scripts/Makefile])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror tar-ustar])
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])
m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR

# Configure libtool
LT_INIT

#######################
### Checks

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_EGREP

# Check some compiler flags
AX_CFLAGS_GCC_OPTION([-fdiagnostics-show-option],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-pipe],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-Wall],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-W],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-Wextra],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-Wformat],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-Wformat-security],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-Wfatal-errors],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-Wcast-align],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-Winline],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-fstack-protector],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-D_FORTIFY_SOURCE=2],[MORE_CPPFLAGS])
AX_CFLAGS_GCC_OPTION([-Wno-unused-parameter],[MORE_CFLAGS])
AX_CFLAGS_GCC_OPTION([-Wno-missing-field-initializers],[MORE_CFLAGS])
AX_LDFLAGS_OPTION([-Wl,-z,relro],[MORE_LDFLAGS])
AX_LDFLAGS_OPTION([-Wl,-z,now],[MORE_LDFLAGS])

dnl Enable _GNU_SOURCE and the like
AX_CFLAGS_GCC_OPTION([-D_GNU_SOURCE],[MORE_CPPFLAGS])    dnl GNU systems (asprintf, ...)
case $host_os in
   solaris*)
     AX_CFLAGS_GCC_OPTION([-D__EXTENSIONS__],[MORE_CPPFLAGS]) dnl (CMSG_*)
     AX_CFLAGS_GCC_OPTION([-D_XPG4_2],[MORE_CPPFLAGS])        dnl (CMSG_*)
     ;;
   hpux*)
     AX_CFLAGS_GCC_OPTION([-D_XOPEN_SOURCE=500],[MORE_CPPFLAGS])      dnl HP-UX
     AX_CFLAGS_GCC_OPTION([-D_XOPEN_SOURCE_EXTENDED],[MORE_CPPFLAGS]) dnl HP-UX
     ;;
esac

AC_CACHE_SAVE

# zstd or zlib
AC_ARG_ENABLE(zstd,
        [AS_HELP_STRING([--enable-zstd],[Use zstd (new compression lib by facebook) insteed of default (zlib) @<:@default=no@:>@])],
        [case "${enableval}" in
         yes) enable_zstd="yes" ;;
          no) enable_zstd="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-zstd) ;;
         esac],
        [enable_zstd="no"]
)
PKG_CHECK_MODULES([ZLIB], [zlib], [
  has_zlib='yes'
], [AC_MSG_NOTICE([Didn't find zLib!])])
PKG_CHECK_MODULES([ZSTD], [libzstd], [
  has_zstd='yes'
], [AC_MSG_NOTICE([Didn't find ZStd!])])
AS_IF(
[test "x$enable_zstd" = "xyes" && test "x$has_zstd" == "xyes"], [
    AC_MSG_NOTICE([ZStandard chosen as prefered compression impl])
    USE_ZSTD="yes"
    AC_DEFINE(USE_ZSTD, 1, [Use ZStandard])
],
[test "x$has_zlib" == "xyes"], [
    AC_MSG_NOTICE([zLib chosen as prefered compression impl])
    USE_ZLIB="yes"
    AC_DEFINE(USE_ZLIB, 1, [Use zLib])
],
[AC_MSG_FAILURE([Compression impl is missing])])
AM_CONDITIONAL(USE_ZSTD, test "x$USE_ZSTD" = "xyes")
AM_CONDITIONAL(USE_ZLIB, test "x$USE_ZLIB" = "xyes")

AC_CHECK_HEADERS([stdint.h errno.h time.h sys/types.h sys/socket.h netdb.h sys/epoll.h sys/queue.h uthash.h assert.h sys/uio.h netinet/in.h netinet/ip.h unistd.h fcntl.h arpa/inet.h])

AC_ARG_ENABLE(valgrind,
        [AS_HELP_STRING([--enable-valgrind], [Run testbench with valgrind. @<:@default=no@:>@])],
        [case "${enableval}" in
         yes) enable_valgrind="yes" ;;
          no) enable_valgrind="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-valgrind) ;;
         esac],
        [enable_valgrind=no]
)
AC_CHECK_PROG([has_valgrind], [valgrind], ["yes"], ["no"])

AS_IF(
[test "x$enable_valgrind" = "xyes" && test "x$has_valgrind" == "xyes"], [
    AC_MSG_NOTICE([Valgrind enabled for test-run])
    USE_VALGRIND="yes"
],
[USE_VALGRIND="no"])

AM_CONDITIONAL(WITH_VALGRIND, test $USE_VALGRIND == "yes")

AC_SUBST([MORE_CFLAGS])
AC_SUBST([MORE_CPPFLAGS])
AC_SUBST([MORE_LDFLAGS])
AC_SUBST([USE_VALGRIND])
AC_OUTPUT

cat <<EOF

------------------ Summary ------------------
 $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix..............: $prefix
  C Compiler..........: $CC $MORE_CFLAGS $MORE_CPPFLAGS $CFLAGS $CPPFLAGS
  Linker..............: $LD $MORE_LDFLAGS $LDFLAGS $LIBS
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
