
check_PROGRAMS = str_htab_test
str_htab_test_SOURCES = str_htab_test.c
str_htab_test_CPPFLAGS = $(AM_CFLAGS)
str_htab_test_LDADD = $(AM_LDFLAGS) ../src/libstr_htab.la ../src/liblogging.la
TESTS = $(check_PROGRAMS)

if WITH_VALGRIND
TESTS += str_htab_test-vg.sh
endif

EXTRA_DIST = \
	str_htab_test-vg.sh
