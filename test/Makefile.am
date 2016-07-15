
check_PROGRAMS = str_htab_test byte_array_htab_test protocol_version_test
str_htab_test_SOURCES = str_htab_test.c
str_htab_test_CPPFLAGS = $(AM_CFLAGS)
str_htab_test_LDADD = $(AM_LDFLAGS) ../src/libstr_htab.la ../src/liblogging.la

byte_array_htab_test_SOURCES = byte_array_htab_test.c
byte_array_htab_test_CPPFLAGS = $(AM_CFLAGS)
byte_array_htab_test_LDADD = $(AM_LDFLAGS) ../src/libba_htab.la ../src/liblogging.la

protocol_version_test_SOURCES = protocol_version_test.c
protocol_version_test_CPPFLAGS = $(AM_CFLAGS)
protocol_version_test_LDADD = $(AM_LDFLAGS) ../src/libcommon.la

TESTS = $(check_PROGRAMS)
# integration test that uses netns over veth connected to bridge is commented out because for some reason linux doesn't seem to take packets from tun (RX from tun seems broken, will debug someday and then enable this)
# TESTS += nocompress_integration_test.sh 

if WITH_VALGRIND
TESTS += str_htab_test-vg.sh \
	byte_array_htab_test-vg.sh
endif

EXTRA_DIST = \
	str_htab_test-vg.sh \
	byte_array_htab_test-vg.sh \
	nocompress_integration_test.sh
