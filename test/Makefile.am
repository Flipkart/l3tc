
check_PROGRAMS = str_htab_test byte_array_htab_test protocol_version_test compress_test debug_test
str_htab_test_SOURCES = str_htab_test.c
str_htab_test_CPPFLAGS = $(AM_CFLAGS)
str_htab_test_LDADD = $(AM_LDFLAGS) ../src/libstr_htab.la ../src/liblogging.la

byte_array_htab_test_SOURCES = byte_array_htab_test.c
byte_array_htab_test_CPPFLAGS = $(AM_CFLAGS)
byte_array_htab_test_LDADD = $(AM_LDFLAGS) ../src/libba_htab.la ../src/liblogging.la

protocol_version_test_SOURCES = protocol_version_test.c
protocol_version_test_CPPFLAGS = $(AM_CFLAGS)
protocol_version_test_LDADD = $(AM_LDFLAGS) ../src/libcommon.la

compress_test_SOURCES = compress_test.c
compress_test_CPPFLAGS = $(AM_CFLAGS)
compress_test_LDADD = $(AM_LDFLAGS) ../src/libcompress.la ../src/libdebug.la ../src/liblogging.la
if USE_ZSTD
compress_test_CPPFLAGS += @ZSTD_CFLAGS@
compress_test_LDADD += @ZSTD_LIBS@
else
compress_test_CPPFLAGS += @ZLIB_CFLAGS@
compress_test_LDADD += @ZLIB_LIBS@
endif

debug_test_SOURCES = debug_test.c
debug_test_CPPFLAGS = $(AM_CFLAGS) @ZLIB_CFLAGS@
debug_test_LDADD = $(AM_LDFLAGS) ../src/libdebug.la @ZLIB_LIBS@

TESTS = $(check_PROGRAMS)
# integration test that uses netns over veth connected to bridge is commented out because for some reason linux doesn't seem to take packets from tun (RX from tun seems broken, will debug someday and then enable this)
# TESTS += nocompress_integration_test.sh 

if WITH_VALGRIND
TESTS += str_htab_test-vg.sh \
	byte_array_htab_test-vg.sh \
	compress_test-vg.sh
endif

EXTRA_DIST = \
	str_htab_test-vg.sh \
	byte_array_htab_test-vg.sh \
	nocompress_integration_test.sh \
	compress_test-vg.sh
