#include "../src/compress.h"
#include "../src/log.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ORIGINAL_PCAP_FILE "http.pcap.original"
#define COMPRESSED_PCAP_FILE "http.pcap.compressed"
#define DECOMPRESSED_PCAP_FILE "http.pcap.decompressed"
#define SMALL_BUFF_SZ 4096
#define LARGE_BUFF_SZ 1024*1024
#define VERY_SMALL_BUFF_SZ 512
#define EMBARASSINGLY_SMALL_BUFF_SZ 27
#define C_LOG "compress_test"


static void assert_files_are_identical(FILE *one, FILE *two) {
    rewind(one);
    rewind(two);
    size_t bytes_read = 0;
    char buff_one[SMALL_BUFF_SZ];
    char buff_two[sizeof(buff_one)];
    while (bytes_read = fread(buff_one, 1, sizeof(buff_one), one)) {
        assert(fread(buff_two, 1, bytes_read, two) == bytes_read);
        assert(memcmp(buff_one, buff_two, bytes_read) == 0);
    }
    size_t matched_pt = ftell(two);
    fseek(two, 0L, SEEK_END);
    size_t end_pt = ftell(two);
    assert(matched_pt == end_pt);
}

void do_test(int buff_sz, int buff_dest_sz) {
    compress_t comp;
    memset(&comp, 0, sizeof(comp));
    char *buff, *buff_dest;
    assert(buff = malloc(buff_sz));
    assert(buff_dest = malloc(buff_dest_sz));

    FILE* src = fopen(ORIGINAL_PCAP_FILE, "r");
    assert(src != NULL);
    remove(COMPRESSED_PCAP_FILE);
    FILE* comp_dest = fopen(COMPRESSED_PCAP_FILE, "w+r");
    assert(comp_dest != NULL);
    remove(DECOMPRESSED_PCAP_FILE);
    FILE* decomp_dest = fopen(DECOMPRESSED_PCAP_FILE, "w+r");
    assert(decomp_dest != NULL);

    assert(init_compression_ctx(&comp, DEFAULT_COMPRESSION_LEVEL) == 0);

    ssize_t total_consumed = -1;
    int complete = 0;
    size_t bytes_read = 0;
    int has_more_data = 1;
    ssize_t written = 0;
    while (has_more_data || (written != 0)) {
        ssize_t consumed = 0;
        if (total_consumed == bytes_read || total_consumed == -1) {
            bytes_read = fread(buff, 1, buff_sz, src);
            total_consumed = 0;
            log_debug(C_LOG, L("Read more bytes (%zd) from file\n"), bytes_read);
            if (bytes_read == 0) {
                has_more_data = 0;
            } else {
                setup_compress_input(&comp, buff, bytes_read);
            }
        }
        written = do_compress(&comp, buff_dest, buff_dest_sz, &consumed, &complete);
        total_consumed += consumed;
        size_t actual_write = fwrite(buff_dest, 1, written, comp_dest);
        log_crit(C_LOG, L("Remaining in compression buff: %d (consumed: %zd, written: %zd, avail_out: %d, avail_in: %d)\n"), comp.deflate.avail_in, consumed, written, comp.deflate.avail_out, comp.deflate.avail_in);

        assertf(actual_write == written, C_LOG, L("written: %zd"), written);
    }

    rewind(comp_dest);

    has_more_data = 1;
    while (has_more_data || (comp.inflatable_bytes != 0)) {
        if (comp.inflatable_bytes == 0) {
            ssize_t read_buff_sz = sizeof(comp.inflate_src_buff) > buff_sz ? buff_sz : sizeof(comp.inflate_src_buff);
            bytes_read = fread(buff, 1, read_buff_sz, comp_dest);
            log_crit(C_LOG, L("read bytes: %zd (remaining compressed: %d)\n"), bytes_read, comp.inflatable_bytes);
            if (bytes_read == 0) {
                has_more_data = 0;
                continue;
            } else {
                memcpy(comp.inflate_src_buff, buff, bytes_read);
                comp.inflatable_bytes = bytes_read;
                comp.inflatable_bytes_offset = 0;
                log_crit(C_LOG, L("Adding inflatable bytes: %d\n"), comp.inflatable_bytes);
            }
        }
        written = do_decompress(&comp, buff_dest, buff_dest_sz);
        assertf(written <= buff_dest_sz, C_LOG, L("wrote more than buffer, wrote: %zd, buff_sz; %d"), written, buff_dest_sz);
        log_crit(C_LOG, L("decomprssed(written) bytes: %zd (remaining compressed: %d, avail_in: %d)\n"), written, comp.inflatable_bytes, comp.inflate.avail_in);
        assert(fwrite(buff_dest, 1, written, decomp_dest) == written);
    }

    assert_files_are_identical(src, decomp_dest);

    assert(destroy_compression_ctx(&comp) == 0);
    free(buff);
    free(buff_dest);
}

int main() {
    log_init(3, "test");
    
    do_test(EMBARASSINGLY_SMALL_BUFF_SZ, EMBARASSINGLY_SMALL_BUFF_SZ);
    do_test(VERY_SMALL_BUFF_SZ, EMBARASSINGLY_SMALL_BUFF_SZ);
    do_test(SMALL_BUFF_SZ, EMBARASSINGLY_SMALL_BUFF_SZ);
    do_test(LARGE_BUFF_SZ, EMBARASSINGLY_SMALL_BUFF_SZ);

    do_test(EMBARASSINGLY_SMALL_BUFF_SZ, VERY_SMALL_BUFF_SZ);
    do_test(VERY_SMALL_BUFF_SZ, VERY_SMALL_BUFF_SZ);
    do_test(SMALL_BUFF_SZ, VERY_SMALL_BUFF_SZ);
    do_test(LARGE_BUFF_SZ, VERY_SMALL_BUFF_SZ);

    do_test(EMBARASSINGLY_SMALL_BUFF_SZ, SMALL_BUFF_SZ);
    do_test(VERY_SMALL_BUFF_SZ, SMALL_BUFF_SZ);
    do_test(SMALL_BUFF_SZ, SMALL_BUFF_SZ);
    do_test(LARGE_BUFF_SZ, SMALL_BUFF_SZ);

    do_test(EMBARASSINGLY_SMALL_BUFF_SZ, LARGE_BUFF_SZ);
    do_test(VERY_SMALL_BUFF_SZ, LARGE_BUFF_SZ);
    do_test(SMALL_BUFF_SZ, LARGE_BUFF_SZ);
    do_test(LARGE_BUFF_SZ, LARGE_BUFF_SZ);
}
