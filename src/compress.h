#ifndef _COMPRESS_H
#define _COMPRESS_H

#include <zlib.h>
#include <stdint.h>

#define COMPRESSED_SURPLUS_CONTENT_CAPACITY 4096
#define UNCOMPRESSED_SURPLUS_CONTENT_CAPACITY 4*4096

struct compress_s {
    z_stream deflate;
    uint8_t deflate_dest_buff[COMPRESSED_SURPLUS_CONTENT_CAPACITY];
    uint32_t deflate_surplus;

    z_stream inflate;
    uint8_t inflate_src_buff[UNCOMPRESSED_SURPLUS_CONTENT_CAPACITY];
    uint32_t inflate_surplus;
};

typedef struct compress_s compress_t;

ssize_t do_compress(compress_t *comp, void *to, ssize_t capacity, ssize_t *consumed, int *complete);

ssize_t worst_case_compressed_out_sz(compress_t *comp, ssize_t len);

void setup_compress_input(compress_t *comp, void *buff, ssize_t len);

#endif
