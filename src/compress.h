#ifndef _COMPRESS_H
#define _COMPRESS_H

#include <zlib.h>
#include <stdint.h>

#define COMPRESSED_SURPLUS_CONTENT_CAPACITY 4*1024
#define DECOMPRESSION_SRC_BUFF_CAPACITY 64*1024

#define DEFAULT_COMPRESSION_LEVEL Z_DEFAULT_COMPRESSION

struct compress_s {
    z_stream deflate;
    uint8_t deflate_dest_buff[COMPRESSED_SURPLUS_CONTENT_CAPACITY];
    uint32_t deflate_surplus;
    uint32_t deflate_surplus_offset;

    z_stream inflate;
    uint8_t inflate_src_buff[DECOMPRESSION_SRC_BUFF_CAPACITY];
    uint32_t inflatable_bytes;
    uint32_t inflatable_bytes_offset;
};

typedef struct compress_s compress_t;

int init_compression_ctx(compress_t *comp, int compression_level);

int destroy_compression_ctx(compress_t *comp);

ssize_t do_decompress(compress_t *comp, void *to, ssize_t capacity);

ssize_t do_compress(compress_t *comp, void *to, ssize_t capacity, ssize_t *consumed, int *complete);

ssize_t worst_case_compressed_out_sz(compress_t *comp, ssize_t len);

void setup_compress_input(compress_t *comp, void *buff, ssize_t len);

#endif
