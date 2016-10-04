#ifndef _COMPRESS_H
#define _COMPRESS_H

#include "config.h"

#ifdef USE_ZLIB
#include <zlib.h>
#endif

#ifdef USE_ZSTD
#include <zstd.h>
#endif

#include <stdint.h>
#include <sys/types.h>

#ifdef USE_ZLIB
#define DECOMPRESSION_SRC_BUFF_CAPACITY 64*1024
#define DEFAULT_COMPRESSION_LEVEL Z_DEFAULT_COMPRESSION
#define MAX_COMPRESSION_LEVEL Z_BEST_COMPRESSION
#define MIN_COMPRESSION_LEVEL Z_BEST_SPEED
#define NO_COMPRESSION_LEVEL Z_NO_COMPRESSION
#define COMPRESSION_IMPL "zlib"
#endif
#ifdef USE_ZSTD
#define DEFAULT_COMPRESSION_LEVEL 4
#define MAX_COMPRESSION_LEVEL 22
#define MIN_COMPRESSION_LEVEL 1
#define NO_COMPRESSION_LEVEL -1
#define COMPRESSION_IMPL "zstd"
#endif

struct compress_s {
#ifdef USE_ZLIB
    z_stream deflate;
    z_stream inflate;
    uint8_t inflate_src_buff[DECOMPRESSION_SRC_BUFF_CAPACITY];
#endif
    
#ifdef USE_ZSTD
    ZSTD_CStream* cstream;
    ZSTD_inBuffer cinput;

    ZSTD_DStream* dstream;

    uint8_t *inflate_src_buff;
    uint32_t inflate_src_buff_offset;
#endif
    
    int deflate_fully_flushed;
    uint32_t inflate_src_buff_sz;

    uint32_t inflatable_bytes;
};

typedef struct compress_s compress_t;

int init_compression_ctx(compress_t *comp, int compression_level);

int destroy_compression_ctx(compress_t *comp);

ssize_t do_decompress(compress_t *comp, void *to, ssize_t capacity);

ssize_t do_compress(compress_t *comp, void *to, ssize_t capacity, ssize_t *consumed, int *complete);

ssize_t worst_case_compressed_out_sz(compress_t *comp, ssize_t len);

void setup_compress_input(compress_t *comp, void *buff, ssize_t len);

#endif
