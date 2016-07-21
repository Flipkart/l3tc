#ifndef _COMPRESS_H
#define _COMPRESS_H

#include <zlib.h>

struct compress_s {
    z_stream deflate;
    z_stream inflate;
};

typedef struct compress_s compress_t;

ssize_t do_compress(compress_t *comp, void *to, ssize_t capacity, ssize_t *consumed, int *complete);

ssize_t worst_case_compressed_out_sz(compress_t *comp, ssize_t len);

void setup_compress_input(compress_t *comp, void *buff, ssize_t len);

#endif
