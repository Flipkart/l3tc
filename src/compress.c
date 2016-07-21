#include "compress.h"

#include <assert.h>

ssize_t do_compress(compress_t *comp, void *to, ssize_t capacity, ssize_t *consumed, int *complete) {
    assert(comp != NULL);
    z_stream *zstrm = &comp->deflate;
    assert(zstrm != NULL);
    zstrm->avail_out = capacity;
    zstrm->next_out = to;
    ssize_t available_at_start = zstrm->avail_in;
    int ret;
    do {
        ret = deflate(zstrm, Z_NO_FLUSH);
        assert(ret != Z_STREAM_ERROR);
    } while ((zstrm->avail_out != 0) && (zstrm->avail_in != 0));

    *complete = (zstrm->avail_in == 0);

    *consumed = available_at_start - zstrm->avail_in;
    return capacity - zstrm->avail_out;
}

ssize_t worst_case_compressed_out_sz(compress_t *comp, ssize_t len) {
    assert(comp != NULL);
    return deflateBound(&comp->deflate, len);
}

void setup_compress_input(compress_t *comp, void *buff, ssize_t len) {
    assert(comp != NULL);
    z_stream *zstrm = &comp->deflate;
    assert(zstrm != NULL);
    assert(0 == zstrm->avail_in);
    zstrm->avail_in = len;
    zstrm->next_in = buff;
}

