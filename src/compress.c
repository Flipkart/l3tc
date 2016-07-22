#include "compress.h"
#include "log.h"

#include <assert.h>
#include <string.h>

#define C_LOG "compression"

ssize_t do_decompress(compress_t *comp, void *to, ssize_t capacity) {
    assert(comp != NULL);
    z_stream *zstrm = &comp->inflate;
    assert(zstrm != NULL);
    if (zstrm->avail_in == 0) {
        zstrm->avail_in = comp->inflatable_bytes;
        zstrm->next_in = comp->inflate_src_buff;
    }
    zstrm->avail_out = capacity;
    zstrm->next_out = to;

    int ret;
    do {
        ret = inflate(zstrm, Z_NO_FLUSH);
        assert(ret != Z_STREAM_ERROR);
    } while ((zstrm->avail_out != 0) && (zstrm->avail_in != 0));

    if (zstrm->avail_in == 0) {
        comp->inflatable_bytes = 0;
    }

    return capacity - zstrm->avail_out;
}

ssize_t do_compress(compress_t *comp, void *to, ssize_t capacity, ssize_t *consumed, int *complete) {
    assert(comp != NULL);
    ssize_t data_copied_from_buffer = 0;
    if (comp->deflate_surplus > 0) {
        data_copied_from_buffer = (comp->deflate_surplus > capacity) ? capacity : comp->deflate_surplus;
        memcpy(to, comp->deflate_dest_buff, data_copied_from_buffer);
        comp->deflate_surplus -= data_copied_from_buffer;
    }
    ssize_t remaining_capacity = capacity - data_copied_from_buffer;
    assert(remaining_capacity >= 0);
    if ((comp->deflate_surplus > 0 || remaining_capacity == 0) && (capacity > 0)) {
        *complete = 0;
        *consumed = 0;
        return data_copied_from_buffer;
    }
    z_stream *zstrm = &comp->deflate;
    assert(zstrm != NULL);
    zstrm->avail_out = remaining_capacity;
    zstrm->next_out = to;
    ssize_t available_at_start = zstrm->avail_in;
    int ret;
    do {
        ret = deflate(zstrm, Z_NO_FLUSH);
        assert(ret != Z_STREAM_ERROR);
    } while ((zstrm->avail_out != 0) && (zstrm->avail_in != 0));

    if (zstrm->avail_out == 0) {
        zstrm->avail_out = COMPRESSED_SURPLUS_CONTENT_CAPACITY;
        zstrm->next_out = comp->deflate_dest_buff;
        do {
            ret = deflate(zstrm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);
        } while ((zstrm->avail_out != 0) && (zstrm->avail_in != 0));
        comp->deflate_surplus = COMPRESSED_SURPLUS_CONTENT_CAPACITY - zstrm->avail_out;
    }

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

int init_compression_ctx(compress_t *comp, int compression_level) {
    assert(comp != NULL);
    int ret = deflateInit(&comp->deflate, compression_level);
    if (ret != Z_OK) {
        log_crit(C_LOG, L("deflate-stream initialization failed(err: %d): %s"), ret, comp->deflate.msg);
        return -1;
    }
    ret = inflateInit(&comp->inflate);
    if (ret != Z_OK) {
        log_crit(C_LOG, L("inflate-stream initialization failed(err: %d): %s"), ret, comp->inflate.msg);
        return -1;
    }
    return 0;
}

int destroy_compression_ctx(compress_t *comp) {
    assert(comp != NULL);
    int ret = deflateEnd(&comp->deflate);
    if (ret != Z_OK) {
        log_crit(C_LOG, L("deflate-stream destroy failed(err: %d): %s"), ret, comp->deflate.msg);
        return -1;
    }
    ret = inflateEnd(&comp->inflate);
    if (ret != Z_OK) {
        log_crit(C_LOG, L("inflate-stream destroy failed(err: %d): %s"), ret, comp->inflate.msg);
        return -1;
    }
    return 0;
}

