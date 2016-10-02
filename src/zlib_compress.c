#include "compress.h"
#include "log.h"

#include <assert.h>
#include <string.h>
#include "debug.h"

#define C_LOG "comp/zlib"

ssize_t do_decompress(compress_t *comp, void *to, ssize_t capacity) {
    assert(comp != NULL);
    z_stream *zstrm = &comp->inflate;
    assert(zstrm != NULL);
    if (zstrm->avail_in == 0) {
        DBG(C_LOG, L("decompress(%p) input reset"), comp);
        zstrm->avail_in = comp->inflatable_bytes;
        zstrm->next_in = comp->inflate_src_buff;
    }
    zstrm->avail_out = capacity;
    zstrm->next_out = to;

    ssize_t available_at_start = zstrm->avail_in;

    int ret;
    do {
        ret = inflate(zstrm, Z_SYNC_FLUSH);
        assertf(ret >= Z_OK, C_LOG, L("inflate return: %d"), ret);
    } while ((zstrm->avail_out != 0) && (zstrm->avail_in != 0));

    if (zstrm->avail_in == 0) {
        comp->inflatable_bytes = 0;
    }

    ssize_t decompressed_out = capacity - zstrm->avail_out;

    DBG(C_LOG, L("decompress(%p) %zd bytes (unhandled: %u) => %zd bytes (remaining capacity: %u) (dest buff: %p (capacity: %zd))"), \
        comp, available_at_start - zstrm->avail_in, zstrm->avail_in, decompressed_out, zstrm->avail_out, to, capacity);

    return decompressed_out;
}

#ifdef DEBUG
#define DBG_BUFF_SZ 50000
char dbgbuf[DBG_BUFF_SZ];
#define DBG_PEEK(buff, offset, len, msg)                                \
    if (DEBUG_LOG_ENABLED) {                                            \
        print_byte_array(buff + offset, len, dbgbuf, DBG_BUFF_SZ);      \
        DBG(C_LOG, L("%s TRACE %zd bytes starting in: %s"), msg, len, dbgbuf); \
    }
#endif

ssize_t do_compress(compress_t *comp, void *to, ssize_t capacity, ssize_t *consumed, int *complete) {
    assert(comp != NULL);
    z_stream *zstrm = &comp->deflate;
    assert(zstrm != NULL);
    zstrm->avail_out = capacity;
    zstrm->next_out = to;
    ssize_t available_at_start = zstrm->avail_in;
    ssize_t bytes_directly_written = 0;
    if (available_at_start > 0 || ! comp->deflate_fully_flushed) {
        int ret;
        do {
            ret = deflate(zstrm, Z_SYNC_FLUSH);
            assertf(ret >= Z_OK, C_LOG, L("deflate return: %d"), ret);
        } while ((zstrm->avail_out != 0) && (zstrm->avail_in != 0));

        comp->deflate_fully_flushed = (zstrm->avail_out > 0);

        bytes_directly_written = capacity - zstrm->avail_out;
    }

    *complete = (zstrm->avail_in == 0);
    *consumed = available_at_start - zstrm->avail_in;

    DBG(C_LOG, L("compress(%p) [complete: %d] overall %zd bytes => %zd bytes"), comp, *complete, *consumed, bytes_directly_written);

    return bytes_directly_written;
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
    if (ret < Z_OK) {
        log_crit(C_LOG, L("deflate-stream initialization failed(err: %d): %s"), ret, comp->deflate.msg);
        return -1;
    }
    comp->deflate_fully_flushed = 0;
    comp->inflate_src_buff_sz = DECOMPRESSION_SRC_BUFF_CAPACITY;
    ret = inflateInit(&comp->inflate);
    if (ret < Z_OK) {
        log_crit(C_LOG, L("inflate-stream initialization failed(err: %d): %s"), ret, comp->inflate.msg);
        return -1;
    }
    return 0;
}

int destroy_compression_ctx(compress_t *comp) {
    int failure = 0;
    assert(comp != NULL);
    unsigned char buff[64];
    char remaining_bytes_message[64];
    comp->deflate.next_out = buff;
    comp->deflate.avail_out = sizeof(buff);
    int ret = deflate(&comp->deflate, Z_FINISH);
    size_t diff_bytes = (sizeof(buff) - comp->deflate.avail_out);
    if ((diff_bytes > 0) || (ret != Z_STREAM_END)) {
        print_byte_array(buff, diff_bytes, remaining_bytes_message, sizeof(remaining_bytes_message));
        log_crit(C_LOG, L("deflate-stream destroy found %s %zd un-flushed bytes(err: %d): %s {bytes: %s}"), comp->deflate.avail_out == 0 ? "atleast" : "exactly", diff_bytes,  ret, comp->deflate.msg, remaining_bytes_message);
        failure = ret;
    }
    ret = deflateEnd(&comp->deflate);
    if (ret < Z_OK) {
        log_crit(C_LOG, L("deflate-stream destroy failed(err: %d): %s"), ret, comp->deflate.msg);
        failure = ret;
    }
    ret = inflateEnd(&comp->inflate);
    if (ret < Z_OK) {
        log_crit(C_LOG, L("inflate-stream destroy failed(err: %d): %s"), ret, comp->inflate.msg);
        failure = ret;
    }
    return failure;
}

