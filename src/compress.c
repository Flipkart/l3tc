#include "compress.h"
#include "log.h"

#include <assert.h>
#include <string.h>
#include "debug.h"
#include <stdio.h>

#define C_LOG "compression"

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
    ssize_t data_copied_from_buffer = 0;
    ssize_t remaining_capacity = capacity;
    if (comp->deflate_surplus > 0) {
        data_copied_from_buffer = (comp->deflate_surplus > capacity) ? capacity : comp->deflate_surplus;
        memcpy(to, comp->deflate_dest_buff + comp->deflate_surplus_offset, data_copied_from_buffer);
#ifdef DEBUG
        DBG_PEEK(to, 0, data_copied_from_buffer, "Compress surplus-drain");
#endif
        comp->deflate_surplus -= data_copied_from_buffer;
        if (comp->deflate_surplus > 0) {
            comp->deflate_surplus_offset += data_copied_from_buffer;
        }
        remaining_capacity -= data_copied_from_buffer;
        DBG(C_LOG, L("compress(%p) copied %zd compressed surplus (remaining surplus: %u, remaining dest capacity: %zd) bytes over to buff %p"), comp, data_copied_from_buffer, comp->deflate_surplus, remaining_capacity, to);
    }
    assertf(remaining_capacity >= 0, C_LOG, L("remaining capacity was: %zd"), remaining_capacity);
    if (0 == remaining_capacity) {
        *complete = 0;
        *consumed = 0;
        DBG(C_LOG, L("compress(%p) ran out of space to write to, still has surplus: %u at offset %u"), comp, comp->deflate_surplus, comp->deflate_surplus_offset);
        return data_copied_from_buffer;
    }
    assertf(comp->deflate_surplus == 0, C_LOG, L("deflate surplus was: %u"), comp->deflate_surplus);
    comp->deflate_surplus_offset = 0;
    z_stream *zstrm = &comp->deflate;
    assert(zstrm != NULL);
    zstrm->avail_out = remaining_capacity;
    zstrm->next_out = to + data_copied_from_buffer;
    ssize_t available_at_start = zstrm->avail_in;
    ssize_t bytes_directly_written;
    if (available_at_start > 0 || ! comp->deflate_fully_flushed) {
        int ret;
        do {
            ret = deflate(zstrm, Z_SYNC_FLUSH);
            assertf(ret >= Z_OK, C_LOG, L("deflate return: %d"), ret);
        } while ((zstrm->avail_out != 0) && (zstrm->avail_in != 0));

        ssize_t remaining_capacity_after_compression = zstrm->avail_out;
        ssize_t surplus_input;
        if (DEBUG_LOG_ENABLED) surplus_input = zstrm->avail_in;
#ifdef DEBUG
        if (zstrm->avail_out != remaining_capacity) {
            DBG_PEEK(to + data_copied_from_buffer, 0, remaining_capacity - zstrm->avail_out, "Compress direct-write");
        }
#endif

        if (0 == remaining_capacity_after_compression) {
            zstrm->avail_out = COMPRESSED_SURPLUS_CONTENT_CAPACITY;
            zstrm->next_out = comp->deflate_dest_buff;
            do {
                ret = deflate(zstrm, Z_SYNC_FLUSH);
                assertf(ret >= Z_OK, C_LOG, L("deflate return: %d"), ret);
            } while ((zstrm->avail_out != 0) && (zstrm->avail_in != 0));
            comp->deflate_surplus = COMPRESSED_SURPLUS_CONTENT_CAPACITY - zstrm->avail_out;
            comp->deflate_fully_flushed = (zstrm->avail_out > 0);
        } else {
            comp->deflate_fully_flushed = 1;
        }

        bytes_directly_written = capacity - remaining_capacity_after_compression;

        DBG(C_LOG, L("compress(%p) %zd bytes (handled directly: %zd, handled towards surplus buff: %zd, unhandled: %u) => %zd bytes (actual dest: %zd bytes (remaining capacity: %zd), surplus buff: %u bytes (remaining capacity: %u))"),
            comp,
            available_at_start - zstrm->avail_in, available_at_start - surplus_input, surplus_input - zstrm->avail_in, zstrm->avail_in,
            bytes_directly_written + comp->deflate_surplus, bytes_directly_written, remaining_capacity_after_compression, comp->deflate_surplus, COMPRESSED_SURPLUS_CONTENT_CAPACITY - comp->deflate_surplus);
    } else {
        bytes_directly_written = capacity - remaining_capacity;
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
    ret = inflateInit(&comp->inflate);
    if (ret < Z_OK) {
        log_crit(C_LOG, L("inflate-stream initialization failed(err: %d): %s"), ret, comp->inflate.msg);
        return -1;
    }
    return 0;
}

int destroy_compression_ctx(compress_t *comp) {
    assert(comp != NULL);
    int ret = deflateEnd(&comp->deflate);
    if (ret < Z_OK) {
        log_crit(C_LOG, L("deflate-stream destroy failed(err: %d): %s"), ret, comp->deflate.msg);
    }
    ret = inflateEnd(&comp->inflate);
    if (ret < Z_OK) {
        log_crit(C_LOG, L("inflate-stream destroy failed(err: %d): %s"), ret, comp->inflate.msg);
    }
    return 0;
}

