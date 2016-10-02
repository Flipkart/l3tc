#include "compress.h"
#include "log.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "debug.h"

#define C_LOG "comp/zstd"

ssize_t do_decompress(compress_t *comp, void *to, ssize_t capacity) {
    assert(comp != NULL);
    ZSTD_DStream *dstream = comp->dstream;
    assert(dstream != NULL);
    ZSTD_outBuffer out = { to, capacity, 0 };
    ZSTD_inBuffer in = { comp->inflate_src_buff, comp->inflatable_bytes, 0 };
    size_t decompress_status = 0;
    do {
        decompress_status = ZSTD_decompressStream(dstream, &out, &in);
        assertf(! ZSTD_isError(decompress_status), C_LOG, L("decompress returned: %s"), ZSTD_getErrorName(decompress_status));
    } while ((in.pos < in.size) &&
             (out.pos < out.size));
    comp->inflatable_bytes -= in.pos;
    DBG(C_LOG, L("decompress(%p) %zd bytes (unhandled: %zd) => %zd bytes (remaining capacity: %zd) (dest buff: %p (orig capacity: %zd))"), \
        comp, in.pos, in.size - in.pos, out.pos, out.size - out.pos, to, capacity);

    return out.pos;
}

ssize_t do_compress(compress_t *comp, void *to, ssize_t capacity, ssize_t *consumed, int *complete) {
    assert(comp != NULL);
    ZSTD_CStream *cstream = comp->cstream;
    assert(cstream != NULL);
    ZSTD_outBuffer out = { to, capacity, 0 };
    uint32_t old_pos = comp->cinput.pos;
    size_t in_sz_hint;
    do {
        in_sz_hint = ZSTD_compressStream(cstream, &out , &comp->cinput);
        assertf(! ZSTD_isError(in_sz_hint), C_LOG, L("compress returned: %s"), ZSTD_getErrorName(in_sz_hint));
    } while ((comp->cinput.pos < comp->cinput.size) &&
             (out.pos < out.size));
    if (out.pos < out.size)  {
        size_t old_offset = out.pos;
        size_t remaining = ZSTD_flushStream(cstream, &out);
        assertf(! ZSTD_isError(remaining), C_LOG, L("compress flush returned: %s"), ZSTD_getErrorName(remaining));
        log_debug(C_LOG, L("zstd flush had %zd bytes remaining and flushed %zd bytes"), remaining, out.pos - old_offset);
    }
    *consumed = comp->cinput.pos - old_pos; 
    *complete = (comp->cinput.pos == comp->cinput.size);
    
    DBG(C_LOG, L("compress(%p) [complete: %d] overall %zd bytes => %zd bytes"), comp, *complete, *consumed, out.pos);

    return out.pos;
}

ssize_t worst_case_compressed_out_sz(compress_t *comp, ssize_t len) {
    return ZSTD_CStreamOutSize();
}

void setup_compress_input(compress_t *comp, void *buff, ssize_t len) {
    assert(comp != NULL);
    assert(comp->cinput.size == comp->cinput.pos);
    comp->cinput.size = len;
    comp->cinput.pos = 0;
    comp->cinput.src = buff;
}

int init_compression_ctx(compress_t *comp, int compression_level) {
    assert(comp != NULL);
    assertf(comp->cstream = ZSTD_createCStream(), C_LOG, L("Couldn't allocate ZStd compressor stream"));
    size_t init_res = ZSTD_initCStream(comp->cstream, compression_level);
    assertf(! ZSTD_isError(init_res), C_LOG, L("ZSTD_initCStream() error : %s"), ZSTD_getErrorName(init_res));
    memset(&comp->cinput, 0, sizeof(comp->cinput));

    assertf(comp->dstream = ZSTD_createDStream(), C_LOG, L("Couldn't allocate ZStd de-compressor stream"));
    init_res = ZSTD_initDStream(comp->dstream);
    comp->inflate_src_buff_sz = ZSTD_DStreamOutSize();
    comp->inflate_src_buff = malloc(comp->inflate_src_buff_sz);
    assertf(! ZSTD_isError(init_res), C_LOG, L("ZSTD_initDStream() error : %s"), ZSTD_getErrorName(init_res));
    return 0;
}

int destroy_compression_ctx(compress_t *comp) {
    int failure = 0;
    assert(comp != NULL);
    unsigned char buff[64];
    char remaining_bytes_message[64];
    ZSTD_outBuffer out = { buff, sizeof(buff), 0 };
    size_t const remaining = ZSTD_endStream(comp->cstream, &out);
    if (remaining > 0) {
        print_byte_array(buff, remaining, remaining_bytes_message, sizeof(remaining_bytes_message));
        log_warn(C_LOG, L("zstd compress-stream destroy had atleast %zd un-flushed bytes before close: {bytes: %s}"), remaining, remaining_bytes_message);
    }
    free(comp->inflate_src_buff);
    ZSTD_freeCStream(comp->cstream);

    ZSTD_freeDStream(comp->dstream);
    return failure;
}

