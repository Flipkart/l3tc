
#include "debug.h"
#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <assert.h>

void print_byte_array(char *src_buf, size_t src_len, char *dbgbuf, size_t dbgbuf_len) {
    assert(dbgbuf_len >= 16);

    size_t requires_skip = ((src_len * 3 + 2) > dbgbuf_len);
    size_t elipsis_start_idx = ((dbgbuf_len - 1) / 3) / 2;

    size_t i, j;
    for (i = 0, j = 1; i < src_len; i++, j+=3) {
        if (requires_skip) {
            if (elipsis_start_idx == i) {
                sprintf(dbgbuf + j, ".. ");
                if (src_len - i > i) {
                    i = src_len - i - 1;
                }
                continue;
            }
        }
        int x = 0x000000FF & src_buf[i];
        sprintf(dbgbuf + j, "%02x ", x);
    }
    
    dbgbuf[0] = '[';
    if (j > 1) {
        dbgbuf[j - 1] = ']';
        dbgbuf[j] = '\0';
    } else {
        dbgbuf[1] = ']';
        dbgbuf[2] = '\0';
    }
}
