#ifndef _BA_HTAB_H
#define _BA_HTAB_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif
#include "htab_common.h"

#include <uthash.h>

/* byte array key based hash table */

struct batab_entry_s {
    void *value;
    UT_hash_handle hh;
};
typedef struct batab_entry_s batab_entry_t;

struct batab_s {
    batab_entry_t *t;
    char *name;
    unsigned key_offset;
    unsigned key_len;
    value_destructor_t *val_destructor;
    char *print_buf;
    batab_entry_t *tmp;
};
typedef struct batab_s batab_t;

int batab_init(batab_t *tab, unsigned key_offset, unsigned key_len, value_destructor_t *val_destructor, const char *name);

void batab_destory(batab_t *tab);

void *batab_get(batab_t *tab, uint8_t *key);

int batab_remove(batab_t *tab, uint8_t *key);

int batab_put(batab_t *tab, void *new_value, void **old_value);

#define batab_foreach_do(tab, e)                \
    HASH_ITER(hh, tab->t, e, tab->tmp)

#endif
