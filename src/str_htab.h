#ifndef _STR_HTAB_H
#define _STR_HTAB_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif
#include "htab_common.h"

/* string key based hash table */

struct shtab_entry_s {
    char *key;
    void *value;
    UT_hash_handle hh;
};
typedef struct shtab_entry_s shtab_entry_t;

struct shtab_s {
    shtab_entry_t *t;
    char *name;
    value_destructor_t *val_destructor;
};
typedef struct shtab_s shtab_t;

int shtab_init(shtab_t *tab, value_destructor_t *val_destructor, const char *name);

void shtab_destory(shtab_t *tab);

void *shtab_get(shtab_t *tab, char *key);

void shtab_remove(shtab_t *tab, char *key);

int shtab_put(shtab_t *tab, char *key, void *new_value, void **old_value);

#define shtab_foreach_do(tab, e)                                 \
    for(e = tab->t; e != NULL; e=(shtab_entry_t*)(e->hh.next))

#endif
