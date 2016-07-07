#ifndef _STR_HTAB_H
#define _STR_HTAB_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <uthash.h>

struct htab_entry_s {
    char *key;
    void *value;
    UT_hash_handle hh;
};
typedef struct htab_entry_s htab_entry_t;

typedef void (value_destructor_t)(void *v);

struct htab_s {
    htab_entry_t *t;
    char *name;
    value_destructor_t *val_destructor;
};
typedef struct htab_s htab_t;

int htab_init(htab_t *tab, value_destructor_t *val_destructor, const char *name);

void htab_destory(htab_t *tab);

void *htab_get(htab_t *tab, char *key);

void htab_remove(htab_t *tab, char *key);

int htab_put(htab_t *tab, char *key, void *new_value, void **old_value);

#define htab_foreach_do(tab, e)                                 \
    for(e = tab->t; e != NULL; e=(htab_entry_t*)(e->hh.next))

#endif
