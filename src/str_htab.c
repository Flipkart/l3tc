#include "str_htab.h"
#include "log.h"

int shtab_init(shtab_t *tab, value_destructor_t *val_destructor, const char *name) {
    log_info("ht", L("initializing hash-table %s"), name);
    tab->t = NULL;
    tab->name = NULL;
    if (NULL != name) {
        tab->name = strdup(name);
        if (NULL == tab->name) {
            log_warn("str_ht", L("failed to set hash-table name: %s"), name); /*ignore*/
        }
    }
    tab->val_destructor = val_destructor;
    return 0;
}

static inline void _shtab_free_val(shtab_t *tab, void *val) {
    if (tab->val_destructor != NULL) tab->val_destructor(val);
}

static inline void _shtab_del_entry(shtab_t *tab, shtab_entry_t *e) {
    HASH_DEL(tab->t, e);
    free(e->key);
    _shtab_free_val(tab, e->value);
    free(e);
}

void shtab_destory(shtab_t *tab) {
    shtab_entry_t *e, *tmp;
    HASH_ITER(hh, tab->t, e, tmp) {
        _shtab_del_entry(tab, e);
    }
    free(tab->name);
}

static inline shtab_entry_t *_shtab_get(shtab_t *tab, char *key) {
    shtab_entry_t *e;
    HASH_FIND_STR(tab->t, key, e);
    return e;
}

void *shtab_get(shtab_t *tab, char *key) {
    shtab_entry_t *e = _shtab_get(tab, key);
    if (e == NULL) return NULL;
    return e->value;
}

int shtab_put(shtab_t *tab, char *key, void *new_value, void **old_value) {
    shtab_entry_t *e = _shtab_get(tab, key);
    if (e == NULL) {
        e = malloc(sizeof(shtab_entry_t));
        if (e == NULL) {
            log_warn("str_ht", L("failed to insert key %s and value %p into hash-table %s (couldn't allocate entry)"), key, new_value, tab->name);
            return -1;
        }
        e->key = strdup(key);
        if (e->key == NULL) {
            log_warn("str_ht", L("failed to insert key %s and value %p into hash-table %s (couldn't duplicate key)"), key, new_value, tab->name);
            free(e);
            return -1;
        }
        e->value = new_value;
        HASH_ADD_KEYPTR(hh, tab->t, e->key, strlen(e->key), e);
    } else {
        if (old_value != NULL)
            *old_value = e->value;
        else
            _shtab_free_val(tab, e->value);
        
        e->value = new_value;
    }
    return 0;
}

void shtab_remove(shtab_t *tab, char *key) {
    shtab_entry_t *e = _shtab_get(tab, key);
    if (e == NULL) return;
    _shtab_del_entry(tab, e);
}
