#include "str_htab.h"
#include "log.h"

int htab_init(htab_t *tab, value_destructor_t *val_destructor, const char *name) {
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

static inline void _htab_free_val(htab_t *tab, void *val) {
    if (tab->val_destructor != NULL) tab->val_destructor(val);
}

static inline void _htab_del_entry(htab_t *tab, htab_entry_t *e) {
    HASH_DEL(tab->t, e);
    free(e->key);
    _htab_free_val(tab, e->value);
    free(e);
}

void htab_destory(htab_t *tab) {
    htab_entry_t *e, *tmp;
    HASH_ITER(hh, tab->t, e, tmp) {
        _htab_del_entry(tab, e);
    }
    free(tab->name);
}

static inline htab_entry_t *_htab_get(htab_t *tab, char *key) {
    htab_entry_t *e;
    HASH_FIND_STR(tab->t, key, e);
    return e;
}

void *htab_get(htab_t *tab, char *key) {
    htab_entry_t *e = _htab_get(tab, key);
    if (e == NULL) return NULL;
    return e->value;
}

int htab_put(htab_t *tab, char *key, void *new_value, void **old_value) {
    htab_entry_t *e = _htab_get(tab, key);
    if (e == NULL) {
        e = malloc(sizeof(htab_entry_t));
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
            _htab_free_val(tab, e->value);
        
        e->value = new_value;
    }
    return 0;
}

void htab_remove(htab_t *tab, char *key) {
    htab_entry_t *e = _htab_get(tab, key);
    if (e == NULL) return;
    _htab_del_entry(tab, e);
}
