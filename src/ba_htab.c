#include "ba_htab.h"
#include "log.h"
#include <stdio.h>

int batab_init(batab_t *tab, unsigned key_offset, unsigned key_len, value_destructor_t *val_destructor, const char *name) {
    log_info("ht", L("initializing byte-array hash-table %s"), name);
    tab->t = NULL;
    tab->name = NULL;
    if (NULL != name) {
        tab->name = strdup(name);
        if (NULL == tab->name) {
            log_warn("str_ht", L("failed to set hash-table name: %s"), name); /*ignore*/
        }
    }
    tab->print_buf = malloc(key_len * 3 + 2); /* each byte 2 chars in hex + paren, no \0 because last space will serve that purpose */
    if (tab->print_buf == NULL) {
        log_warn("str_ht", L("failed to create print-buffer name: %s"), name); /*ignore*/
    }
    tab->val_destructor = val_destructor;
    tab->key_offset = key_offset;
    tab->key_len = key_len;
    return 0;
}

static inline void _batab_free_val(batab_t *tab, void *val) {
    if (tab->val_destructor != NULL) tab->val_destructor(val);
}

static inline void _batab_del_entry(batab_t *tab, batab_entry_t *e, int free_value) {
    HASH_DEL(tab->t, e);
    if (free_value) _batab_free_val(tab, e->value);
    free(e);
}

void batab_destory(batab_t *tab) {
    batab_entry_t *e, *tmp;
    HASH_ITER(hh, tab->t, e, tmp) {
        _batab_del_entry(tab, e, 1);
    }
    free(tab->name);
    free(tab->print_buf);
}

static inline batab_entry_t *_batab_get(batab_t *tab, uint8_t *key) {
    batab_entry_t *e;
    HASH_FIND(hh, tab->t, key, tab->key_len, e);
    return e;
}

void *batab_get(batab_t *tab, uint8_t *key) {
    batab_entry_t *e = _batab_get(tab, key);
    if (e == NULL) return NULL;
    return e->value;
}

void _batab_print_key(batab_t *tab, void *new_value) {
    tab->print_buf[0] = '[';
    unsigned i;
    uint8_t *key = new_value + tab->key_offset;
    for (i = 0; i < tab->key_len; i++) {
        sprintf(tab->print_buf + 1 + i*3, "%02x ", key[i]);
    }
    
    sprintf(tab->print_buf + i*3, "]");
}

int _batab_put(batab_t *tab, void *new_value) {
    batab_entry_t *e = malloc(sizeof(batab_entry_t));
    if (e == NULL) {
        _batab_print_key(tab, new_value);
        log_warn("ba_ht", L("failed to insert key %s and value %p into hash-table %s (couldn't allocate entry)"), tab->print_buf, new_value, tab->name);
        return -1;
    }
    e->value = new_value;
    HASH_ADD_KEYPTR(hh, tab->t, new_value + tab->key_offset, tab->key_len, e);
    return 0;
}

int batab_put(batab_t *tab, void *new_value, void **old_value) {
    if (new_value == NULL) return -1;
    uint8_t *key = new_value + tab->key_offset;
    batab_entry_t *e = _batab_get(tab, key);
    if (e != NULL) {
        if (old_value != NULL) {
            *old_value = e->value;
            _batab_del_entry(tab, e, 0);
        } else {
            _batab_del_entry(tab, e, 1);
        }
    }
    return _batab_put(tab, new_value);
}

void batab_remove(batab_t *tab, uint8_t *key) {
    batab_entry_t *e = _batab_get(tab, key);
    if (e == NULL) return;
    _batab_del_entry(tab, e, 1);
}
