#include "ba_htab.h"
#include "log.h"
#include <stdio.h>
#include <assert.h>

static const char * _batab_print_key(batab_t *tab, uint8_t *key) {
    if (tab->print_buf == NULL) return NULL;
    unsigned i;
    for (i = 0; i < tab->key_len; i++) {
        sprintf(tab->print_buf + 1 + i*7, "%02x/%03d ", key[i], key[i]);
    }
    tab->print_buf[i*7] = ']';
    return tab->print_buf;
}

static const char * _batab_print_value_id(batab_t *tab, void *new_value) {
    if (tab->print_buf == NULL) return NULL;
    uint8_t *key = new_value + tab->key_offset;
    return _batab_print_key(tab, key);
}

int batab_init(batab_t *tab, unsigned key_offset, unsigned key_len, value_destructor_t *val_destructor, const char *name) {
    log_info("ht", L("initializing byte-array hash-table %s"), name);
    tab->t = NULL;
    tab->name = NULL;
    if (NULL != name) {
        tab->name = strdup(name);
        if (NULL == tab->name) {
            log_warn("ht", L("failed to set hash-table name: %s"), name); /*ignore*/
        }
    }
    int print_buf_sz = key_len * 7 + 2;
    tab->print_buf = malloc(print_buf_sz); /* each byte 2 chars in hex + paren, no \0 because last space will serve that purpose */
    if (tab->print_buf == NULL) {
        log_warn("ht", L("failed to create print-buffer(of %d bytes) for table %s"), print_buf_sz, name); /*ignore*/
    }
    tab->print_buf[0] = '[';
    tab->print_buf[print_buf_sz - 1] = '\0';
    tab->val_destructor = val_destructor;
    tab->key_offset = key_offset;
    tab->key_len = key_len;
    return 0;
}

static inline void _batab_free_val(batab_t *tab, void *val) {
    if (tab->val_destructor != NULL) tab->val_destructor(val);
}

static inline void _batab_del_entry(batab_t *tab, batab_entry_t *e, int free_value) {
    assert(e != NULL);
    DBG("ht", L("DELETing  hash-table %s entry for key %s and %s its value"), tab->name, _batab_print_value_id(tab, e->value), free_value ? "freeing" : "_not_ freeing");
    HASH_DEL(tab->t, e);
    if (free_value) _batab_free_val(tab, e->value);
    free(e);
}

void batab_destory(batab_t *tab) {
    DBG("ht", L("destorying hash-table %s"), tab->name);
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
    DBG("ht", L("table %s get key %s returning entry %p"), tab->name, _batab_print_key(tab, key), e);
    return e;
}

void *batab_get(batab_t *tab, uint8_t *key) {
    batab_entry_t *e = _batab_get(tab, key);
    if (e == NULL) return NULL;
    DBG("ht", L("table %s get key %s is returning non-null value %p"), tab->name, _batab_print_key(tab, key), e->value);
    return e->value;
}

int _batab_put_new(batab_t *tab, void *new_value) {
    batab_entry_t *e = malloc(sizeof(batab_entry_t));
    if (e == NULL) {
        log_warn("ba_ht", L("failed to insert key %s and value %p into hash-table %s (couldn't allocate entry)"), _batab_print_value_id(tab, new_value), new_value, tab->name);
        return -1;
    }
    e->value = new_value;
    DBG("ht", L("PUTing new entry for %s to table %s"), _batab_print_value_id(tab, new_value), tab->name);
    HASH_ADD_KEYPTR(hh, tab->t, new_value + tab->key_offset, tab->key_len, e);
    return 0;
}

int batab_put(batab_t *tab, void *new_value, void **old_value) {
    if (new_value == NULL) {
        DBG("ht", L("PUT to table %s requested with NULL value (IGNORING the request)"), tab->name);
        return -1;
    }
    uint8_t *key = new_value + tab->key_offset;
    batab_entry_t *e = _batab_get(tab, key);
    if (e != NULL) {
        if (old_value != NULL) {
            *old_value = e->value;
            DBG("ht", L("PUT-replace to table %s is capturing old value for key %s. Will not attempt to destory the old value."), tab->name, _batab_print_key(tab, key));
            _batab_del_entry(tab, e, 0);
        } else {
            DBG("ht", L("PUT-replace to table %s doesn't care about the old value for key %s"), tab->name, _batab_print_key(tab, key));
            _batab_del_entry(tab, e, 1);
        }
    }
    return _batab_put_new(tab, new_value);
}

int batab_remove(batab_t *tab, uint8_t *key) {
    assert(key != NULL);
    batab_entry_t *e = _batab_get(tab, key);
    DBG("ht", L("Removing key %s from table %s (entry: %p, value: %p)"), _batab_print_key(tab, key), tab->name, e, e == NULL ? NULL : e->value);
    if (e == NULL) return -1;
    _batab_del_entry(tab, e, 1);
    return 0;
}

unsigned batab_sz(batab_t *tab) {
    unsigned c = HASH_COUNT(tab->t);
    DBG("ht", L("Reporting table size %u for table %s"), c, tab->name);
    return c;
}
