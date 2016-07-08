#include "../src/ba_htab.h"
#include <assert.h>
#include <stddef.h>
#include <utarray.h>

typedef struct data_s {
    char *str;
    int i32;
} data_t;

typedef int (cmpfcn_t)(const void *, const void *);

int str_cmpfcn(const void *one, const void *other) {
    return strcmp(*(char**)one, *(char**)other);
}

void test_with_statically_allocated_values() {
    batab_t tab;

    assert(batab_init(&tab, offsetof(data_t, i32), sizeof(int), NULL, "static-alloc") == 0);

    data_t foo, bar, quux;
    foo.i32 = 10;
    foo.str = "foo";
    bar.i32 = 20;
    bar.str = "bar";
    quux.i32 = 30;
    quux.str = "quux";
    
    assert(batab_put(&tab, &foo, NULL) == 0);
    assert(batab_put(&tab, &bar, NULL) == 0);
    assert(batab_put(&tab, &quux, NULL) == 0);

    int lkp = 10;

    assert(strcmp(((data_t*)batab_get(&tab, (uint8_t *)&lkp))->str, "foo") == 0);
    lkp = 20;
    assert(strcmp(((data_t*)batab_get(&tab, (uint8_t *)&lkp))->str, "bar") == 0);
    lkp = 30;
    assert(strcmp(((data_t*)batab_get(&tab, (uint8_t *)&lkp))->str, "quux") == 0);

    data_t *old_val = NULL;
    data_t corge;
    corge.i32 = 20;
    corge.str = "corge";
    assert(batab_put(&tab, &corge, (void **)&old_val) == 0);
    assert(strcmp(old_val->str, "bar") == 0);

    UT_array *strs;
    utarray_new(strs, &ut_str_icd);
    
    batab_entry_t *e;
    
    batab_foreach_do((&tab), e) {
        utarray_push_back(strs, &((data_t*)e->value)->str);
    }
    utarray_sort(strs, (cmpfcn_t *) str_cmpfcn);

    assert(strcmp(*(char**)utarray_eltptr(strs, 0), "corge") == 0);
    assert(strcmp(*(char**)utarray_eltptr(strs, 1), "foo") == 0);
    assert(strcmp(*(char**)utarray_eltptr(strs, 2), "quux") == 0);
    utarray_free(strs);

    batab_destory(&tab);
}

#define KEY_LEN 100

typedef struct foo {
    struct foo *next;
    char key[KEY_LEN];
    int label;
} F;

void foo_destructor(void *f) {
    F *c = (F*) f;
    while(c != NULL) {
        F *p = c;
        c = c->next;
        free(p);
    }
}

void test_with_complex_dynamically_allocated_values() {
    F *one = calloc(1, sizeof(F));
    strcpy(one->key, "ONE");
    one->label = 1;
    one->next = calloc(1, sizeof(F));
    strcpy(one->next->key, "NEXT of ONE");
    one->next->next = NULL;

    F *two = calloc(1, sizeof(F));
    strcpy(two->key, "TWO");
    two->label = 2;
    two->next = NULL;

    F *three = calloc(1, sizeof(F));
    strcpy(three->key, "TWO");
    three->label = 3;
    three->next = NULL;
    three->next = calloc(1, sizeof(F));
    strcpy(three->next->key, "NEXT of THREE");
    three->next->next = NULL;

    F *four = calloc(1, sizeof(F));
    strcpy(four->key, "TWO");
    four->label = 4;
    four->next = NULL;
    four->next = calloc(1, sizeof(F));
    strcpy(four->next->key, "NEXT of FOUR");
    four->next->next = NULL;

    batab_t tab;

    assert(batab_init(&tab, offsetof(F, key), KEY_LEN, foo_destructor, "dyn-alloc") == 0);

    assert(batab_put(&tab, one, NULL) == 0);
    assert(batab_put(&tab, two, NULL) == 0);

    char key[KEY_LEN];

    memset(key, 0, KEY_LEN);
    strcpy(key, "ONE");
    assert(((F*) batab_get(&tab, key))->label == 1);

    memset(key, 0, KEY_LEN);
    strcpy(key, "TWO");
    assert(((F*) batab_get(&tab, key))->label == 2);

    UT_array *strs;
    utarray_new(strs, &ut_str_icd);
    char buff[1024];
    
    batab_entry_t *e;
    char * to_free[] = {NULL, NULL};
    int i = 0;
    batab_foreach_do((&tab), e) {
        F *v = (F*) e->value;
        buff[0] = '\0';
        while(v != NULL) {
            strcat(buff, v->key);
            strcat(buff, ",");
            v = v->next;
        }
        char *x = strdup(buff);
        to_free[i++] = x;
        utarray_push_back(strs, &x);
    }

    i = 0;
    utarray_sort(strs, str_cmpfcn);

    char *val = *(char**)utarray_eltptr(strs, 0);
    assert(strcmp(val, "ONE,NEXT of ONE,") == 0);
    val = *(char**)utarray_eltptr(strs, 1);
    assert(strcmp(val, "TWO,") == 0);

    utarray_clear(strs);
    free(to_free[0]);
    free(to_free[1]);
    
    F *old_val = NULL;
    assert(batab_put(&tab, three, (void**)&old_val) == 0);
    memset(key, 0, KEY_LEN);
    strcpy(key, "TWO");
    assert(((F*) batab_get(&tab, key))->label == 3);
    assert(old_val->label == 2);

    foo_destructor(two);

    assert(batab_put(&tab, four, NULL) == 0);
    assert(((F*) batab_get(&tab, key))->label == 4);


    memset(to_free, 0, sizeof(to_free));
    batab_foreach_do((&tab), e) {
        F *v = (F*) e->value;
        buff[0] = '\0';
        while(v != NULL) {
            strcat(buff, v->key);
            strcat(buff, ",");
            v = v->next;
        }
        char *x = strdup(buff);
        to_free[i++] = x;
        utarray_push_back(strs, &x);
    }
    utarray_sort(strs, str_cmpfcn);

    val = *(char**)utarray_eltptr(strs, 0);
    assert(strcmp(val, "ONE,NEXT of ONE,") == 0);
    val = *(char**)utarray_eltptr(strs, 1);
    assert(strcmp(val, "TWO,NEXT of FOUR,") == 0);
    utarray_free(strs);
    free(to_free[0]);
    free(to_free[1]);


    memset(key, 0, KEY_LEN);
    strcpy(key, "TWO");
    batab_remove(&tab, key);
    assert(batab_get(&tab, key) == NULL);

    memset(key, 0, KEY_LEN);
    strcpy(key, "ONE");
    assert(((F*) batab_get(&tab, key))->label == 1);

    memset(key, 0, KEY_LEN);
    strcmp(key, "quux");
    batab_remove(&tab, key); /* a key that does not exist */
    
    batab_destory(&tab);
}

int main() {
    test_with_statically_allocated_values();
    test_with_complex_dynamically_allocated_values();
}
