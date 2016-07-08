#include "../src/str_htab.h"
#include <assert.h>

void test_with_statically_allocated_values() {
    shtab_t tab;

    assert(shtab_init(&tab, NULL, "static-alloc") == 0);

    shtab_put(&tab, "foo", "bar", NULL);
    shtab_put(&tab, "bar", "baz", NULL);
    shtab_put(&tab, "quux", "corge", NULL);

    assert(strcmp(shtab_get(&tab, "foo"), "bar") == 0);
    assert(strcmp(shtab_get(&tab, "bar"), "baz") == 0);
    assert(strcmp(shtab_get(&tab, "quux"), "corge") == 0);

    char *old_val = NULL;
    shtab_put(&tab, "bar", "grault", (void **)&old_val);
    assert(strcmp(old_val, "baz") == 0);

    char buff[1024];
    buff[0]='\0';

    shtab_entry_t *e;
    shtab_foreach_do((&tab), e) {
        strcat(buff, e->key);
        strcat(buff, "=");
        strcat(buff, e->value);
        strcat(buff, ";");
    }

    assert(strcmp(buff, "foo=bar;bar=grault;quux=corge;") == 0);
    
    shtab_destory(&tab);
}

typedef struct foo {
    struct foo *next;
    char *value;
} F;

void foo_destructor(void *f) {
    F *c = (F*) f;
    while(c != NULL) {
        F *p = c;
        c = c->next;
        free(p->value);
        free(p);
    }
}

void test_with_complex_dynamically_allocated_values() {
    F *one = malloc(sizeof(F));
    one->value = strdup("ONE");
    one->next = malloc(sizeof(F));
    one->next->value = strdup("NEXT of ONE");
    one->next->next = NULL;

    F *two = malloc(sizeof(F));
    two->value = strdup("TWO");
    two->next = NULL;

    F *three = malloc(sizeof(F));
    three->value = strdup("THREE");
    three->next = NULL;
    three->next = malloc(sizeof(F));
    three->next->value = strdup("NEXT of THREE");
    three->next->next = NULL;

    F *four = malloc(sizeof(F));
    four->value = strdup("FOUR");
    four->next = NULL;
    four->next = malloc(sizeof(F));
    four->next->value = strdup("NEXT of FOUR");
    four->next->next = NULL;

    shtab_t tab;

    assert(shtab_init(&tab, foo_destructor, "dyn-alloc") == 0);

    shtab_put(&tab, "foo", one, NULL);
    shtab_put(&tab, "bar", two, NULL);

    assert(strcmp(((F*) shtab_get(&tab, "foo"))->value, "ONE") == 0);
    assert(strcmp(((F*) shtab_get(&tab, "bar"))->value, "TWO") == 0);

    char buff[1024];
    shtab_entry_t *e;
    
    buff[0]='\0';
    shtab_foreach_do((&tab), e) {
        strcat(buff, e->key);
        strcat(buff, "=");
        F *v = (F*) e->value;
        while(v != NULL) {
            strcat(buff, v->value);
            strcat(buff, ",");
            v = v->next;
        }
        strcat(buff, ";");
    }

    assert(strcmp(buff, "foo=ONE,NEXT of ONE,;bar=TWO,;") == 0);

    F *old_val = NULL;
    shtab_put(&tab, "bar", three, (void**)&old_val);
    assert(strcmp(((F*) shtab_get(&tab, "bar"))->value, "THREE") == 0);
    assert(strcmp(old_val->value, "TWO") == 0);

    foo_destructor(two);

    shtab_put(&tab, "bar", four, NULL);
    assert(strcmp(((F*) shtab_get(&tab, "bar"))->value, "FOUR") == 0);

    buff[0]='\0';
    shtab_foreach_do((&tab), e) {
        strcat(buff, e->key);
        strcat(buff, "=");
        F *v = (F*) e->value;
        while(v != NULL) {
            strcat(buff, v->value);
            strcat(buff, ",");
            v = v->next;
        }
        strcat(buff, ";");
    }
    assert(strcmp(buff, "foo=ONE,NEXT of ONE,;bar=FOUR,NEXT of FOUR,;") == 0);

    shtab_remove(&tab, "bar");

    assert(shtab_get(&tab, "bar") == NULL);
    assert(strcmp(((F*) shtab_get(&tab, "foo"))->value, "ONE") == 0);

    shtab_remove(&tab, "quux"); /* a key that does not exist */
    
    shtab_destory(&tab);
}

int main() {
    test_with_statically_allocated_values();
    test_with_complex_dynamically_allocated_values();
}
