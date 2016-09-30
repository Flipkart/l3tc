#include "../src/debug.h"
#include "../src/log.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void test_with_big_array() {
    char buff[40];
    char arr[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    print_byte_array(arr, sizeof(arr), buff, sizeof(buff));
    char print_buf[1024];
    sprintf(print_buf, "%s", buff);
    printf("BUFF: %s\n", print_buf);
    assert(strcmp(print_buf, "[00 01 02 03 04 05 .. 0a 0b 0c 0d 0e 0f]") == 0);
}

static void test_with_small_array() {
    char buff[40];
    char arr[] = {0x0, 0x1, 0x2};
    print_byte_array(arr, sizeof(arr), buff, sizeof(buff));
    char print_buf[1024];
    sprintf(print_buf, "%s", buff);
    printf("BUFF: %s\n", print_buf);
    assert(strcmp(print_buf, "[00 01 02]") == 0);
}

static void test_with_exactly_same_size_array() {
    char buff[40];
    char arr[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9 };
    print_byte_array(arr, sizeof(arr), buff, sizeof(buff));
    char print_buf[1024];
    sprintf(print_buf, "%s", buff);
    printf("BUFF: %s\n", print_buf);
    assert(strcmp(print_buf, "[00 01 02 03 04 05 06 07 08 09]") == 0);
}

int main() {
    test_with_small_array();
    test_with_big_array();
    test_with_exactly_same_size_array();

    char *expectations[] = {
        "[]",
        "[00]",
        "[00 01]",
        "[00 01 02]",
        "[00 01 02 03]",
        "[00 01 02 03 04]",
        "[00 01 .. 04 05]",
        "[00 01 .. 05 06]",
    };

    char buff[17];
    for (int i = 0; i < 8; i++) {
        char *arr = malloc(i);
        size_t sz = i;
        for (int j = 0; j < sz; j++) {
            arr[j] = j;
        }
        print_byte_array(arr, sz, buff, sizeof(buff));
        char print_buf[32];
        sprintf(print_buf, "'%s' (len: %zd)", buff, strlen(buff));
        printf("VISUAL CHECK BUFF(%d): %s\n", i, print_buf);
        assert(strcmp(expectations[i], buff) == 0);
        free(arr);
    }
}
