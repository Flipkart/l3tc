#!/bin/sh

exec valgrind --leak-check=full --error-exitcode=1 ./byte_array_htab_test
