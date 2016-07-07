#!/bin/sh

exec valgrind --leak-check=full --error-exitcode=1 ./str_htab_test
