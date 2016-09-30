#!/bin/sh

exec valgrind --leak-check=full --error-exitcode=1 ./compress_test
