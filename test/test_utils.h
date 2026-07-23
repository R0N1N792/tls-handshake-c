#pragma once
#include <stdio.h>
#include <stdlib.h>






static int tests_run = 0, tests_passed = 0;

#define CHECK(condition, description) do {                             \
    tests_run++;                                                       \
    if (condition) {                                                   \
        tests_passed++;                                                \
        printf("  [OK]   %s\n", description);                          \
    }                                                                  \
    else {                                                             \
    printf("  [FAIL] %s  (%s:%d)\n", description, __FILE__, __LINE__); \
    }                                                                  \
} while (0)


#define TEST_SUMMARY() \
    printf("\n%d/%d tests passed\n", tests_passed, tests_run)