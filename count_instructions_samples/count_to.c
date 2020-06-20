#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main(int argc, char **argv) {
    if (argc <= 1) {
        exit(1);
    }

    uint64_t target = strtoull(argv[1], NULL, 10);
    // volatile so the compiler does not optimize away the loop
    volatile uint64_t counter = 0;
    while (counter < target) {
        ++counter;
    }
    return 0;
}