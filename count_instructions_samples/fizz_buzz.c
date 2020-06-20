#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc <= 1) {
        printf("usage: fizz_buzz target_number");
        exit(1);
    }
    int target = atoi(argv[1]);
    if (target < 1) {
        printf("usage: fizz_buzz target_number");
        exit(1);
    }

    for (int i = 1; i < target + 1; ++i) {
        char buf[16] = { 0 };
        if ((i % 3) == 0) {
            strcat(buf, "Fizz");
        }
        if ((i % 5) == 0) {
            strcat(buf, "Buzz");
        }

        if (*buf == '\x00') {
            printf("%d, ", i);
        } else {
            printf("%s, ", buf);
        }
    }
    printf("...\n");
}