#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int i, n, t1 = 0, t2 = 1, nextTerm;
    if (argc <= 1)
        exit(1);
    n = atoi(argv[1]);
    printf("Fibonacci Series for %d terms:\n", n);

    for (i = 1; i <= n; ++i) {
        printf("%d, ", t1);
        nextTerm = t1 + t2;
        t1 = t2;
        t2 = nextTerm;
    }

    return 0;
}
