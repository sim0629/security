#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *cp = malloc(1);
    cp[0] = 'A';
    free(cp);
    return 0;
}
