#include <stdio.h>

int main(void) {
    FILE *f = fopen("/tmp/test", "w");
    fclose(f);
    return 0;
}
