#include <stdio.h>
#include <unistd.h>

int main(void) {
    pid_t p;
    printf("Let's fork!\n");
    p = fork();
    printf("pid: %d\n", p);
    return 0;
}
