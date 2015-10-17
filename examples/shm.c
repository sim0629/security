#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void) {
    int fd = shm_open("/sgm", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    close(fd);
    return 0;
}
