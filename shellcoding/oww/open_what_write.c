#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

const int allowed_syscalls[] = {
    SCMP_SYS(open),
    SCMP_SYS(write),
    SCMP_SYS(close),
    SCMP_SYS(exit),
    SCMP_SYS(exit_group),
    SCMP_SYS(mmap),
    SCMP_SYS(mprotect),
    SCMP_SYS(munmap),
    SCMP_SYS(nanosleep)};

void init() 
{
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void load_jail() {
  scmp_filter_ctx ctx;
  int i;

  ctx = seccomp_init(SCMP_ACT_KILL);
  if (ctx == NULL) {
    fprintf(stderr, "seccomp_init failed\n");
    exit(1);
  }
  for (i = 0; i < sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]); i++) {
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed_syscalls[i], 0) < 0) {
      fprintf(stderr, "seccomp_rule_add failed with syscall %d\n", allowed_syscalls[i]);
      exit(1);
    }
  }
  if (seccomp_load(ctx) < 0) {
    fprintf(stderr, "seccomp_load failed\n");
    exit(1);
  }
}

int main(int argc, char const *argv[])
{
  unsigned char *code;
  void (*shellcode)(void); 

  init();
  printf("Enter your shellcode: ");
  code = (unsigned char *) mmap(NULL, 1024, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  read(0, code, 1024);
  load_jail();
  shellcode = (void (*)())code;
  asm volatile("xor rbx, rbx\n"
                "xor rcx, rcx\n"
                "xor rdx, rdx\n"
                "xor rsi, rsi\n"
                "xor rdi, rdi\n"
                "xor r8, r8\n"
                "xor r9, r9\n"
                "xor r10, r10\n"
                "xor r11, r11\n"
                "xor r12, r12\n"
                "xor r13, r13\n"
                "xor r14, r14\n"
                "xor r15, r15\n"
                "call rax\n"
                : 
                : "a"(shellcode)
               );
  return 0;
}