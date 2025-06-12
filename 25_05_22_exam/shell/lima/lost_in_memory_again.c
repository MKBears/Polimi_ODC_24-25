#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <seccomp.h>


#define PAGE_SIZE 0x1000
#define SHELLCODE_LENGTH 0x200
#define INVALID_POINTER ((void *) -1)


const int allowed_syscalls[] = {
    SCMP_SYS(write),
    SCMP_SYS(exit),
    SCMP_SYS(exit_group)};


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


char* read_flag(char *flag_path) {
  int fd;

  fd = open(flag_path, O_RDONLY);
  if (fd < 0) {
    perror("Can't open flag file: ");
    exit(1);
  }
  // Using mmap to read the flag
  char *flag = (char *) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (flag == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }
  close(fd);

  return flag;
}


int main()
{
  char *lost_page;
  void (*shellcode)(void);
  unsigned char tmp_buf[SHELLCODE_LENGTH + 1] = {0};
  ssize_t shellcode_len;
  size_t flag_len;
  char *flag_path = getenv("FLAG_PATH");

  init();
  // Setting flag path
  if (flag_path == NULL)
      flag_path = "./flag";
  // Reading the flag at the beginning of the lost page
  lost_page = read_flag(flag_path);
  // Appending a 'xor rax, rax' to the lost page 
  flag_len = strlen(lost_page);
  lost_page[flag_len] = '\x48';
  lost_page[flag_len + 1] = '\x31';
  lost_page[flag_len + 2] = '\xC0';
  // Reading the shellcode
  puts("I forgot where I put my flag again!!! :(");
  puts("Can you help me recover it?");
  printf(" > ");
  shellcode_len = read(0, tmp_buf, SHELLCODE_LENGTH);
  if (shellcode_len <= 0) {
    perror("read");
    exit(1);
  }
  // Appending the shellcode to the lost page 
  memcpy(lost_page + flag_len + 3, tmp_buf, shellcode_len);
  // Changing the permissions of the lost page
  if (mprotect(lost_page, PAGE_SIZE, PROT_READ | PROT_EXEC) == -1) {
    perror("mprotect");
    exit(1);
  }
  // Setting up seccomp
  load_jail();
  // Executing the shellcode
  shellcode = (void (*)())lost_page + flag_len;
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
                "xor rbp, rbp\n"
                "xor rsp, rsp\n"
                "jmp rax\n"
                : 
                : "a"(shellcode)
               );
  return 0;
}