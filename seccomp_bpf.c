#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>

void configure_seccomp() {
  struct sock_filter filter [] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };

  struct sock_fprog prog = {
       .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
       .filter = filter,
  };

  // Setting to enable NO_NEW_PRIVS
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  printf("Setting seccomp filter mode...\n");
  prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main() {
  int fd;
  pid_t pid;
  const char *val = "hello, again.\n";

  configure_seccomp();

  printf("Opening a file for reading...\n");
  fd = open("foo.txt", O_RDONLY);
  
  printf("Getting PID...\n"); 
  pid = getpid();

  printf("Done.");
}
