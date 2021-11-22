#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/utsname.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>

#ifndef seccomp
int seccomp(unsigned int op, unsigned int flags, void *args){
  errno = 0;
  return syscall(__NR_seccomp, op, flags, args);
}
#endif

#define SECCOMP_RET_KILL_PROCESS_NAME   "kill_process"
#define SECCOMP_RET_KILL_THREAD_NAME    "kill_thread"
#define SECCOMP_RET_TRAP_NAME           "trap"
#define SECCOMP_RET_ERRNO_NAME          "errno"
#define SECCOMP_RET_USER_NOTIF_NAME     "user_notif"
#define SECCOMP_RET_TRACE_NAME          "trace"
#define SECCOMP_RET_LOG_NAME            "log"
#define SECCOMP_RET_ALLOW_NAME          "allow"

#define SECCOMP_RET_KILL_PROCESS 0x80000000U /* kill the process */
#define SECCOMP_RET_KILL_THREAD  0x00000000U /* kill the thread */
#define SECCOMP_RET_KILL         SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_TRAP         0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO        0x00050000U /* returns an errno */
#define SECCOMP_RET_USER_NOTIF   0x7fc00000U /* notifies userspace */
#define SECCOMP_RET_TRACE        0x7ff00000U /* pass to a tracer or disallow */
#define SECCOMP_RET_LOG          0x7ffc0000U /* allow after logging */
#define SECCOMP_RET_ALLOW        0x7fff0000U /* allow */

int main () {

  char* actnames[] = {
      SECCOMP_RET_KILL_PROCESS_NAME,
      SECCOMP_RET_KILL_THREAD_NAME,
      SECCOMP_RET_TRAP_NAME,
      SECCOMP_RET_ERRNO_NAME,
      SECCOMP_RET_USER_NOTIF_NAME,
      SECCOMP_RET_TRACE_NAME,
      SECCOMP_RET_LOG_NAME,
      SECCOMP_RET_ALLOW_NAME
  };

  __u32 actions[] = {
      SECCOMP_RET_KILL_PROCESS,
      SECCOMP_RET_KILL_THREAD,
      SECCOMP_RET_TRAP,
      SECCOMP_RET_ERRNO,
      SECCOMP_RET_USER_NOTIF,
      SECCOMP_RET_TRACE,
      SECCOMP_RET_LOG,
      SECCOMP_RET_ALLOW
  };

  int i;
  long ret;
  size_t n = sizeof(actions)/sizeof(actions[0]);

  struct utsname uname_buff;

  if (uname(&uname_buff) == 0) {
    printf("OS version : %s\n", uname_buff.version);
  } else {
    perror("main");
  }

  for (i = 0; i < n; i++) {
    ret = seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &actions[i]);
    printf("Expected action \"%s\" (0x%X) : ", actnames[i], actions[i]);
    if(ret != 0) {
      printf("Unavailable. %d(%s)\n", errno, strerror(errno));
    } else {
      printf("Available. (%s)\n", strerror(errno));
    }
  }
}
