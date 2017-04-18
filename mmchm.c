#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/syscall.h>

#include <sys/ptrace.h>

#include <seccomp.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "sysnames.h"

#define MMCHM_PRTACE_EVENT(status) (((status >> 8) ^ SIGTRAP) >> 8)

static int on_trap(pid_t child) {
  unsigned long msg;
  struct user_regs_struct regs;
  void *data;

  if (ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg) != 0) {
    perror("ptrace(PTRACE_GETEVENTMSG...");
    return 2;
  }
  if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) {
    perror("ptrace(PTRACE_GETREGS...");
    return 2;
  }
  fprintf(stderr, "%5d: syscall is: %s(#%d), arg0: %p\n", child,
          sysnames[(int)regs.orig_rax], (int)regs.orig_rax, (void *)regs.rdi);
  /* data = (void *)ptrace(PTRACE_PEEKTEXT, child, (void *)regs.rdi, NULL); */
  /* fprintf(stderr, "%5d: %p\n", child, data); */

  fprintf(stderr, "%5d: custom message received, %d\n", child, (int)msg);

  return 0;
}

static int on_parent(pid_t pid) {
  pid_t child;
  int status, sig;
  int result;

  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    perror("ptrace(PTRACE_ATTACH...");

  waitpid(pid, &status, 0);

  if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)PTRACE_O_TRACESECCOMP) == -1)
    perror("ptrace(PTRACE_SETOPTIONS...");
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    perror("ptrace(PTRACE_CONT...");
  fprintf(stderr, "%5d: tracing start\n", pid);

  sleep(1);

  while (1) {
    child = waitpid(-1, &status, WUNTRACED | WCONTINUED);
    if (child == -1) {
      perror("waitpid");
      return 1;
    }

    if (WIFEXITED(status)) {
      fprintf(stderr, "%5d: exited, status:%d\n", child, WEXITSTATUS(status));
      break;
    } else if (WIFSIGNALED(status)) {
      fprintf(stderr, "%5d: signaled, sig:%d, core:%s\n", child,
              WTERMSIG(status), (WCOREDUMP(status)) ? "yes" : "no");
      break;
    } else if (WIFSTOPPED(status)) {
      fprintf(stderr, "%5d: got status: event = %04x, signal = %04x.\n", child,
              MMCHM_PRTACE_EVENT(status), WSTOPSIG(status));
      if (WSTOPSIG(status) == SIGTRAP &&
          MMCHM_PRTACE_EVENT(status) == PTRACE_EVENT_SECCOMP) {
        // trap seccomp event
        result = on_trap(child);
        if (result) {
          fprintf(stderr, "%5d: hook failed.\n", child);
          return 1;
        }
      } else {
        // not trap
        fprintf(stderr, "%5d: stopped, sig:%d skip\n", child, WSTOPSIG(status));

        sig = WSTOPSIG(status);
      }
    } else if (WIFCONTINUED(status)) {
      fprintf(stderr, "%5d: continued.\n", child);
    } else {
      fprintf(stderr, "%5d: illegal status %d.", child, status);
      return 1;
    }

    result = ptrace(PTRACE_CONT, pid, NULL, NULL);
    if (result == -1) {
      perror("ptrace(PTRACE_CONT, ...)");
      return 1;
    }
  }

  return 0;
}

int on_child(void) {
  scmp_filter_ctx ctx;

  sleep(1);

  ctx = seccomp_init(SCMP_ACT_ALLOW);
  /* if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(uname), 1, */
  /*                      SCMP_A0(SCMP_CMP_GE, 0)) != 0) { */
  if (seccomp_rule_add(ctx, SCMP_ACT_TRACE(2017), SCMP_SYS(uname), 0) != 0) {
    perror("seccomp_rule_add");
    return 1;
  }
  if (seccomp_load(ctx) != 0) {
    perror("seccomp_load");
    return 1;
  }

  execlp("uname", "uname", "-a", (char *)NULL);
  return 127;
}

int main(int argc, char **argv) {
  pid_t pid;
  int ret;

  pid = fork();
  if (pid) {
    fprintf(stderr, "%5d: child started\n", pid);

    ret = on_parent(pid);
  } else {
    ret = on_child();
  }

  return ret;
}
