#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/syscall.h>

#include <sys/ptrace.h>

#include <seccomp.h>

#include <errno.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>

static int on_trap(pid_t child) {
  unsigned long msg;
  ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg);
  fprintf(stderr, "%5d: message received, %d\n", child, (int)msg);
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
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    perror("ptrace(PTRACE_DETACH...");
  fprintf(stderr, "%5d: tracing start", pid);

  while (1) {
    child = waitpid(-1, &status, WUNTRACED | WCONTINUED);
    if (child == -1) {
      perror("waitpid");
      return 1;
    }

    if (WIFEXITED(status)) {
      fprintf(stderr, "%5d: exited, st:%d\n", child, WEXITSTATUS(status));
      break;
    } else if (WIFSIGNALED(status)) {
      fprintf(stderr, "%5d: signaled, sig:%d, core:%s\n", child,
              WTERMSIG(status), (WCOREDUMP(status)) ? "yes" : "no");
      break;
    } else if (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == SIGTRAP) {
        // trap
        result = on_trap(child);
        if (result) {
          fprintf(stderr, "%5d: hook failed.\n", child);
          return 1;
        }
      } else {
        // not trap
        fprintf(stderr, "%5d: stopped, sig:%d\n", child, WSTOPSIG(status));

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
  /* seccomp stuffs */
  sleep(2);

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
