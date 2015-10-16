#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <asm/ptrace-abi.h>

static pid_t tracee;

void suicide() {
    if(kill(tracee, SIGKILL) < 0) {
        perror("kill");
    }
    exit(1);
}

int wait_tracee() {
    int status;
    if(waitpid(tracee, &status, 0) < 0) {
        perror("waitpid");
        suicide();
    }
    if(WIFEXITED(status) || WIFSIGNALED(status)) {
        printf("tracee exited\n");
        return -1;
    }
    return 0;
}

void continue_tracee() {
    if(ptrace(PTRACE_SYSCALL, tracee, NULL, NULL) < 0) {
        perror("ptrace syscall");
        suicide();
    }
}

void get_regs(struct user_regs_struct *regs_p) {
    if(ptrace(PTRACE_GETREGS, tracee, NULL, regs_p) < 0) {
        perror("ptrace getregs");
        suicide();
    }
}

void print_syscall(struct user_regs_struct *regs_p) {
    printf("%llu\n", regs_p->orig_rax);
}

void monitor() {
    struct user_regs_struct regs;
    bool entry = false;

    if(wait_tracee() < 0) {
        return;
    }
    get_regs(&regs);
    print_syscall(&regs);

    while(true) {
        continue_tracee();
        if(wait_tracee() < 0) {
            break;
        }
        entry = !entry;

        if(entry) {
            get_regs(&regs);
            print_syscall(&regs);
        }
    }
}

int main(int argc, char *argv[]) {

    if((tracee = fork()) < 0) {
        perror("fork");
        return 1;
    }

    if(tracee == 0) {
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace traceme");
            return 1;
        }
        if(execvp(argv[1], argv + 1) < 0) {
            perror("execvp");
            return 0;
        }
    }else { // tracer
        monitor();
    }

    return 0;
}
