#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <asm/ptrace-abi.h>

#include "sgm_syscallent.h"

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
        fprintf(stderr, "tracee exited\n");
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

void print_syscall_entry(struct user_regs_struct *regs_p) {
    unsigned long long n = regs_p->orig_rax;
    unsigned long long args[6] = {
        regs_p->rdi,
        regs_p->rsi,
        regs_p->rdx,
        regs_p->r10,
        regs_p->r8,
        regs_p->r9,
    };
    int i;

    printf("%s ( ", ents[n].name);
    if(ents[n].argc < 0) {
        for(i = 0; i < 6; i++) {
            printf("0x%Lx", args[i]);
            if(i < 5) printf(", ");
            else printf(" )");
        }
        printf("?");
    }else {
        for(i = 0; i < ents[n].argc; i++) {
            printf("0x%Lx", args[i]);
            if(i < ents[n].argc - 1) printf(", ");
            else printf(" )");
        }
    }
}

void print_syscall_exit(struct user_regs_struct *regs_p) {
    printf(" = 0x%Lx\n", regs_p->rax);
}

void monitor() {
    struct user_regs_struct regs_entry;
    struct user_regs_struct regs_exit;
    bool entry = false;

    if(wait_tracee() < 0) {
        return;
    }
    get_regs(&regs_entry);
    print_syscall_entry(&regs_entry);
    print_syscall_exit(&regs_entry);

    while(true) {
        continue_tracee();
        if(wait_tracee() < 0) {
            break;
        }
        entry = !entry;

        if(entry) {
            get_regs(&regs_entry);
            print_syscall_entry(&regs_entry);
        }else {
            get_regs(&regs_exit);
            print_syscall_exit(&regs_exit);
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
