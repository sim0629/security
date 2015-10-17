#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <asm/ptrace-abi.h>

#include "sgm_syscallent.h"

static pid_t tracee;

static struct pcy {
    bool kill;
} my_pcy;

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
        }
        printf(" )?");
    }else {
        for(i = 0; i < ents[n].argc; i++) {
            printf("0x%Lx", args[i]);
            if(i < ents[n].argc - 1) printf(", ");
        }
        printf(" )");
    }
}

void print_syscall_exit(struct user_regs_struct *regs_p) {
    printf(" = 0x%Lx\n", regs_p->rax);
}

void print_encounter(const char *type) {
    printf(" => Encountered a %s syscall", type);
}

void sandbox(struct user_regs_struct *regs_p) {
    unsigned long long n = regs_p->orig_rax;

    switch(n) {
    case SYS_open:
    case SYS_creat:
    case SYS_openat:
        print_encounter("filesystem");
        if(my_pcy.kill) suicide();
        break;

    case SYS_socket:
    case SYS_socketpair:
        print_encounter("network");
        if(my_pcy.kill) suicide();
        break;

    case SYS_pipe:
    case SYS_pipe2:
    case SYS_shmget:
    case SYS_msgget:
    case SYS_mq_open:
        print_encounter("IPC");
        if(my_pcy.kill) suicide();
        break;

    case SYS_mmap:
        print_encounter("memory mapping");
        if(my_pcy.kill) suicide();
        break;

    default:
        break;
    }
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
            sandbox(&regs_entry);
        }else {
            get_regs(&regs_exit);
            print_syscall_exit(&regs_exit);
        }
    }
}

void usage(const char *exe) {
    fprintf(stderr, "usage: %s [-k] <tracee>\n", exe);
}

int main(int argc, char *argv[]) {
    const char *exe = argv[0];
    int offset = 1;

    if(argc < 2) {
        usage(exe);
        return 1;
    }
    if(strcmp(argv[1], "-k") == 0) {
        my_pcy.kill = true;
        offset = 2;
        if(argc < 3) {
            usage(exe);
            return 1;
        }
    }

    if((tracee = fork()) < 0) {
        perror("fork");
        return 1;
    }

    if(tracee == 0) {
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace traceme");
            return 1;
        }
        if(execvp(argv[offset], argv + offset) < 0) {
            perror("execvp");
            return 0;
        }
    }else { // tracer
        monitor();
    }

    return 0;
}
