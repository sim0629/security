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
    bool bypass;
    unsigned long long number;
    int cond_idx;
    unsigned long long cond_val;
    int chg_idx;
    bool chg_ref;
    unsigned long long chg_val;
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

void bind_args(struct user_regs_struct *regs_p, unsigned long long *args_p[6]) {
    args_p[0] = &regs_p->rdi;
    args_p[1] = &regs_p->rsi;
    args_p[2] = &regs_p->rdx;
    args_p[3] = &regs_p->r10;
    args_p[4] = &regs_p->r8;
    args_p[5] = &regs_p->r9;
}

void print_syscall_entry(struct user_regs_struct *regs_p) {
    unsigned long long n = regs_p->orig_rax;
    unsigned long long *args_p[6];
    int i;

    bind_args(regs_p, args_p);

    printf("%s ( ", ents[n].name);
    if(ents[n].argc < 0) {
        for(i = 0; i < 6; i++) {
            printf("0x%Lx", *args_p[i]);
            if(i < 5) printf(", ");
            else printf(" )");
        }
        printf("?");
    }else {
        for(i = 0; i < ents[n].argc; i++) {
            printf("0x%Lx", *args_p[i]);
            if(i < ents[n].argc - 1) printf(", ");
            else printf(" )");
        }
    }
}

void print_syscall_exit(struct user_regs_struct *regs_p) {
    printf(" = 0x%Lx\n", regs_p->rax);
}

void interpose(struct user_regs_struct regs) {
    unsigned long long *args_p[6];

    if(my_pcy.bypass) return;

    bind_args(&regs, args_p);

    if(my_pcy.number != regs.orig_rax) return;

    if(my_pcy.cond_idx >= 0) {
        if(my_pcy.cond_idx >= 6) {
            fprintf(stderr, "Malformed policy.\n");
            suicide();
        }
        if(*args_p[my_pcy.cond_idx] != my_pcy.cond_val) return;
    }

    if(my_pcy.chg_ref) {
        if(ptrace(PTRACE_POKEDATA, tracee, *args_p[my_pcy.chg_idx], my_pcy.chg_val) < 0) {
            perror("ptrace pokedata");
            suicide();
        }
    }else {
        if(my_pcy.chg_idx < 0) {
            regs.orig_rax = my_pcy.chg_val;
        }else if(my_pcy.chg_idx >= 6) {
            fprintf(stderr, "Malformed policy.\n");
            suicide();
        }else {
            *args_p[my_pcy.chg_idx] = my_pcy.chg_val;
        }
        if(ptrace(PTRACE_SETREGS, tracee, NULL, &regs) < 0) {
            perror("ptrace setregs");
            suicide();
        }
    }

    printf(" => ");
    print_syscall_entry(&regs);
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
            interpose(regs_entry);
        }else {
            get_regs(&regs_exit);
            print_syscall_exit(&regs_exit);
        }
    }
}

void parse_pcy(const char *policy) {
    FILE *f = NULL;
    char line[256];
    char *line_p;

    f = fopen(policy, "r");
    if(f == NULL) {
        perror("fopen policy");
        return;
    }

    if(fgets(line, sizeof(line), f) == NULL)
        goto error;
    if(sscanf(line, "%llu", &my_pcy.number) < 1)
        goto error;

    if(fgets(line, sizeof(line), f) == NULL)
        goto error;
    if(line[0] == '*') {
        my_pcy.cond_idx = -1;
    }else {
        if(sscanf(line, "[%d] == %llu", &my_pcy.cond_idx, &my_pcy.cond_val) < 2)
            goto error;
    }

    if(fgets(line, sizeof(line), f) == NULL)
        goto error;
    if(line[0] == '*') {
        my_pcy.chg_ref = true;
        line_p = line + 1;
    }else {
        my_pcy.chg_ref = false;
        line_p = line;
    }
    if(sscanf(line_p, "[%d] = %llu", &my_pcy.chg_idx, &my_pcy.chg_val) < 2)
        goto error;

    fclose(f);

    my_pcy.bypass = false;
    return;

error:
    fprintf(stderr, "Fail to parse policy. Assume it empty.\n");
    if(f != NULL) {
        fclose(f);
        f = NULL;
    }
}

void usage(const char *exe) {
    fprintf(stderr, "usage: %s [-p <policy>] <tracee>\n", exe);
}

int main(int argc, char *argv[]) {
    const char *exe = argv[0];
    const char *policy = NULL;
    int offset = 1;

    if(argc < 2) {
        usage(exe);
        return 1;
    }
    if(strcmp(argv[1], "-p") == 0) {
        policy = argv[2];
        offset = 3;
        if(argc < 4) {
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
        my_pcy.bypass = true;
        if(policy != NULL)
            parse_pcy(policy);
        monitor();
    }

    return 0;
}
