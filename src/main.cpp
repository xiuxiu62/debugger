#include "core/logger.h"
#include "core/types.h"
#include "memory_region.hpp"
#include "symbol.hpp"

#include <cstdio>
#include <cstring>
#include <sys/personality.h>
#include <sys/procfs.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

struct DebugCommand {
    const char *name;
    const char *description;
    void (*handler)(pid_t pid, char *args);
};

void handle_continue(pid_t pid, char *args);
void handle_break(pid_t pid, char *args);
void handle_registers(pid_t pid, char *args);
void handle_help(pid_t pid, char *args);
void handle_exit(pid_t pid, char *args);

static DebugCommand commands[] = {
    {"continue", "Continue execution", handle_continue},  {"break", "Set breakpoint at address (in hex)", handle_break},
    {"registers", "Print registers", handle_registers},   {"maps", "Show memory maps", handle_maps},
    {"symbols", "Show function symbols", handle_symbols}, {"help", "Show this help message", handle_help},
    {"exit", "Exit the debugger", handle_exit},
};

static std::string program_path;
static bool should_exit = false;

void print_registers(pid_t pid) {
    user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        error("ptrace registers");
        return;
    }

    printf("Register dump:\n");
    printf("rax: 0x%llx\n", regs.rax);
    printf("rbx: 0x%llx\n", regs.rbx);
    printf("rcx: 0x%llx\n", regs.rcx);
    printf("rdx: 0x%llx\n", regs.rdx);
    printf("rdi: 0x%llx\n", regs.rdi);
    printf("rsi: 0x%llx\n", regs.rsi);
    printf("rip: 0x%llx\n", regs.rip);
    printf("rsp: 0x%llx\n", regs.rsp);
    printf("rbp: 0x%llx\n", regs.rbp);
}

void debug_process(pid_t pid);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        return 1;
    }

    std::string program_path = argv[1];
    info("`%s`", program_path.c_str());
    printf("Starting debugger for: %s\n", program_path.c_str());

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        printf("Child process starting...\n");
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            error("ptrace traceme");
            return 1;
        }

        // Disable ASLR for more predictable debugging
        personality(ADDR_NO_RANDOMIZE);

        printf("Child executing program: %s\n", program_path.c_str());
        if (execvp(program_path.c_str(), argv + 1) == -1) {
            perror("execvp failed");
            return 1;
        }
    }

    if (pid < 0) {
        error("fork");
        return 1;
    }

    // Parent process (debugger)
    printf("Parent waiting for child pid: %d\n", pid);
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        error("waitpid");
        return 1;
    }

    // Set options but don't continue yet
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL) == -1) {
        error("ptrace setoptions");
        return 1;
    }

    printf("Debugger started. Type 'help' for available commands.\n");
    debug_process(pid);

    return 0;
}

void handle_continue(pid_t pid, char *args) {
    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
        error("ptrace continue");
        return;
    }

    // Wait for the process to stop
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        error("waitpid");
        return;
    }

    // Check if we hit a breakpoint (SIGTRAP)
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        printf("Breakpoint hit!\n");
        print_registers(pid);
    } else if (WIFEXITED(status)) {
        printf("Program exited with status %d\n", WEXITSTATUS(status));
        should_exit = true;
    }
}

void handle_break(pid_t pid, char *args) {
    if (!args) {
        printf("Usage: break <address|symbol>\n");
        return;
    }

    usize addr;

    // Only try hex parsing if starts with 0x
    if (strncmp(args, "0x", 2) == 0) {
        if (sscanf(args, "%lx", &addr) != 1) {
            printf("Invalid hex address: %s\n", args);
            return;
        }
    }
    // Otherwise treat as symbol
    else {
        bool found = false;
        addr = get_symbol_address(program_path, args, found);
        info("%b", found);
        if (!found) {
            printf("Could not find symbol: %s\n", args);
            return;
        }
    }

    if (!address_is_valid(pid, addr)) {
        printf("Invalid address 0x%lx\n", addr);
        return;
    }

    // Read the current instruction
    i32 data = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
    if (data == -1) {
        error("ptrace peek");
        return;
    }

    // Replace with int3 instruction (0xCC)
    u32 data_with_int3 = (data & ~0xFF) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, addr, data_with_int3) == -1) {
        error("ptrace poke");
        return;
    }

    printf("Breakpoint set at 0x%lx\n", addr);
}

void handle_registers(pid_t pid, char *args) {
    print_registers(pid);
}

void handle_help(pid_t pid, char *args) {
    printf("Available commands:\n");
    for (const DebugCommand &command : commands) {
        printf("%s - %s\n", command.name, command.description);
    }
}

void handle_exit(pid_t pid, char *args) {
    should_exit = true;
}

void debug_process(pid_t pid) {
    char cmd[256];
    char *args;

    load_memory_regions(pid);
    load_symbols(program_path);

    while (true) {
        if (should_exit) {
            break;
        }

        printf("dbg> ");
        if (fgets(cmd, sizeof(cmd), stdin) == nullptr) {
            break;
        }

        // Remove training newline
        cmd[strcspn(cmd, "\n")] = 0;

        // Split command and arguments
        args = strchr(cmd, ' ');
        if (args) {
            *args = '\0';
            args++;
        }

        // Find and execute command
        bool found = false;
        for (const DebugCommand &command : commands) {
            if (strcmp(cmd, command.name) == 0) {
                command.handler(pid, args);
                found = true;
                break;
            }
        }

        if (!found) {
            printf("Unknown command. Type 'help' for available commands.\n");
        }
    }
}
