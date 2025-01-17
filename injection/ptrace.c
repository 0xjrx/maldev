#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/ptrace.h>   // For ptrace
#include <sys/types.h>    // For pid_t
#include <sys/wait.h>     // For waitpid and macros like WIFEXITED
#include <unistd.h>       // For getpid and sleep

int get_pid_by_name(const char *process_name){
  DIR *proc_dir = opendir("/proc");
  if(!proc_dir){
    perror("opendir failed");
    return -1;
  }

  struct dirent *entry;

  while ((entry = readdir(proc_dir))!=NULL){
  if(entry->d_type ==DT_DIR && atoi(entry->d_name)>0){
    char cmdline_path[256];
    snprintf(cmdline_path, sizeof(cmdline_path),"/proc/%s/cmdline", entry->d_name);
    
    FILE *cmdline_file = fopen(cmdline_path, "r");
    if(cmdline_file){
      char cmdline[256];
      if(fgets(cmdline, sizeof(cmdline), cmdline_file) != NULL){

        if(strstr(cmdline, process_name)!=NULL){
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

int main(){
  const char *process_name = "spotify";
  int status;
  int pid = get_pid_by_name(process_name);
  if(pid>0){
    printf("PID of %s: %d\n", process_name, pid);
  }
  else{
    printf("Process %s not found.\n", process_name);
  }
  ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  while (1) {
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid failed");
        break;
    }
    printf("Status: %d\n", status);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    if (WIFEXITED(status)) {
        printf("Spotify terminated\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        break;
    } else if (WIFSIGNALED(status)) {
        printf("Spotify killed by signal %d\n", WTERMSIG(status));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        break;
    }
  }
}
