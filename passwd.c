#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <termios.h>

#include <sys/socket.h> // required for inet_ntoa used in sha1.c
#include <arpa/inet.h>  // required for inet_ntoa used in sha1.c

#include "sha1.c"

//--prototypes-- this section will be automatically rewritten

static void _error_ (char *file, int line, char *message, int number);
static void _abort_ (char *file, int line, char *message);
static char *get_input (int noecho);
int main (int argc, char **argv);

//--page-split-- _error_

#define error(message, error) _error_(__FILE__, __LINE__, message, error)
static void _error_ (char *file, int line, char *message, int number) {
  fprintf(stderr, "%s:%d: %s: %s\n", file, line, message, strerror(number));
  exit(1);
};

//--page-split-- _abort_

#define abort(message) _abort_(__FILE__, __LINE__, message)
static void _abort_ (char *file, int line, char *message) {
  fprintf(stderr, "%s:%d: %s\n", file, line, message);
  exit(1);
};

//--page-split-- get_input

static char *get_input (int noecho) {

  struct termios old, new;

  if (noecho) {
    // turn off echoing
    if (tcgetattr(fileno(stdin), &old) != 0) error("tcgetattr(stdin)", errno);
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0) error("tcsetattr(stdin)", errno);
  };

  // read a line
  char *buffer = NULL;
  size_t size = 0;
  int length = getline(&buffer, &size, stdin);
  if (length < 0) error("getline()", errno);

  if (noecho) {
    // restore previous terminal settings
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &old) != 0) error("tcsetattr(stdin)", errno);
    printf("\n");
  };

  // remove the newline
  if (length && buffer[length - 1] == '\n') buffer[length - 1] = 0;

  return buffer;

};

//--page-split-- main

int main (int argc, char **argv) {

  if (argc > 1) {
    fprintf(stderr, "This program takes no arguments.\n");
    fprintf(stderr, "It will prompt you to enter the new password.\n");
    exit(1);
  };

  // prompt for password

  printf("This program will create a new password.\n");
  printf("To cancel, enter an empty password.\n");

  printf("New Password: ");
  char *password = get_input(1);

  if (!strlen(password)) {
    fprintf(stderr, "Error: Password is empty.\n");
    exit(1);
  };

  printf("Confirm Password: ");
  char *confirm = get_input(1);

  if (strcmp(password, confirm) != 0) {
    fprintf(stderr, "Error: Passwords do not match.\n");
    exit(1);
  };

  // create a random salt

  char *salt = malloc(20);
  char *hash = malloc(20);

  int passlen = strlen(password);
  char *buffer = malloc(20 + passlen + 1);

  FILE *random = fopen("/dev/urandom", "rb");
  if (!random) error("fopen(/dev/urandom)", errno);
  int count = fread(salt, 1, 20, random);
  if (count < 0) error("fread('/dev/urandom')", errno);
  if (count < 20) {
    fprintf(stderr, "Failed to read 20 bytes from /dev/urandom\n");
    exit(1);
  };
  fclose(random);

  // hash the password with the salt

  memmove(buffer, salt, 20);
  strcpy(buffer + 20, password);
  sha1(hash, buffer, 20 + passlen);

  // write the hash and salt to password file

  FILE *output = fopen("/etc/bouncer/password", "wb");
  if (!output) error("fopen('/etc/bouncer/password')", errno);
  count = 0;
  count += fwrite(salt, 1, 20, output);
  count += fwrite(hash, 1, 20, output);
  if (count < 40) {
    fprintf(stderr, "Failed to write 40 bytes to /etc/bouncer/password\n");
    exit(1);
  };
  fclose(output);

  free(salt);
  free(hash);
  free(buffer);
  free(password);
  free(confirm);

};
