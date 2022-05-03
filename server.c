#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h> // recommended for socket, bind, recvfrom
#include <sys/socket.h> // required for socket, bind, recvfrom, inet_ntoa
#include <arpa/inet.h> // required for inet_ntoa
#include <netinet/in.h> // required according to "man 7 ip" for the IPv4 protocol implementation, and for inet_ntoa
#include <netinet/ip.h> // required according to "man 7 ip" for the IPv4 protocol implementation
#include <unistd.h> // required for close
#include <sys/wait.h>

#include "sha1.c" // <-- more C code in here, to calculate SHA-1

#define PORT 730

// We'll be sending random salts to clients, and need to track which salt was
// sent to which client.  We'll store the salts in one of two arrays depending
// on which second the initial request arrives, and delete the arrays that are
// too old when a new request comes in.  With two structures, clients will have
// at least one second to respond before the data expires.

struct {
  struct in_addr address;
  char salt[20];
} *record_data[2] = {};
time_t record_time[2] = {};
int record_count[2] = {};

// This union avoids dodging type-checking by avoiding
// the need for a cast in the bind() call later.

typedef union {
  struct sockaddr sa;
  struct sockaddr_in sa_in;
} SOCKADDR_IN;

//--prototypes-- this section will be automatically rewritten

static void _error_ (char *file, int line, char *message, int number);
static void _abort_ (char *file, int line, char *message);
void whitelist (char *address);
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

//--page-split-- whitelist

void whitelist (char *address) {
  int pid = fork();
  if (pid) {
    waitpid(pid, NULL, 0);
  } else {
    char *argv[3];
    argv[0] = "/etc/bouncer/whitelist";
    argv[1] = address;
    argv[2] = NULL;
    extern char **environ;
    execve("/etc/bouncer/whitelist", argv, environ);
    error("execve('/etc/bouncer/whitelist')", errno);
    _Exit(0);
  };
};

//--page-split-- main

int main (int argc, char **argv) {

  int return_value;

  // all buffers are allocated with malloc()
  // so that address sanitizer can catch errors

  char *password_salt = malloc(20);
  char *password_hash = malloc(20);
  char *packet_buffer = malloc(40);

  // read the password salt and hash previously
  // created with the included 'passwd' program

  {
    FILE *password_file = fopen("/etc/bouncer/password", "rb");
    if (!password_file) error("fopen('/etc/bouncer/password')", errno);
    return_value = fread(password_salt, 1, 20, password_file);
    if (return_value < 0) error("fread('/etc/bouncer/password')", errno);
    if (return_value < 20) abort("short read from '/etc/bouncer/password'");
    return_value = fread(password_hash, 1, 20, password_file);
    if (return_value < 0) error("fread('/etc/bouncer/password')", errno);
    if (return_value < 20) abort("short read from '/etc/bouncer/password'");
    return_value = fclose(password_file);
    if (return_value < 0) error("fclose('/etc/bouncer/password')", errno);
  };

  // create a new socket, documented in "man 2 socket"

  int socket_descriptor = socket(PF_INET, SOCK_DGRAM, 0);
  if (socket_descriptor < 0) error("socket():", errno);

  {
    SOCKADDR_IN our_socket_address = {};

    // bind the socket to the port, documented in "man 7 ip"

    our_socket_address.sa_in.sin_family = AF_INET;
    our_socket_address.sa_in.sin_port = htons(PORT);
    our_socket_address.sa_in.sin_addr.s_addr = htons(INADDR_ANY);

    return_value = bind(socket_descriptor, &our_socket_address.sa, sizeof(our_socket_address));
    if (return_value < 0) error("bind():", errno);
  };

  #ifdef TEST
  // for testing we need to eventually exit so that
  // address sanitizer can report what it has found
  time_t start_time = time(NULL);
  #endif

  while (1) { // main loop

    // wait for a packet to be received

    SOCKADDR_IN remote_socket_address = {};
    socklen_t size = sizeof(remote_socket_address);
    return_value = recvfrom(socket_descriptor, packet_buffer, 40, 0, &remote_socket_address.sa, &size);
    if (return_value < 0) error("recvfrom()", errno);

    // all valid packets are 20 bytes, so if it was any other size, ignore it

    if (return_value != 20) continue;

    // for consistency we only want to call time() once

    time_t now = time(NULL);

    // delete any records that are over 1 second old

    for (int i = 0; i < 2; i++) {
      if (record_time[i] && record_time[i] < now - 1) {
        record_data[i] = realloc(record_data[i], 0);
        record_count[i] = 0;
        record_time[i] = 0;
      };
    };

    // if a record for this client exists, attempt to verify it

    int found_existing_record = 0;

    for (int i = 0; i < 2; i++) {
      if (!record_time[i]) continue;
      for (int j = 0; j < record_count[i]; j++) {
        if (0 == memcmp(&record_data[i][j].address, &remote_socket_address.sa_in.sin_addr, sizeof(struct in_addr))) {
          found_existing_record = 1;

          // calculate what answer the client should have sent us

          char *temp = malloc(40);
          memmove(temp, record_data[i][j].salt, 20);
          memmove(temp + 20, password_hash, 20);

          char *answer = malloc(20);
          sha1(answer, temp, 40);

          int correct = (0 == memcmp(packet_buffer, answer, 20));

          free(answer);
          free(temp);

          if (correct) {
            printf("Received correct response from %s\n", inet_ntoa(remote_socket_address.sa_in.sin_addr));
            memset(packet_buffer, 0, 20);
            whitelist(inet_ntoa(remote_socket_address.sa_in.sin_addr));
          } else {
            printf("Received incorrect response from %s\n", inet_ntoa(remote_socket_address.sa_in.sin_addr));
            memset(packet_buffer, -1, 20);
          };

          // let the client know if their response was accepted

          return_value = sendto(socket_descriptor, packet_buffer, 20, 0, &remote_socket_address.sa, sizeof(remote_socket_address));
          if (return_value < 0) error("sendto()", errno);

          // in either case, erase the record so that it cannot be reused

          memset(&record_data[i][j], 0, sizeof(record_data[i][j]));

        };
      };
    };

    if (!found_existing_record) {

      // create a new record for this host

      printf("Sending new challenge to %s\n", inet_ntoa(remote_socket_address.sa_in.sin_addr));

      int i = now & 1;
      record_time[i] = now;
      int j = record_count[i]++;
      record_data[i] = realloc(record_data[i], record_count[i] * sizeof(record_data[i][j]));
      memmove(&record_data[i][j].address, &remote_socket_address.sa_in.sin_addr, sizeof(struct in_addr));

      FILE *random = fopen("/dev/urandom", "rb");
      if (!random) error("fopen(/dev/urandom)", errno);
      int count = fread(record_data[i][j].salt, 1, 20, random);
      if (count < 0) error("fread('/dev/urandom')", errno);
      if (count < 20) abort("Failed to read 20 bytes from /dev/urandom\n");
      fclose(random);

      memmove(packet_buffer, record_data[i][j].salt, 20);
      memmove(packet_buffer + 20, password_salt, 20);

      return_value = sendto(socket_descriptor, packet_buffer, 40, 0, &remote_socket_address.sa, sizeof(remote_socket_address));
      if (return_value < 0) error("sendto()", errno);

    } else {

      #ifdef TEST
      // for testing we need to eventually exit so that
      // address sanitizer can report what it has found
      if (now - start_time > 60) break;
      #endif

    };

  };

  for (int i = 0; i < 2; i++) {
    record_data[i] = realloc(record_data[i], 0);
  };

  free(password_salt);
  free(password_hash);
  free(packet_buffer);

  close(socket_descriptor);

  return 0;

};
