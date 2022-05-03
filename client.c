#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef WINDOWS
  #define WINVER WindowsXP
  #include <w32api.h>
  #include <winsock2.h>
  //#include <windows.h>
  #include <ws2tcpip.h>
  #define SOCKET_ERRNO WSAGetLastError()
#else
  #include <errno.h>
  #define SOCKET_ERRNO errno
  #include <sys/types.h> // recommended for socket, bind, recvfrom, getaddrinfo
  #include <sys/socket.h> // required for socket, bind, recvfrom, inet_ntoa, getaddrinfo
  #include <arpa/inet.h> // required for inet_ntoa
  #include <netinet/in.h> // required according to "man 7 ip" for the IPv4 protocol implementation, and for inet_ntoa
  #include <netinet/ip.h> // required according to "man 7 ip" for the IPv4 protocol implementation
  #include <termios.h>
  #include <unistd.h> // required for close
  #include <netdb.h> // required for getaddrinfo
#endif

#include "sha1.c"

#define PORT "730"

//--prototypes-- this section will be automatically rewritten

static void _error_ (char *file, int line, char *message, int number);
static void _abort_ (char *file, int line, char *message);
static char *get_input (int noecho);
int main (int argc, char **argv);

//--page-split-- _error_

#define error(message, error) _error_(__FILE__, __LINE__, message, error)
static void _error_ (char *file, int line, char *message, int number) {
  #ifdef WINDOWS
  char *text = NULL;
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, number, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &text, 0, NULL);
  if (!text) {
    text = malloc(4096);
    sprintf(text, "error %d", number);
  };
  #else
  char *error = strerror(number);
  #endif
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
  #ifdef WINDOWS

  HANDLE hStdin;
  DWORD mode = 0;
  if (noecho) {
    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
  };

  // read a line
  size_t size = 4096;
  char *buffer = malloc(size);

  char *p = fgets(buffer, size, stdin);
  if (!p) error("fgets()", errno);
  int length = strlen(buffer);
  if (length == size - 1) printf("Your password may be too long, but we'll see what happens.\n");

  if (noecho) {
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
  };

  // remove the newline
  if (length && buffer[length - 1] == '\n') buffer[length - 1] = 0;

  return buffer;

  #else

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

  #endif
};

//--page-split-- main

int main (int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "Please supply a server name.\n");
    exit(1);
  };

  int return_value;

  #ifdef WINDOWS
  {
    WSADATA whatever;
    return_value = WSAStartup(0x0202, &whatever);
    if (return_value) error("WSAStartup()", SOCKET_ERRNO);
  };
  #endif

  // use getaddrinfo() to look up IP addresses of server

  printf("Looking up IP address of %s...\n", argv[1]);

  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  struct addrinfo *results = NULL;

  return_value = getaddrinfo(argv[1], PORT, &hints, &results);

  if (return_value != 0) {
    if (return_value == EAI_NONAME) {
      error("unable to find address", SOCKET_ERRNO);
    } else {
      error("getaddrinfo()", SOCKET_ERRNO);
    };
  };

  // count how many results we got

  int count = 0;
  for (struct addrinfo *p = results; p != NULL; p = p->ai_next) count++;
  printf("...getaddrinfo() returned %d result%s.\n", count, count == 1 ? "" : "s");

  // prompt user for the password

  printf("Password: ");
  char *password = get_input(1);

  if (!strlen(password)) abort("Error: Password is empty.\n");

  // connect to all returned IP addresses and authenticate with the server

  struct addrinfo *result = results;
  for (int index = 1; result != NULL; result = result->ai_next) {

    // tell the user what we're doing
    {
      int length = 4096;
      char *host = malloc(length);
      char *serv = malloc(length);
      return_value = getnameinfo(result->ai_addr, result->ai_addrlen, host, length, serv, length, NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV);
      if (return_value) {
        printf("Connecting to server...");
      } else {
        printf("Connecting to %s via UDP port %s...\n", host, serv);
      };
      free(host);
      free(serv);
    };

    // create socket
    int socket_descriptor = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (socket_descriptor < 0) error("socket()", SOCKET_ERRNO);

    // create buffer

    int passlen = strlen(password);
    char *buffer = malloc(40 + passlen + 1);

    // send request for challenge

    return_value = sendto(socket_descriptor, buffer, 20, 0, result->ai_addr, result->ai_addrlen);
    if (return_value < 0) error("sendto()", SOCKET_ERRNO);

    // prepare buffer

    strcpy(buffer + 40, password);
    memset(password, 0, passlen);
    free(password);

    // receive challenge

    return_value = recvfrom(socket_descriptor, buffer, 40, 0, NULL, 0);
    if (return_value < 0) error("recvfrom()", SOCKET_ERRNO);

    // calculate response

    sha1(buffer + 20, buffer + 20, 20 + passlen);
    sha1(buffer, buffer, 40);
    memset(buffer + 20, 0, 20 + passlen);

    // send response to challenge

    return_value = sendto(socket_descriptor, buffer, 20, 0, result->ai_addr, result->ai_addrlen);
    if (return_value < 0) error("sendto()", SOCKET_ERRNO);

    // receive response

    return_value = recvfrom(socket_descriptor, buffer, 40, 0, NULL, 0);
    if (return_value < 0) error("recvfrom()", SOCKET_ERRNO);

    if (buffer[0]) {
      printf("Failure!\n");
    } else {
      printf("Success!\n");
    };

    free(buffer);

    #ifdef WINDOWS
    closesocket(socket_descriptor);
    #else
    close(socket_descriptor);
    #endif

  };

  freeaddrinfo(results);

  return 0;

};
