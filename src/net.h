#pragma once

/* --- platform block: must precede everything that touches sockets --- */
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0601
  #endif
  #include <winsock2.h>      /* must come before <windows.h> */
  #include <ws2tcpip.h>
  #include <basetsd.h>
  typedef SOCKET socket_t;
#define INVALID_SOCK INVALID_SOCKET
#ifndef _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#define _SSIZE_T_DEFINED
#endif
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
typedef int socket_t;
#define INVALID_SOCK (-1)
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>


#define DEFAULT_SERVER_PORT 8000
#define DEFAULT_SERVER_IP "127.0.0.1"


#define MAX_BACKLOG 15

#define BATCH_SIZE 1024


#define NET_OK    0
#define NET_ERR (-1)


/* --- socket error codes: Winsock keeps its own set and never touches errno --- */
#ifdef _WIN32
  #define NET_EINTR        WSAEINTR
  #define NET_ECONNABORTED WSAECONNABORTED
  #define NET_EMFILE       WSAEMFILE
  #define NET_ENOBUFS      WSAENOBUFS
#else
  #define NET_EINTR        EINTR
  #define NET_ECONNABORTED ECONNABORTED
  #define NET_EMFILE       EMFILE
  #define NET_ENOBUFS      ENOBUFS
#endif


/**
 * @brief Sends exactly len bytes over a TCP socket, retrying until the
 *        full buffer is transmitted
 *
 * A single send() call is not guaranteed to transmit the whole buffer;
 * this loops until len bytes are sent. EINTR is retried transparently
 *
 * @param socket connected TCP socket descriptor
 * @param buf    buffer to send; must not be NULL
 * @param len    number of bytes to send
 * @return len on success (all bytes sent); -1 on error (NULL buf, or
 *         send() failure other than EINTR)
 */
ssize_t tcp_send(socket_t socket, const void* buf, size_t len);

/**
 * @brief Reads exactly len bytes from a TCP socket, retrying until the
 *        full amount is received or the peer closes the connection
 *
 * A single recv() call is not guaranteed to fill the whole buffer;
 * this loops until len bytes are read or EOF. EINTR is retried
 * transparently.
 *
 * @param socket connected TCP socket descriptor
 * @param buf    buffer to fill; must not be NULL
 * @param len    number of bytes to read
 * @return number of bytes actually read. Equals len on full success;
 *         less than len if the peer closed the connection before len
 *         bytes arrived (EOF, not an error). -1 on error (NULL buf, or
 *         a recv() failure other than EINTR). Callers must compare the
 *         result against len, not just against 0, to detect a short read.
 */
ssize_t tcp_read(socket_t socket, void* buf, size_t len);

/**
 *
 * @return socket of domain AF_INET(TCP) and type SOCK_STREAM if success, or INVALID_SOCK otherwise
 */
socket_t get_tcp_socket(void);


/**
 * @brief from given args formats the address of type sockaddr_in*
 *
 * @param ip must not be NULL
 * @param port
 * @param p_server_addr to save the in
 * @return 0 if success, -1 otherwise
 */
int get_server_addr(const char* ip, uint16_t port,
                    struct sockaddr_in* p_server_addr);


/**
 * @brief assigns name to the socket(with given ip and port)
 *
 * @param socket to assign name to it
 * @param ip must not be NULL
 * @param port
 * @return 0 if success, -1 otherwise
 */
int bind_server(socket_t socket, const char* ip, uint16_t port);


/**
 * @brief creates a passive socket(and binds it to ip and port passed in args) and sets it to listen
 *
 * @param ip IP address to associate the socket with; must not be NULL
 * @param port port to associate the socket with
 * @return socket number if success, INVALID_SOCK otherwise
 */
socket_t tcp_server_init(const char* ip, uint16_t port);


/**
 * @brief establishes connection between server and client
 *
 * @param passive_socket passive socket of server
 * @param cli_addr address of client to connect
 * @return the connected socket if success, INVALID_SOCK otherwise
 */
socket_t tcp_accept(socket_t passive_socket,struct sockaddr_in* cli_addr);



/**
 * @brief WSAStartup on Windows, no-op on POSIX
 *
 * @return 0 if success, or one of error codes
 */
int net_init(void);

/**
 * @brief WSACleanup on Windows, no-op on POSIX
 *
 */
void net_cleanup(void);

/**
 *@brief a closesocket() on Windows/ close() depending on POSIX
 *
 * @param sock socket to be cleaned
 */
void net_close_socket(socket_t sock);

/**
 * @brief error code left by the last failed socket call
 *
 * Winsock does not report through errno, so socket errors must be read with
 * WSAGetLastError() on Windows and errno everywhere else. Compare the result
 * against the NET_E* constants, never against the bare errno names.
 *
 * @return platform-specific error code
 */
int net_last_error(void);

/**
 * @brief human-readable text for a code returned by net_last_error()
 *
 * @param err code from net_last_error()
 * @return pointer to a static buffer, overwritten by the next call
 */
const char* net_error_str(int err);
