#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "net.h"

#ifdef _WIN32
  #include <windows.h>
#endif

#include <errno.h>


#ifdef _WIN32
  #define NET_IOLEN(n) ((int)(n))
static size_t io_chunk(size_t remaining) {
    return remaining > (size_t)INT_MAX ? (size_t)INT_MAX : remaining;
}
#else
  #define NET_IOLEN(n) (n)
static size_t io_chunk(size_t remaining) { return remaining; }
#endif


int net_init(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else
    return 0;
#endif
}

void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

void net_close_socket(socket_t sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

int net_last_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

const char* net_error_str(int err) {
#ifdef _WIN32
    static char buf[256];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, (DWORD)err,
                             MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                             buf, sizeof buf, NULL);
    if (n == 0) {
        snprintf(buf, sizeof buf, "socket error %d", err);
    } else {
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    }
    return buf;
#else
    return strerror(err);
#endif
}



ssize_t tcp_send(socket_t socket, const void* buf, size_t len){
    if (buf == NULL) {
        fprintf(stderr, "response is NULL\n");
        return NET_ERR;
    }

    const char *p = (const char*)buf;   /* Winsock takes char*, not void* */
    size_t sent = 0;
    while (sent < len) {
        const size_t chunk = io_chunk(len - sent);
        ssize_t n = send(socket, p + sent, NET_IOLEN(chunk), 0);
        if (n < 0) {
            if (net_last_error() == NET_EINTR) continue;
            return NET_ERR;
        }
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}


ssize_t tcp_read(socket_t socket, void* buf, size_t len){
    if (buf == NULL) {
        fprintf(stderr, "buf is NULL\n");
        return NET_ERR;
    }

    char *p = (char*)buf;

    size_t received = 0;
    while (received < len) {
        const size_t chunk = io_chunk(len - received);
        ssize_t n = recv(socket, p + received, NET_IOLEN(chunk), 0);
        if (n < 0) {
            if (net_last_error() == NET_EINTR) continue;
            return NET_ERR;
        }
        if (n == 0) break;
        received += (size_t)n;
    }
    return (ssize_t)received;
}

socket_t get_tcp_socket(void){
    return socket(AF_INET, SOCK_STREAM, 0);
}

int get_server_addr(const char* ip, uint16_t port,
                    struct sockaddr_in* p_server_addr){

    if (ip == NULL) {
        fprintf(stderr, "ip is NULL\n");
        return NET_ERR;
    }
    if (p_server_addr == NULL) {
        fprintf(stderr, "p_server_addr is NULL\n");
        return NET_ERR;
    }
    *p_server_addr = (struct sockaddr_in){ 0 };

    p_server_addr->sin_family = AF_INET;
    p_server_addr->sin_port   = htons(port);

    if (inet_pton(AF_INET, ip, &p_server_addr->sin_addr) <= 0) {
        return NET_ERR;
    }

    return NET_OK;
}

int bind_server(socket_t socket, const char* ip, uint16_t port){

    if(ip == NULL) {
        fprintf(stderr, "ip is NULL\n");
        return NET_ERR;
    }

    struct sockaddr_in server_addr;
    int err = get_server_addr(ip, port, &server_addr);
    if (err != NET_OK) return err;
    if ( bind(socket, (struct sockaddr*)&server_addr, (socklen_t)sizeof(server_addr)) < 0) return NET_ERR;
    return NET_OK;
}

socket_t tcp_server_init(const char* ip, uint16_t port){

    if (ip == NULL) {
        fprintf(stderr, "ip is NULL\n");
        return INVALID_SOCK;
    }

    // Create a socket
    const socket_t fd = get_tcp_socket();
    if (fd == INVALID_SOCK) {
        fprintf(stderr, "Error opening TCP socket: %s\n", net_error_str(net_last_error()));
        return INVALID_SOCK;
    }

#ifndef _WIN32
    const int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        fprintf(stderr, "setsockopt(SO_REUSEADDR): %s\n", net_error_str(net_last_error()));
        net_close_socket(fd);
        return INVALID_SOCK;
    }
#endif

    if (bind_server(fd, ip, port) != NET_OK) {
        fprintf(stderr, "Error binding TCP socket: %s\n", net_error_str(net_last_error()));
        net_close_socket(fd);
        return INVALID_SOCK;
    }

    if (listen(fd, MAX_BACKLOG) != NET_OK) {
        fprintf(stderr, "Error listening TCP socket: %s\n", net_error_str(net_last_error()));
        net_close_socket(fd);
        return INVALID_SOCK;
    }

    return fd;
}

socket_t tcp_accept(socket_t passive_socket,struct sockaddr_in* cli_addr)
{
    socklen_t addrlen = sizeof(struct sockaddr_in);

    return accept(passive_socket,
                  (struct sockaddr*)cli_addr,
                  cli_addr == NULL ? NULL : &addrlen);
}