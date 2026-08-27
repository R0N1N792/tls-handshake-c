#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include "net.h"

#include <errno.h>


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



ssize_t tcp_send(int socket, const void* buf, size_t len){
    if (buf == NULL) {
        fprintf(stderr, "response is NULL\n");
        return NET_ERR;
    }

    const unsigned char *p = (const unsigned char*)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(socket, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}


ssize_t tcp_read(int socket, void* buf, size_t len)
{
    if (buf == NULL) {
        fprintf(stderr, "buf is NULL\n");
        return NET_ERR;
    }

    unsigned char *p = (unsigned char*)buf;

    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(socket, p + received, len - received, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        received += (size_t)n;
    }
    return (ssize_t)received;
}

int get_tcp_socket(void)
{
    const int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) return NET_ERR;

    return fd;
}

int get_server_addr(const char* ip, uint16_t port,
                    struct sockaddr_in* p_server_addr)
{
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

int bind_server(int socket, const char* ip, uint16_t port)
{
    if(ip == NULL) {
        fprintf(stderr, "ip is NULL\n");
        return NET_ERR;
    }

    struct sockaddr_in server_addr;
    int err = get_server_addr(ip, port, &server_addr);
    if (err != NET_OK) return err;
    if ( bind(socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) return NET_ERR;
    return NET_OK;
}

int tcp_server_init(const char* ip, uint16_t port)
{
    if (ip == NULL) {
        fprintf(stderr, "ip is NULL\n");
        return NET_ERR;
    }

    // Create a socket
    const int fd = get_tcp_socket();
    if (fd < 0) {
        fprintf(stderr, "Error opening TCP socket");
        return NET_ERR;
    }


    const int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        fprintf(stderr, "setsockopt(SO_REUSEADDR): %s\n", strerror(errno));
        net_close_socket(fd);
        return NET_ERR;
    }

    if (bind_server(fd, ip, port) != NET_OK) {
        fprintf(stderr, "Error binding TCP socket\n");
        net_close_socket(fd);
        return NET_ERR;
    }

    if (listen(fd, MAX_BACKLOG) != NET_OK) {
        fprintf(stderr, "Error listening TCP socket\n");
        net_close_socket(fd);
        return NET_ERR;
    }

    return fd;
}

int tcp_accept(int passive_socket,struct sockaddr_in* cli_addr)
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    socklen_t dummy;

    return accept(passive_socket,
                  (struct sockaddr*)cli_addr,
                  cli_addr == NULL ? &dummy : &addrlen);
}