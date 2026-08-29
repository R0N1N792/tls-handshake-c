#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <errno.h>
#include <signal.h>

#include "net.h"          /* brings in the platform's socket headers */
#include "crypto.h"
#include "byteorder.h"

#ifdef _WIN32
  #include <windows.h>    /* Sleep(); must follow the winsock2.h in net.h */
  #include <direct.h>     /* _chdir()/_getcwd() */
  #define chdir  _chdir
  #define getcwd _getcwd
#else
  #include <unistd.h>
#endif

#define ARTIFICIAL_SERVER_DELAY 0

//for multi-thread reading
typedef struct {
    socket_t active_socket;
    struct sockaddr_in cli_addr;
} thread_args_t;


//signals to interrupt server in the middle of syscall
static volatile sig_atomic_t g_stop = 0;

//the listener, published so the handler can wake up a blocking accept()
static socket_t g_passive_sock = INVALID_SOCK;

#ifdef _WIN32
static void on_signal(int sig){

    (void)sig;
    g_stop = 1;
    /* Windows raises SIGINT on its own thread and does not interrupt a
       blocking accept(), so closing the listener is what unblocks main() */
    const socket_t s = g_passive_sock;
    g_passive_sock = INVALID_SOCK;
    if (s != INVALID_SOCK) net_close_socket(s);
}

static void install_signal_handlers(void){

    /* no sigaction() on Windows */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
}

static void sleep_seconds(unsigned seconds) { Sleep(seconds * 1000u); }
#else
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void install_signal_handlers(void){

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static void sleep_seconds(unsigned seconds) { sleep(seconds); }
#endif


static int read_until(socket_t sock, char *buf, size_t maxlen, char delim){

    size_t i = 0;
    char c;
    while (i < maxlen - 1) {
        ssize_t r = tcp_read(sock, &c, 1);
        if (r <= 0) return -1;
        if (c == delim) break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return 0;
}

void* handle_connection(void* arguments);

int main(int argc, char* argv[])
{
    //set working directory
    const char *out_dir = (argc > 1) ? argv[1] : ".";
    if (chdir(out_dir) != 0) {
        fprintf(stderr, "Cannot enter '%s': %s\n", out_dir, strerror(errno));
        return EXIT_FAILURE;
    }
    char cwd[1024];
    if (getcwd(cwd, sizeof cwd)) printf("Saving incoming files to: %s\n", cwd);



    net_init();
    crypto_init();
    uint16_t port = DEFAULT_SERVER_PORT;
    socket_t passive_sock = tcp_server_init(DEFAULT_SERVER_IP, port);
    if (passive_sock == INVALID_SOCK) {
        fprintf(stderr, "Failed to init TCP server\n");
        return EXIT_FAILURE;
    }
    printf("Server listening on %s:%d\n", DEFAULT_SERVER_IP, port);

    g_passive_sock = passive_sock;
    install_signal_handlers();

    while (!g_stop) {
        thread_args_t *args = malloc(sizeof(thread_args_t));
        if (args == NULL) {
            fprintf(stderr, "out of memory\n");
            break;
        }

        args->active_socket = tcp_accept(passive_sock, &args->cli_addr);
        if (args->active_socket == INVALID_SOCK) {
            //Winsock does not use errno; read the code before free() can clobber it
            const int err_code = net_last_error();
            free(args);

            if (g_stop) break;

            if (err_code == NET_EINTR || err_code == NET_ECONNABORTED)
                continue;

            if (err_code == NET_EMFILE || err_code == NET_ENOBUFS) {
                fprintf(stderr, "accept: %s - backing off\n", net_error_str(err_code));
                sleep_seconds(1);
                continue;
                }

            fprintf(stderr, "accept failed: %s\n", net_error_str(err_code));
            break;
        }

        handle_connection(args);
    }

    printf("\nShutting down...\n");
    if (g_passive_sock != INVALID_SOCK) net_close_socket(g_passive_sock);
    g_passive_sock = INVALID_SOCK;
    net_cleanup();
    return EXIT_SUCCESS;
}

void* handle_connection(void* arguments) {

    thread_args_t* args = (thread_args_t*) arguments;
    socket_t active_sock = args ->active_socket;
    struct sockaddr_in cli_addr = args ->cli_addr;
    free(args);


    char cli_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(cli_addr.sin_addr), cli_ip, sizeof(cli_ip));
    printf("Connection from %s:%d\n", cli_ip, ntohs(cli_addr.sin_port));

    //handshake
    keypair_t* server_keypair = malloc(sizeof(keypair_t));
    if (server_keypair == NULL) {
        fprintf(stderr, "Failed to malloc keypair\n");
        net_close_socket(active_sock);
        return NULL;
    }

    unsigned char client_pk[PUBLIC_KEY_LEN];
    int err = generate_keypair(server_keypair);
    if (err < 0) {
        fprintf(stderr, "Failed to generate keypair\n");
        net_close_socket(active_sock);
        crypto_free_keypair(&server_keypair);
        return NULL;
    }
    int handshake_len = tcp_read(active_sock, client_pk, sizeof(client_pk));
    if (handshake_len != PUBLIC_KEY_LEN) {
        fprintf(stderr, "Handshake failed\n");
        net_close_socket(active_sock);
        crypto_free_keypair(&server_keypair);
        return NULL;
    }
    int handshake_sent = tcp_send(active_sock, server_keypair -> pk, PUBLIC_KEY_LEN);
    if (handshake_sent != PUBLIC_KEY_LEN) {
        fprintf(stderr, "Handshake failed\n");
        net_close_socket(active_sock);
        crypto_free_keypair(&server_keypair);
        return NULL;
    }
    session_keypair_t* shared= malloc(sizeof(session_keypair_t));
    if (shared == NULL) {
        fprintf(stderr, "Failed to malloc session_keypair\n");
        net_close_socket(active_sock);
        crypto_free_keypair(&server_keypair);
        return NULL;
    }
    err = derive_server_keys(shared, server_keypair, client_pk);
    if (err < 0) {
        fprintf(stderr, "Failed to derive server keys\n");
        net_close_socket(active_sock);
        crypto_free_keypair(&server_keypair);
        crypto_free_session(&shared);
        return NULL;
    }
    crypto_free_keypair(&server_keypair);
    printf("Handshake is done\n");



    // Read "FILE: <filename>\0"
    char header[300];
    if (read_until(active_sock, header, sizeof(header), '\0') < 0) {
        fprintf(stderr, "Failed to read header\n");
        net_close_socket(active_sock);
        crypto_free_session(&shared);
        return NULL;
    }
    if (strncmp(header, "FILE: ", 6) != 0) {
        fprintf(stderr, "Bad header: %s\n", header);
        net_close_socket(active_sock);
        crypto_free_session(&shared);
        return NULL;
    }
    const char *filename = header + 6;
    printf("Receiving file: %s\n", filename);

    // Read size (until '\n')
    char size_buf[64];
    if (read_until(active_sock, size_buf, sizeof(size_buf), '\n') < 0) {
        fprintf(stderr, "Failed to read size\n");
        net_close_socket(active_sock);
        crypto_free_session(&shared);
        return NULL;
    }
    size_t file_size = (size_t)atol(size_buf);
    printf("Expected size: %zu bytes\n", file_size);

    // Write to file
    const char *base = filename;
    for (const char *p = filename; *p != '\0'; ++p) {
        if (*p == '/' || *p == '\\' || *p == ':') base = p + 1;
    }
    if (base[0] == '\0' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
        fprintf(stderr, "Rejected filename: %s\n", filename);
        net_close_socket(active_sock);
        crypto_free_session(&shared);
        return NULL;
    }

    FILE *f = fopen(base, "wb");
    if (f == NULL) {
        fprintf(stderr, "Failed to open '%s' for writing: %s\n", base, strerror(errno));
        net_close_socket(active_sock);
        crypto_free_session(&shared);
        return NULL;
    }



    //decrypted message received
    unsigned char buf[BATCH_SIZE];
    unsigned long long buf_len;

    size_t total = 0;

    //cipher text received
    unsigned char cipher[BATCH_SIZE + AEAD_TAG_LEN];
    unsigned long long counter = 0;
    unsigned char nonce[NONCE_LEN];

    while (total < file_size) {
        size_t to_read = BATCH_SIZE + AEAD_TAG_LEN; // + Tag length for encrypted messages
        if (file_size - total < BATCH_SIZE)
            to_read = file_size - total + AEAD_TAG_LEN;

        ssize_t r = tcp_read(active_sock, cipher, to_read);
        if (r <= 0) {
            fprintf(stderr, "Connection lost at %zu/%zu bytes\n", total, file_size);
            fclose(f);
            net_close_socket(active_sock);
            crypto_free_session(&shared);
            return NULL;
        }

        //decryption
        make_nonce(nonce, counter++);
        err = decrypt_message(AEAD_CHACHA20POLY1305_IETF, buf, &buf_len,
            cipher, r, nonce, shared -> rx);
        if (err < 0) {
            break;
        }

        fwrite(buf, 1, (size_t)buf_len, f);
        total += (size_t)buf_len;

        sodium_memzero(buf, BATCH_SIZE);
    }
    sleep_seconds(ARTIFICIAL_SERVER_DELAY);
    printf("File '%s' saved (%zu/%zu bytes)\n", filename, total, file_size);
    fclose(f);

    //ack sender
    unsigned char ack_buf[8];
    put_u64_be(ack_buf, (uint64_t)total);
    if (tcp_send(active_sock, ack_buf, sizeof ack_buf) != (ssize_t)sizeof ack_buf) {
        fprintf(stderr, "Failed to send ack\n");
        net_close_socket(active_sock);
        crypto_free_session(&shared);
        return NULL;
    }

    printf("ACK %zu was successfully sent\n", total);
    net_close_socket(active_sock);
    crypto_free_session(&shared);
    return NULL;
}