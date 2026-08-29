#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sodium.h>
#include <inttypes.h>


#include "net.h" 
#include "crypto.h"
#include "byteorder.h"

int main(int argc, char* argv[])
{

    net_init();
    crypto_init();

    char filename[256];
    if (argc > 1) {
        snprintf(filename, sizeof filename, "%s", argv[1]);
    } else {
        printf("Enter filename to send: ");
        if (!fgets(filename, sizeof filename, stdin)) return EXIT_FAILURE;
        filename[strcspn(filename, "\n")] = '\0';
    }

    // Check file exists and get size
    struct stat st;
    if (stat(filename, &st) < 0) {
        fprintf(stderr, "Failed to stat filename\n");
        return EXIT_FAILURE;
    }
    size_t file_size = (size_t)st.st_size;

    FILE *f = fopen(filename, "rb");
    if (f == NULL) {
        fprintf(stderr, "Failed to open %s\n", filename);
        return EXIT_FAILURE;
    }

    // Create socket and connect
    socket_t sock = get_tcp_socket();
    if (sock == INVALID_SOCK) {
        fprintf(stderr, "Failed to create TCP socket\n");
        fclose(f);
        return EXIT_FAILURE;
    }

    struct sockaddr_in srv_addr;
    uint16_t portServer = DEFAULT_SERVER_PORT;
    if (get_server_addr(DEFAULT_SERVER_IP, portServer, &srv_addr) != NET_OK) {
        fprintf(stderr, "Failed to get server address\n");
        net_close_socket(sock);
        fclose(f);
        return EXIT_FAILURE;
    }

    if (connect(sock, (struct sockaddr *)&srv_addr, (socklen_t)sizeof(srv_addr)) < 0) {
        fprintf(stderr, "Failed to connect to server\n");
        net_close_socket(sock);
        fclose(f);
        return EXIT_FAILURE;
    }

    printf("Connected to %s:%d\n", DEFAULT_SERVER_IP, portServer);

    //handshake
    keypair_t* client_keypair = malloc(sizeof(keypair_t));
    if (client_keypair == NULL) {
        fprintf(stderr, "Failed to allocate client_keypair\n");
        net_close_socket(sock);
        fclose(f);
        return EXIT_FAILURE;
    }

    unsigned char server_pk[PUBLIC_KEY_LEN];
    int err = generate_keypair(client_keypair);
    if (err < 0) {
        fprintf(stderr, "Failed to generate keypair\n");
        net_close_socket(sock);
        crypto_free_keypair(&client_keypair);
        fclose(f);
        return EXIT_FAILURE;
    }

    int handshake_sent = tcp_send(sock, client_keypair -> pk, PUBLIC_KEY_LEN);
    if (handshake_sent != PUBLIC_KEY_LEN) {
        fprintf(stderr, "Failed to send public key\n");
        net_close_socket(sock);
        crypto_free_keypair(&client_keypair);
        fclose(f);
        return EXIT_FAILURE;
    }
    int handshake_read = tcp_read(sock, server_pk, sizeof(server_pk));
    if (handshake_read != PUBLIC_KEY_LEN) {
        fprintf(stderr, "Failed to read public key\n");
        net_close_socket(sock);
        crypto_free_keypair(&client_keypair);
        fclose(f);
        return EXIT_FAILURE;
    }
    session_keypair_t* shared= malloc(sizeof(session_keypair_t));
    if (shared == NULL) {
        fprintf(stderr, "Failed to allocate shared\n");
        net_close_socket(sock);
        crypto_free_keypair(&client_keypair);
        fclose(f);
        return EXIT_FAILURE;
    }
    err = derive_client_keys(shared, client_keypair, server_pk);
    if (err < 0) {
        fprintf(stderr, "Failed to derive client_keypair\n");
        net_close_socket(sock);
        crypto_free_keypair(&client_keypair);
        crypto_free_session(&shared);
        fclose(f);
        return EXIT_FAILURE;
    }

    crypto_free_keypair(&client_keypair);
    printf("Handhsake is done\n");



    //Send "FILE: <filename>\0"
    char header[300];
    int header_len = snprintf(header, sizeof(header), "FILE: %s", filename) + 1;
    if (tcp_send(sock, header, (size_t)header_len) < 0) {
        fprintf(stderr, "Failed to send filename\n");
        net_close_socket(sock);
        crypto_free_session(&shared);
        fclose(f);
        return EXIT_FAILURE;
    }

    //Send file size + '\n'
    char size_buf[64];
    int size_len = snprintf(size_buf, sizeof(size_buf), "%zu\n", file_size);
    if (tcp_send(sock, size_buf, (size_t)size_len) < 0) {
        fprintf(stderr, "Failed to send file size\n");
        net_close_socket(sock);
        crypto_free_session(&shared);
        fclose(f);
        return EXIT_FAILURE;
    }
    printf("Sending file '%s' (%zu bytes)\n", filename, file_size);

    //Send file content in 1 KiB batches
    unsigned char buf[BATCH_SIZE];
    size_t total_sent = 0;
    size_t n;


    //creating buffer for encrypted message and nonce
    unsigned char encrypted_buf[BATCH_SIZE + AEAD_TAG_LEN];
    unsigned long long encrypted_len = BATCH_SIZE + AEAD_TAG_LEN;
    unsigned char nonce[NONCE_LEN];

    //creating a counter for sent messages
    unsigned long counter = 0;

    while ((n = fread(buf, 1, BATCH_SIZE, f)) > 0) {
        make_nonce(nonce, counter++);
        err = encrypt_message(AEAD_CHACHA20POLY1305_IETF, encrypted_buf, &encrypted_len,
       buf, n,
       nonce, shared -> tx);

        if (err < 0) {
            fprintf(stderr, "Failed to encrypt message\n");
            net_close_socket(sock);
            crypto_free_session(&shared);
            fclose(f);
            return EXIT_FAILURE;
        }

        if (tcp_send(sock, encrypted_buf, encrypted_len) < 0) {
            fprintf(stderr, "Failed to send encrypted file content\n");
            net_close_socket(sock);
            crypto_free_session(&shared);
            fclose(f);
            return EXIT_FAILURE;
        }


        sodium_memzero(buf, BATCH_SIZE);
        total_sent += n;
    }

    crypto_free_session(&shared);
    printf("Done. Sent %zu bytes.\n", total_sent);
    fclose(f);


    //ack receiver
    unsigned char ack_buf[8];
    if (tcp_read(sock, ack_buf, sizeof ack_buf) != (ssize_t)sizeof ack_buf) {
        fprintf(stderr, "Failed to receive ACK\n");
        net_close_socket(sock);
        return EXIT_FAILURE;
    }

    uint64_t ack = get_u64_be(ack_buf);

    if (ack != total_sent) {
        fprintf(stderr, "ACK mismatch: sent %zu, server wrote %" PRIu64 "\n", total_sent, ack);
    } else {
        printf("Server confirmed %" PRIu64 " bytes written\n", ack);
    }

    net_cleanup();
    net_close_socket(sock);
    return EXIT_SUCCESS;
}


