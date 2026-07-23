#include <sodium/crypto_sign.h>
#include <sodium.h>
#include <string.h>

#include "crypto.h"
#include "test_utils.h"
#include "../src/crypto.h"


static int test_correctness_of_generation(void) {
    int err = crypto_init();
    if (err == -1) {
        printf("Error initializing crypto\n");
        return err;
    }

    keypair_t * keypair = malloc(sizeof(keypair_t));
    err = generate_keypair(keypair);
    if (err == -1) {
        printf("Error generating keypair\n");
        return err;
    }

    return keypair -> sk != keypair -> pk ? 0 : -1;

}

static int test_session_keys_correctness(void) {
    int err = crypto_init();
    if (err == -1) {
        printf("Error initializing crypto\n");
        return err;
    }

    keypair_t * client = malloc(sizeof(keypair_t));
    err = generate_keypair(client);
    if (err == -1) {
        printf("Error generating client keypair\n");
        return err;
    }

    keypair_t* server = malloc(sizeof(keypair_t));
    err = generate_keypair(server);
    if (err == -1) {
        printf("Error generating server keypair\n");
        return err;
    }

    session_keypair_t* client_session = malloc(sizeof(session_keypair_t));
    err = derive_client_keys(client_session,client, server -> pk);
    if (err == -1) {
        printf("Error generating client session keypair\n");
        return err;
    }

    session_keypair_t* server_session = malloc(sizeof(session_keypair_t));
    err = derive_server_keys(server_session,server, client -> pk);
    if (err == -1) {
        printf("Error generating server session keypair\n");
        return err;
    }

    return (memcmp(server_session -> rx, client_session -> tx,32)==0 && memcmp(client_session -> rx , server_session -> tx, 32)==0) ? 0 : -1;
}


static int test_forged_server_pk_is_rejected_or_diverges(void) {
    int err = crypto_init();
    if (err == -1) {
        printf("Error initializing crypto\n");
        return err;
    }

    keypair_t * client = malloc(sizeof(keypair_t));
    err = generate_keypair(client);
    if (err == -1) {
        printf("Error generating client keypair\n");
        return err;
    }

    keypair_t* server = malloc(sizeof(keypair_t));
    err = generate_keypair(server);
    if (err == -1) {
        printf("Error generating server keypair\n");
        return err;
    }

    session_keypair_t* client_session = malloc(sizeof(session_keypair_t));
    char forged_server_pk[32];
    randombytes_buf(forged_server_pk, sizeof(forged_server_pk));

    err = derive_client_keys(client_session,client, forged_server_pk);
    if (err == -1) {
        printf("Error generating client session keypair\n");
        return err;
    }

    session_keypair_t* server_session = malloc(sizeof(session_keypair_t));
    err = derive_server_keys(server_session,server, client -> pk);
    if (err == -1) {
        printf("Error generating server session keypair\n");
        return err;
    }



    return (memcmp(server_session -> rx, client_session -> tx, 32)!=0 && memcmp(client_session -> rx , server_session -> tx, 32)!=0) ? 0 : -1;

}

int main(void) {
    int fail = 0;
    fail |= test_correctness_of_generation();
    fail |= test_session_keys_correctness();
    fail |= test_forged_server_pk_is_rejected_or_diverges();
    printf(fail ? "FAILED\n" : "ALL PASSED\n");
    return fail;
}
