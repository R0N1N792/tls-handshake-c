#include <sodium.h>
#include <string.h>

#include "crypto.h"
#include "test_utils.h"


static void test_correctness_of_generation(void) {
    int err = crypto_init();
    CHECK(err != -1, "crypto_init succeeds");

    keypair_t *keypair = malloc(sizeof(keypair_t));
    CHECK(err != -1, "generate_keypair succeeds");

    CHECK_TEST(memcmp(keypair->sk, keypair->pk, sizeof(keypair->pk)) != 0,
      "test: sk differs from pk");

    free(keypair);

}

static void test_session_keys_correctness(void) {
    int err = crypto_init();
    CHECK(err != -1, "crypto_init succeeds");

    keypair_t * client = malloc(sizeof(keypair_t));
    err = generate_keypair(client);
    CHECK(err != -1, "generate_keypair for client succeeds");


    keypair_t* server = malloc(sizeof(keypair_t));
    err = generate_keypair(server);
    CHECK(err != -1, "generate_keypair for server succeeds");

    session_keypair_t* client_session = malloc(sizeof(session_keypair_t));
    err = derive_client_keys(client_session, client, server -> pk);
    CHECK(err != -1, "derive_client_keys succeeds");

    session_keypair_t* server_session = malloc(sizeof(session_keypair_t));
    err = derive_server_keys(server_session, server, client -> pk);
    CHECK(err != -1, "derive_server_keys succeeds");

    CHECK_TEST(memcmp(server_session -> rx, client_session -> tx,32) ==0 && memcmp(client_session -> rx, server_session -> tx, SESSION_KEY_LEN) == 0,
        "test: client tx equals to server tx and vice versa");

    free(client_session);
    free(server_session);
    free(server);

}


static void test_forged_server_pk_is_rejected_or_diverges(void) {
    int err = crypto_init();
    CHECK(err != -1, "crypto_init succeeds");

    keypair_t * client = malloc(sizeof(keypair_t));
    err = generate_keypair(client);
    CHECK(err != -1, "generate_keypair for client succeeds");


    keypair_t* server = malloc(sizeof(keypair_t));
    err = generate_keypair(server);
    CHECK(err != -1, "generate_keypair for server succeeds");

    session_keypair_t* client_session = malloc(sizeof(session_keypair_t));
    //forging a pk for server
    char forged_server_pk[PUBLIC_KEY_LEN];
    randombytes_buf(forged_server_pk, sizeof(forged_server_pk));

    err = derive_client_keys(client_session, client, forged_server_pk);
    CHECK(err != -1, "derive_client_keys succeeds");

    session_keypair_t* server_session = malloc(sizeof(session_keypair_t));
    err = derive_server_keys(server_session, server, client -> pk);
    CHECK(err != -1, "derive_server_keys succeeds");

    CHECK_TEST(memcmp(server_session -> rx, client_session -> tx,SESSION_KEY_LEN) !=0 && memcmp(client_session -> rx, server_session -> tx, SESSION_KEY_LEN) != 0,
        "test: forged server pk is rejected");

    free(client_session);
    free(server_session);
    free(server);

}

int main(void) {
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_correctness_of_generation();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_session_keys_correctness();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_forged_server_pk_is_rejected_or_diverges();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    return 0;
}
