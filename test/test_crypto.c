#include <sodium.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "test_utils.h"



// tests for asymmetric encoding

static void test_correctness_of_generation(void) {
    int err = crypto_init();
    CHECK(err == 0, "crypto_init succeeds");

    keypair_t *keypair = malloc(sizeof(keypair_t));
    CHECK(err != -1, "generate_keypair succeeds");

    CHECK_TEST(memcmp(keypair->sk, keypair->pk, sizeof(keypair->pk)) == 0,
      "test: sk differs from pk");

    free(keypair);

}

static void test_session_keys_correctness(void) {
    int err = crypto_init();
    CHECK(err == 0, "crypto_init succeeds");

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

    CHECK_TEST(memcmp(server_session -> rx, client_session -> tx,32) == 0 && memcmp(client_session -> rx, server_session -> tx, SESSION_KEY_LEN) == 0,
        "test: client tx equals to server tx and vice versa");

    free(client_session);
    free(server_session);
    free(server);

}


static void test_forged_server_pk_is_rejected_or_diverges(void) {
    int err = crypto_init();
    CHECK(err == 0, "crypto_init succeeds");

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

    CHECK_TEST(memcmp(server_session -> rx, client_session -> tx,SESSION_KEY_LEN) != 0 && memcmp(client_session -> rx, server_session -> tx, SESSION_KEY_LEN) != 0,
        "test: forged server pk is rejected");

    free(client_session);
    free(server_session);
    free(server);

}
//--------------------------------------------------------------------------------------------


//tests for symetric encoding
static void test_encrypt_decrypt_roundtrip_returns_original_plaintext(void) {

    int err = crypto_init();
    CHECK(err == 0, "crypto_init succeeds");

    const char* plaintext = "Hello World!";
    const size_t plaintext_len = strlen(plaintext) - 1; // minus '\0' character in the end

    char key[AEAD_KEY_LEN];
    randombytes_buf(key, AEAD_KEY_LEN);

    char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);


    char* ciphertext;
    unsigned long long ciphertext_len;

    err = encrypt_message(ciphertext, &ciphertext_len,
        plaintext, plaintext_len,
        nonce, key);
    CHECK(err != -1, "encrypt_message succeeds");

    char* newPlaintext;
    unsigned long long newPlaintext_len;

    err = decrypt_message(newPlaintext, &newPlaintext_len,
        ciphertext, ciphertext_len,
        nonce, key);
    CHECK(err != -1, "decrypt_message succeeds");


    CHECK_TEST(newPlaintext_len == plaintext_len && memcmp(newPlaintext, plaintext, plaintext_len) == 0, "test: plaintext encodes and decodes correctly");
}



int main(void) {
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_correctness_of_generation();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_session_keys_correctness();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_forged_server_pk_is_rejected_or_diverges();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_encrypt_decrypt_roundtrip_returns_original_plaintext();
    printf("------------------------------------------------------------------------------------------------------------------\n");

    return 0;
}
