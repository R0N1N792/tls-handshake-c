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
    err = generate_keypair(keypair);
    CHECK(err != -1, "generate_keypair succeeds");

    CHECK_TEST(memcmp(keypair->sk, keypair->pk, sizeof(keypair->pk)) != 0,
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

    CHECK_TEST(memcmp(server_session -> rx, client_session -> tx, SESSION_KEY_LEN) == 0 && memcmp(client_session -> rx, server_session -> tx, SESSION_KEY_LEN) == 0,
        "test: client tx equals to server tx and vice versa");

    free(client_session);
    free(server_session);
    free(server);
    free(client);

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
    unsigned char forged_server_pk[PUBLIC_KEY_LEN];
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
static void test_encrypt_decrypt_roundtrip_returns_original_plaintext(aead_algo_t algo) {
    int err = crypto_init();
    CHECK(err == 0, "crypto_init succeeds");

    const char* plaintext = "Hello World!";
    const size_t plaintext_len = strlen(plaintext) ;

    unsigned char key[AEAD_KEY_LEN];
    randombytes_buf(key, AEAD_KEY_LEN);

    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);



    unsigned char* ciphertext = malloc(plaintext_len + AEAD_TAG_LEN);
    unsigned long long ciphertext_len;

    err = encrypt_message(algo, ciphertext, &ciphertext_len,
        (const unsigned char*)plaintext, plaintext_len,
        nonce, key);
    CHECK(err != -1, "encrypt_message succeeds");

    unsigned char* newPlaintext = malloc(plaintext_len);
    unsigned long long newPlaintext_len;

    err = decrypt_message(algo, newPlaintext, &newPlaintext_len,
        ciphertext, ciphertext_len,
        nonce, key);
    CHECK(err != -1, "decrypt_message succeeds");


    CHECK_TEST(newPlaintext_len == plaintext_len && memcmp(newPlaintext, plaintext, plaintext_len) == 0, "test: plaintext encodes and decodes correctly");
    free(ciphertext);
    free(newPlaintext);

}

void test_decrypt_tampered_ciphertext_fails(aead_algo_t algo) {
    int err = crypto_init();
    CHECK(err == 0, "crypto_init succeeds");

    const char* plaintext = "Hello World!";
    const size_t plaintext_len = strlen(plaintext) ;

    unsigned char key[AEAD_KEY_LEN];
    randombytes_buf(key, AEAD_KEY_LEN);

    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);



    unsigned char* ciphertext = malloc(plaintext_len + AEAD_TAG_LEN);
    unsigned long long ciphertext_len;

    err = encrypt_message(algo, ciphertext, &ciphertext_len,
        (const unsigned char*)plaintext, plaintext_len,
        nonce, key);
    CHECK(err != -1, "encrypt_message succeeds");


    //tampering a bit of cipher
    size_t idx = randombytes_uniform((uint32_t)plaintext_len);
    uint8_t bit  = 1 << randombytes_uniform(8);
    ciphertext[idx] ^= bit;


    unsigned char* newPlaintext = malloc(plaintext_len);
    unsigned long long newPlaintext_len;



    err = decrypt_message(algo, newPlaintext, &newPlaintext_len,
        ciphertext, ciphertext_len,
        nonce, key);

    CHECK_TEST(err == -1, "test: tampered cipher detected");
    free(ciphertext);
    free(newPlaintext);

}

void test_decrypt_tampered_tag_fails(aead_algo_t algo) {
    int err = crypto_init();
    CHECK(err == 0, "crypto_init succeeds");

    const char* plaintext = "Hello World!";
    const size_t plaintext_len = strlen(plaintext) ;

    unsigned char key[AEAD_KEY_LEN];
    randombytes_buf(key, AEAD_KEY_LEN);

    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);



    unsigned char* ciphertext = malloc(plaintext_len + AEAD_TAG_LEN);
    unsigned long long ciphertext_len;

    err = encrypt_message(algo, ciphertext, &ciphertext_len,
        (const unsigned char*)plaintext, plaintext_len,
        nonce, key);
    CHECK(err != -1, "encrypt_message succeeds");


    //tampering a bit of tag
    size_t idx = randombytes_uniform((uint32_t)AEAD_TAG_LEN) + plaintext_len;
    uint8_t bit  = 1 << randombytes_uniform(8);
    ciphertext[idx] ^= bit;


    unsigned char* newPlaintext = malloc(plaintext_len);
    unsigned long long newPlaintext_len;



    err = decrypt_message(algo, newPlaintext, &newPlaintext_len,
        ciphertext, ciphertext_len,
        nonce, key);

    CHECK_TEST(err == -1, "test: tampered tag detected");
    free(ciphertext);
    free(newPlaintext);
}

void test_decrypt_wrong_key_fails(aead_algo_t algo) {
    int err = crypto_init();
    CHECK(err == 0, "crypto_init succeeds");

    const char* plaintext = "Hello World!";
    const size_t plaintext_len = strlen(plaintext) ;

    unsigned char key[AEAD_KEY_LEN];
    randombytes_buf(key, AEAD_KEY_LEN);

    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);



    unsigned char* ciphertext = malloc(plaintext_len + AEAD_TAG_LEN);
    unsigned long long ciphertext_len;

    err = encrypt_message(algo, ciphertext, &ciphertext_len,
        (const unsigned char*)plaintext, plaintext_len,
        nonce, key);
    CHECK(err != -1, "encrypt_message succeeds");

    unsigned char* newPlaintext = malloc(plaintext_len);
    unsigned long long newPlaintext_len;

    //creating a new key for decryption
    unsigned char wrongKey[AEAD_KEY_LEN];
    memcpy(wrongKey, key, AEAD_KEY_LEN);

    //tampering a bit of key(not to generate random_but to avoid generating the same key)
    size_t idx = randombytes_uniform((uint32_t)AEAD_KEY_LEN);
    uint8_t bit  = 1 << randombytes_uniform(8);
    wrongKey[idx] ^= bit;

    err = decrypt_message(algo, newPlaintext, &newPlaintext_len,
        ciphertext, ciphertext_len,
        nonce, wrongKey);
    CHECK_TEST(err == -1, "test: decrypt_message fails with wrong key");
    free(ciphertext);
    free(newPlaintext);
}




int main(void) {
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_correctness_of_generation();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_session_keys_correctness();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_forged_server_pk_is_rejected_or_diverges();
    printf("------------------------------------------------------------------------------------------------------------------\n");
    printf("Testing AEAD_CHACHA20POLY1305\n");
    test_encrypt_decrypt_roundtrip_returns_original_plaintext(AEAD_CHACHA20POLY1305_IETF);
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_decrypt_tampered_ciphertext_fails(AEAD_CHACHA20POLY1305_IETF);
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_decrypt_tampered_tag_fails(AEAD_CHACHA20POLY1305_IETF);
    printf("------------------------------------------------------------------------------------------------------------------\n");
    test_decrypt_wrong_key_fails(AEAD_CHACHA20POLY1305_IETF);
    printf("------------------------------------------------------------------------------------------------------------------\n");



    if (crypto_aead_aes256gcm_is_available() == 1) {
        printf("Testing AEAD_AES256GCM\n");
        test_encrypt_decrypt_roundtrip_returns_original_plaintext(AEAD_AES256GCM);
        printf("------------------------------------------------------------------------------------------------------------------\n");
        test_decrypt_tampered_ciphertext_fails(AEAD_AES256GCM);
        printf("------------------------------------------------------------------------------------------------------------------\n");
        test_decrypt_tampered_tag_fails(AEAD_AES256GCM);
        printf("------------------------------------------------------------------------------------------------------------------\n");
        test_decrypt_wrong_key_fails(AEAD_AES256GCM);
        printf("------------------------------------------------------------------------------------------------------------------\n");
    }
    else
        printf("SKIPPED: AES-256-GCM unavailable\n");

    TEST_SUMMARY();
    return tests_passed == tests_run ? 0 : 1;
}
