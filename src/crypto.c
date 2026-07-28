#include <sodium.h>
#include "crypto.h"


int crypto_init(void) {
    if (sodium_init() < 0) {
        return -1;
    }

    if (crypto_aead_aes256gcm_is_available() == 0) {
        return -2;
    }

    return 0;


}


int generate_keypair(keypair_t *kp) {
    return crypto_kx_keypair(kp -> pk, kp -> sk);
}

int derive_client_keys(session_keypair_t* const session_keys,const keypair_t* client_keypair,const unsigned char server_pk[PUBLIC_KEY_LEN]) {
    return crypto_kx_client_session_keys(session_keys -> rx, session_keys -> tx, client_keypair -> pk, client_keypair -> sk, server_pk);
}

int derive_server_keys(session_keypair_t* const session_keys,const keypair_t* server_keypair,const unsigned char client_pk[PUBLIC_KEY_LEN]) {
    return crypto_kx_server_session_keys(session_keys -> rx, session_keys -> tx, server_keypair -> pk, server_keypair -> sk, client_pk);
}


int encrypt_message(unsigned char *out_ciphertext, unsigned long long *out_len,
                     const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char nonce[NONCE_LEN],
                     const unsigned char key[AEAD_KEY_LEN]) {


    return crypto_aead_aes256gcm_encrypt(out_ciphertext, out_len,
        plaintext, plaintext_len,
        NULL, 0,
        NULL,
        nonce, key);
}

int decrypt_message(unsigned char *out_plaintext, unsigned long long *out_len,
                     const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char nonce[NONCE_LEN],
                     const unsigned char key[AEAD_KEY_LEN]) {

    return crypto_aead_aes256gcm_decrypt(out_plaintext, out_len,
        NULL,
        ciphertext, ciphertext_len,
        NULL, 0,
        nonce, key);
}