#include <sodium.h>
#include "crypto.h"
#include <string.h>

#include "byteorder.h"

int crypto_init(void) {
    if (sodium_init() < 0) {
        return -1;
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

int encrypt_message(aead_algo_t algo,unsigned char *out_ciphertext, unsigned long long *out_len,
                     const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char nonce[NONCE_LEN],
                     const unsigned char key[AEAD_KEY_LEN]) {

    switch (algo) {
        case AEAD_AES256GCM:
            return crypto_aead_aes256gcm_encrypt(out_ciphertext, out_len,
                plaintext, plaintext_len,
                NULL, 0,
                NULL,
                nonce, key);

        case AEAD_CHACHA20POLY1305_IETF:
            return crypto_aead_chacha20poly1305_ietf_encrypt(out_ciphertext, out_len,
                plaintext, plaintext_len,
                NULL, 0,
                NULL,
                nonce, key);

        default:
            return -1;
    }
}


int decrypt_message(aead_algo_t algo,unsigned char *out_plaintext,
                    unsigned long long *out_len,
                     const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char nonce[NONCE_LEN],
                     const unsigned char key[AEAD_KEY_LEN]) {
    switch (algo) {
        case AEAD_AES256GCM:
            return crypto_aead_aes256gcm_decrypt(out_plaintext, out_len,NULL,
            ciphertext, ciphertext_len,
            NULL, 0,
            nonce, key);

        case AEAD_CHACHA20POLY1305_IETF:
            return crypto_aead_chacha20poly1305_ietf_decrypt(out_plaintext, out_len,NULL,
                ciphertext, ciphertext_len,
                NULL, 0,
                nonce, key);
        default:
            return -1;

    }
}

void make_nonce(unsigned char nonce[NONCE_LEN], uint64_t counter) {
    memset(nonce, 0, NONCE_LEN);
    put_u64_be(nonce + (NONCE_LEN - 8), counter);   /* right-aligned, TLS 1.3 style */
}


void crypto_free_session(session_keypair_t **sk) {
    if (sk && *sk) { sodium_memzero(*sk, sizeof **sk); free(*sk); *sk = NULL; }
}

void crypto_free_keypair(keypair_t **kp) {
    if (kp && *kp) {sodium_memzero(*kp, sizeof **kp); free(*kp);*kp = NULL;}
}
