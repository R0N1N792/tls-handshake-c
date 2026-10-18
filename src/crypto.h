#pragma once


#include <stdint.h>
#include <sodium.h>



#define AEAD_TAG_LEN crypto_aead_aes256gcm_ABYTES // for AEAD_CHACHA20POLY1305_IETF and AAEAD_AES256GCM the tag length is the same(16 bytes)
_Static_assert(AEAD_TAG_LEN == crypto_aead_chacha20poly1305_ietf_ABYTES,    "tag size mismatch");



#define PUBLIC_KEY_LEN crypto_kx_PUBLICKEYBYTES
#define SECRET_KEY_LEN crypto_kx_SECRETKEYBYTES
/**
 * @brief structure to contain the pair of keys for asymmetric encoding: secret(sk) and public(pk).
 */
typedef struct keypair {
    unsigned char pk[PUBLIC_KEY_LEN];
    unsigned char sk[SECRET_KEY_LEN];
} keypair_t;


/**
 * @brief enumeration of all encryption algorithms that could be used in program
 */
typedef enum {
    AEAD_AES256GCM,
    AEAD_CHACHA20POLY1305_IETF
} aead_algo_t;


#define SESSION_KEY_LEN crypto_kx_SESSIONKEYBYTES
/**
 * @brief structure to contain the pair of keys for symmetric encoding: to send(tx) and to receive(rx).
 */
typedef struct session_keypair {
    unsigned char rx[SESSION_KEY_LEN];
    unsigned char tx[SESSION_KEY_LEN];
} session_keypair_t;

/**
 * @brief initializes the library and should be called before any other function provided by Sodium. It is safe to call this function more than once and from different threads – subsequent calls won’t have any effects.
 *
 * @return 0 on success, -1 on failure.
 */
int crypto_init(void);

/**
 * @brief Generates a fresh X25519 keypair: the secret key is 32 bytes from libsodium’s CSPRNG, the public key is derived from it by scalar multiplication of the curve25519 base point
 *
 * @param kp is a pointer on keypair_t where public and secret key will be stored.
 *
 * @return 0 if success.
 */
int generate_keypair(keypair_t* kp);

/**
 * @brief wrapper for the function crypto_kx_client_session_keys.
 *
 * @param session_keys keys for symmetric encoding(to save result).
 * @param client_keypair client's keypair for asymmetric encryption.
 * @param server_pk server's public key of asymmetric encryption.
 *
 * @return It returns 0 on success and -1 if the server’s public key is not acceptable.
 */
int derive_client_keys(session_keypair_t* const session_keys,const keypair_t* client_keypair,const unsigned char server_pk[PUBLIC_KEY_LEN]);

/**
 * @brief wrapper for the function crypto_kx_server_session_keys.
 *
 * @param session_keys keys for symmetric encoding(to save result).
 * @param server_keypair server's keypair for asymmetric encryption.
 * @param client_pk client's public key of asymmetric encryption.
 *
 * @return It returns 0 on success and -1 if the client’s public key is not acceptable.
 */
int derive_server_keys(session_keypair_t* const session_keys,const keypair_t* server_keypair,const unsigned char client_pk[PUBLIC_KEY_LEN]);



#define NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES //we use crypto_aead_aes256gcm_NPUBBYTES(12 bytes) and crypto_aead_chacha20poly1305_IETF_NPUBBYTES(12 bytes) are of the same size
_Static_assert(NONCE_LEN    == crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "nonce size mismatch");

#define AEAD_KEY_LEN crypto_aead_aes256gcm_KEYBYTES //the same for crypto_aead_chacha20poly1305_IETF_KEYBYTES(32 bytes)
_Static_assert(AEAD_KEY_LEN == crypto_aead_chacha20poly1305_ietf_KEYBYTES,  "key size mismatch");

/**
 * @brief  wrapper for encrypting algo function
 *
 * @param algo select algorithm to encrypt message(AEAD_AES256GCM or AEAD_CHACHA20POLY1305)
 * @param out_ciphertext resulting ciphertext
 * @param out_len length of resulting cipher text
 * @param plaintext input plaintext
 * @param plaintext_len length of input plaintext
 * @param nonce
 * @param key
 *
 * @return  0 on success, -1 if AES-GCM is unavailable or encryption fails.
 */
int encrypt_message(aead_algo_t algo,
    unsigned char *out_ciphertext, unsigned long long *out_len,
                     const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char nonce[NONCE_LEN],
                     const unsigned char key[AEAD_KEY_LEN]);


/**
 * @brief wrapper for decrypting algo function
 *
 * @param algo select algorithm to decrypt message(AEAD_AES256GCM or AEAD_CHACHA20POLY1305)
 * @param out_plaintext resulting plaintext
 * @param out_len length of resulting plain text
 * @param ciphertext input ciphertext
 * @param ciphertext_len length of input ciphertext
 * @param nonce
 * @param key
 *
 * @return 0 on success, -1 if the tag verification fails (message forged or corrupted).
 */
int decrypt_message(aead_algo_t algo,
    unsigned char *out_plaintext, unsigned long long *out_len,
                     const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char nonce[NONCE_LEN],
                     const unsigned char key[AEAD_KEY_LEN]);

/**
 * @brief Encodes a monotonically increasing counter into a fixed-size AEAD nonce
 *
 *
 * @param nonce Buffer of NONCE_LEN bytes to receive the encoded nonce.
 * @param counter Per-key send/receive sequence number, incremented
 *                      once per encrypt/decrypt call
 */
void make_nonce(unsigned char nonce[NONCE_LEN], uint64_t counter);


/**
 * @brief calls sodium_memzero() and free() to the pointer of session_keypair_t
 */
void crypto_free_session(session_keypair_t **sk);

/**
 * @brief calls sodium_memzero() and free() to the pointer of keypair_t
 */
void crypto_free_keypair(keypair_t **kp);