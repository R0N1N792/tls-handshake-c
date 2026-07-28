#pragma once


#define PUBLIC_KEY_LEN crypto_kx_PUBLICKEYBYTES
#define SECRET_KEY_LEN crypto_kx_SECRETKEYBYTES
/**
 * @brief structure to contain the pair of keys for asymmetric encoding: secret(sk) and public(pk).
 */
typedef struct keypair {
    unsigned char pk[PUBLIC_KEY_LEN];
    unsigned char sk[SECRET_KEY_LEN];
} keypair_t;



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
 * @brief generate randomly private key and then with Montgomery ladder derives public key.
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



#define NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES
#define TAG_LEN    crypto_aead_aes256gcm_ABYTES
#define AEAD_KEY_LEN crypto_aead_aes256gcm_KEYBYTES
/**
 * @brief  wrapper for crypto_aead_aes256gcm_encrypt function
 *
 * @param out_ciphertext resulting ciphertext
 * @param out_len length of resulting cipher text
 * @param plaintext input plaintext
 * @param plaintext_len length of input plaintext
 * @param nonce
 * @param key
 *
 * @return  0 on success, -1 if AES-GCM is unavailable or encryption fails.
 */
int encrypt_message(unsigned char *out_ciphertext, unsigned long long *out_len,
                     const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char nonce[NONCE_LEN],
                     const unsigned char key[AEAD_KEY_LEN]);


/**
 * @brief wrapper for crypto_aead_aes256gcm_decrypt function
 *
 * @param out_plaintext resulting plaintext
 * @param out_len length of resulting plain text
 * @param ciphertext input ciphertext
 * @param ciphertext_len length of input ciphertext
 * @param nonce
 * @param key
 *
 * @return 0 on success, -1 if the tag verification fails (message forged or corrupted).
 */
int decrypt_message(unsigned char *out_plaintext, unsigned long long *out_len,
                     const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char nonce[NONCE_LEN],
                     const unsigned char key[AEAD_KEY_LEN]);