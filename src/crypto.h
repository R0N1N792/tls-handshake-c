#pragma once

/**
 * @brief structure to contain the pair of keys for asymmetric encoding: secret(sk) and public(pk).
 */
typedef struct keypair {
    unsigned char pk[32];
    unsigned char sk[32];
} keypair_t;

/**
 * @brief structure to contain the pair of keys for symmetric encoding: to send(tx) and to receive(rx).
 */
typedef struct session_keypair {
    unsigned char rx[32];
    unsigned char tx[32];
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
int derive_client_keys(session_keypair_t* const session_keys,const keypair_t* client_keypair,const unsigned char server_pk[32]);

/**
 * @brief wrapper for the function crypto_kx_server_session_keys.
 *
 * @param session_keys keys for symmetric encoding(to save result).
 * @param server_keypair server's keypair for asymmetric encryption.
 * @param client_pk client's public key of asymmetric encryption.
 *
 * @return It returns 0 on success and -1 if the client’s public key is not acceptable.
 */
int derive_server_keys(session_keypair_t* const session_keys,const keypair_t* server_keypair,const unsigned char client_pk[32]);