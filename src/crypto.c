#include <sodium.h>
#include "crypto.h"


int crypto_init(void) {
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}


int generate_keypair(keypair_t *kp) {
    return crypto_kx_keypair(kp -> pk, kp -> sk);
}

int derive_client_keys(session_keypair_t* const session_keys,const keypair_t* client_keypair,const unsigned char server_pk[32]) {
    return crypto_kx_client_session_keys(session_keys -> rx, session_keys -> tx, client_keypair -> pk, client_keypair -> sk, server_pk);
}

int derive_server_keys(session_keypair_t* const session_keys,const keypair_t* server_keypair,const unsigned char client_pk[32]) {
    return crypto_kx_server_session_keys(session_keys -> rx, session_keys -> tx, server_keypair -> pk, server_keypair -> sk, client_pk);
}