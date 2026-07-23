#include <sodium/crypto_sign.h>

#include "crypto.h"
#include "test_utils.h"



static int test_generator_correctness(void) {
    crypto_init();

    keypair_t * keypair = malloc(sizeof(keypair_t));

    return keypair -> sk != keypair -> pk ? 0 : -1;

}

static int test_generator_incorrectness(void) {
    crypto_init();

    keypair_t * keypair = malloc(sizeof(keypair_t));


}