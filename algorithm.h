#ifndef ALGORITHM_H
#define ALGORITHM_H

#include <inttypes.h>

struct work;

enum algorithm {
    ALGO_SCRYPT, // kernels starting from this will have difficulty calculated by using litecoin algorithm
    ALGO_NSCRYPT,
    ALGO_SCRYPT_JANE,
    ALGO_QUARKCOIN, // kernels starting from this will have difficulty calculated by using quarkcoin algorithm
    ALGO_QUBITCOIN,
    ALGO_INKCOIN,
    ALGO_ANIMECOIN,
    ALGO_SIFCOIN,
    ALGO_DARKCOIN, // kernels starting from this will have difficulty calculated by using bitcoin algorithm
    ALGO_MYRIADCOIN_GROESTL,
    ALGO_FUGUECOIN,
    ALGO_GROESTLCOIN,
};

/* Describes the Scrypt parameters and hashing functions used to mine
 * a specific coin.
 */
typedef struct _algorithm_t {
    const char* name; /* Human-readable identifier */
    char*    kernelname; /* Default kernel */
    uint32_t n;        /* N (CPU/Memory tradeoff parameter) */
    uint8_t  nfactor;  /* Factor of N above (n = 2^nfactor) */
    enum algorithm algo;
    double   diff_multiplier1;
    double   diff_multiplier2;
    unsigned long long   diff_nonce;
    unsigned long long   diff_numerator;
    void     (*regenhash)(struct work *work);
} algorithm_t;

/* Set default parameters based on name. */
void set_algorithm(algorithm_t** algo, const char* name);

/* Set to specific N factor. */
void set_algorithm_nfactor(algorithm_t* algo, const uint8_t nfactor);

#endif /* ALGORITHM_H */
