/*
 * Copyright 2014 sgminer developers
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at
 * your option) any later version.  See COPYING for more details.
 */

#include "algorithm.h"
#include "scrypt.h"
#include "scrypt-jane.h"

#include <inttypes.h>
#include <string.h>

static algorithm_t algos[] = {
    // kernels starting from this will have difficulty calculated by using litecoin algorithm
    { "scrypt",             "ckolivas", 10, 0, ALGO_SCRYPT, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, scrypt_regenhash},
    { "nscrypt",            "ckolivas", 11, 0, ALGO_NSCRYPT, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, scrypt_regenhash},
    { "adaptive-nscrypt",   "ckolivas", 11, 0, ALGO_NSCRYPT, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, scrypt_regenhash},
    { "adaptive-n-scrypt",  "ckolivas", 11, 0, ALGO_NSCRYPT, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, scrypt_regenhash},
    { "scrypt-jane",        "scrypt-jane", 10, 0, ALGO_SCRYPT_JANE, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, sj_scrypt_regenhash},
    { NULL, NULL, 0, 0, ALGO_SCRYPT, 0, 0, 0, 0, NULL}
};

void set_algorithm(algorithm_t** algo, const char* newname) {
    algorithm_t* a;
    for (a = algos; a->name; a++) {
	if (strcmp(a->name, newname) == 0) {
		*algo = a;
		break;
	}
    }
    (*algo)->n = (1 << (*algo)->nfactor);
}

void set_algorithm_nfactor(algorithm_t* algo, const uint8_t nfactor) {
    algo->nfactor = nfactor;
    algo->n = (1 << nfactor);

    return;
}
