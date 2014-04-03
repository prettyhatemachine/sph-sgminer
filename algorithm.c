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
#include "animecoin.h"
#include "inkcoin.h"
#include "quarkcoin.h"
#include "qubitcoin.h"
#include "sifcoin.h"
#include "darkcoin.h"
#include "myriadcoin-groestl.h"
#include "fuguecoin.h"
#include "groestlcoin.h"

#include <inttypes.h>
#include <string.h>

static algorithm_t algos[] = {
    // kernels starting from this will have difficulty calculated by using litecoin algorithm
    { "scrypt",             "ckolivas", 10, 0, ALGO_SCRYPT, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, scrypt_regenhash},
    { "nscrypt",            "ckolivas", 11, 0, ALGO_NSCRYPT, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, scrypt_regenhash},
    { "adaptive-nscrypt",   "ckolivas", 11, 0, ALGO_NSCRYPT, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, scrypt_regenhash},
    { "adaptive-n-scrypt",  "ckolivas", 11, 0, ALGO_NSCRYPT, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, scrypt_regenhash},
    { "scrypt-jane",        "scrypt-jane", 10, 0, ALGO_SCRYPT_JANE, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, sj_scrypt_regenhash},

    // kernels starting from this will have difficulty calculated by using quarkcoin algorithm
    { "quarkcoin",          "quarkcoin", 10, 0, ALGO_QUARKCOIN, 256, 256, 0x000000ffff000000ULL, 0xFFFFFFULL, quarkcoin_regenhash},
    { "qubitcoin",          "qubitcoin", 10, 0, ALGO_QUBITCOIN, 256, 256, 0x000000ffff000000ULL, 0xFFFFFFULL, qubitcoin_regenhash},
    { "inkcoin",            "inkcoin", 10, 0, ALGO_INKCOIN, 256, 256, 0x000000ffff000000ULL, 0xFFFFFFULL, inkcoin_regenhash},
    { "animecoin",          "animecoin", 10, 0, ALGO_ANIMECOIN, 256, 256, 0x000000ffff000000ULL, 0xFFFFFFULL, animecoin_regenhash},
    { "sifcoin",            "sifcoin", 10, 0, ALGO_SIFCOIN, 256, 256, 0x000000ffff000000ULL, 0xFFFFFFULL, sifcoin_regenhash},

    // kernels starting from this will have difficulty calculated by using bitcoin algorithm
    { "darkcoin",           "darkcoin", 10, 0, ALGO_DARKCOIN, 1, 1, 0x00000000ffff0000ULL, 0xFFFFULL, darkcoin_regenhash},
    { "myriadcoin-groestl", "myriadcoin-groestl", 10, 0, ALGO_MYRIADCOIN_GROESTL, 1, 1, 0x00000000ffff0000ULL, 0xFFFFULL, myriadcoin_groestl_regenhash},
    { "fuguecoin",          "fuguecoin", 10, 0, ALGO_FUGUECOIN, 1, 1, 0x00000000ffff0000ULL, 0xFFFFULL, fuguecoin_regenhash},
    { "groestlcoin",        "groestlcoin", 10, 0, ALGO_GROESTLCOIN, 1, 1, 0x00000000ffff0000ULL, 0xFFFFULL, groestlcoin_regenhash},
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
