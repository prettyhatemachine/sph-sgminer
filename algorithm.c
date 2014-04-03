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
#define A_SCRYPT(a, b, c, d, e) \
	{ a, b, 0, c, d, 1, 65536, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, e}
	A_SCRYPT( "scrypt",            "ckolivas",    10, ALGO_SCRYPT,      scrypt_regenhash),
	A_SCRYPT( "nscrypt",           "ckolivas",    11, ALGO_NSCRYPT,     scrypt_regenhash),
	A_SCRYPT( "adaptive-nscrypt",  "ckolivas",    11, ALGO_NSCRYPT,     scrypt_regenhash),
	A_SCRYPT( "adaptive-n-scrypt", "ckolivas",    11, ALGO_NSCRYPT,     scrypt_regenhash),
	A_SCRYPT( "scrypt-jane",       "scrypt-jane", 10, ALGO_SCRYPT_JANE, sj_scrypt_regenhash),
#undef A_SCRYPT

	// kernels starting from this will have difficulty calculated by using quarkcoin algorithm
#define A_QUARK(a, b, c, d) \
	{ a, b, 0, 10, c, 256, 256, 0x000000ffff000000ULL, 0xFFFFFFULL, d}
	A_QUARK( "quarkcoin", "quarkcoin", ALGO_QUARKCOIN, quarkcoin_regenhash),
	A_QUARK( "qubitcoin", "qubitcoin", ALGO_QUBITCOIN, qubitcoin_regenhash),
	A_QUARK( "inkcoin",   "inkcoin",   ALGO_INKCOIN,   inkcoin_regenhash),
	A_QUARK( "animecoin", "animecoin", ALGO_ANIMECOIN, animecoin_regenhash),
	A_QUARK( "sifcoin",   "sifcoin",   ALGO_SIFCOIN,   sifcoin_regenhash),
#undef A_QUARK

	// kernels starting from this will have difficulty calculated by using bitcoin algorithm
#define A_DARK(a, b, c, d) \
	{ a, b, 0, 10, c, 1, 1, 0x00000000ffff0000ULL, 0xFFFFULL, d}
	A_DARK( "darkcoin",           "darkcoin",           ALGO_DARKCOIN, darkcoin_regenhash),
	A_DARK( "myriadcoin-groestl", "myriadcoin-groestl", ALGO_MYRIADCOIN_GROESTL, myriadcoin_groestl_regenhash),
	A_DARK( "fuguecoin",          "fuguecoin",          ALGO_FUGUECOIN, fuguecoin_regenhash),
	A_DARK( "groestlcoin",        "groestlcoin",        ALGO_GROESTLCOIN, groestlcoin_regenhash),
#undef A_DARK

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
