#ifndef SCRYPT_JANE_H
#define SCRYPT_JANE_H

#include "miner.h"

extern int sj_scrypt_test(unsigned char *pdata, const unsigned char *ptarget,
			uint32_t nonce);
extern void sj_scrypt_regenhash(struct work *work);
extern inline void sj_be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len);

#endif /* SCRYPT_JANE_H */
