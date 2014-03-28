/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "config.h"
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>


// yacoin: increasing Nfactor gradually
//const unsigned char minNfactor = 4;
//const unsigned char maxNfactor = 30;

unsigned char sj_GetNfactor(int nTimestamp) {
    int l = 0;

    if (nTimestamp <= sj_startTime)
        return sj_minNf;

    int s = nTimestamp - sj_startTime;
    while ((s >> 1) > 3) {
      l += 1;
      s >>= 1;
    }

    s &= 3;

    int n = (l * 170 + s * 25 - 2320) / 100;

    if (n < 0) n = 0;

    if (n > 255)
        printf("sj_GetNfactor(%d) - something wrong(n == %d)\n", nTimestamp, n);

    unsigned char N = (unsigned char)n;

    if(N<sj_minNf) return sj_minNf;
    if(N>sj_maxNf) return sj_maxNf;
    return N;
}

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
inline void
sj_be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}

static void sj_scrypt(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint8_t Nfactor, uint8_t rfactor, uint8_t pfactor, uint8_t *out, size_t bytes);

void sj_scrypt_regenhash(struct work *work)
{
	uint32_t data[20];
	uint32_t *nonce = (uint32_t *)(work->data + 76);
	uint32_t *ohash = (uint32_t *)(work->hash);

	sj_be32enc_vect(data, (const uint32_t *)work->data, 19);
	data[19] = htobe32(*nonce);
        
	applog(LOG_DEBUG, "timestamp %d", data[17]);
        
        int nfactor = sj_GetNfactor(data[17]);
    
        applog(LOG_DEBUG, "Dat0: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
            data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
    
        sj_scrypt((unsigned char *)data, 80, 
                       (unsigned char *)data, 80, 
                       nfactor, 0, 0, (unsigned char *)ohash, 32);
    
//	flip32(ohash, ohash); // Not needed for scrypt-chacha - mikaelh
        uint32_t *o = ohash;
	applog(LOG_DEBUG, "Nonce: %x, Output buffe0: %x %x %x %x %x %x %x %x", *nonce, o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]);
}

static const uint32_t sj_diff1targ = 0x0000ffff;

typedef uint32_t sj_scrypt_mix_word_t;

typedef void (*sj_scrypt_fatal_errorfn)(const char *msg);
void sj_scrypt_set_fatal_error(sj_scrypt_fatal_errorfn fn);

#define SJ_SCRYPT_BLOCK_BYTES 64
#define SJ_SCRYPT_BLOCK_WORDS (SJ_SCRYPT_BLOCK_BYTES / sizeof(sj_scrypt_mix_word_t))

#define SJ_ROTL32(a,b) (((a) << (b)) | ((a) >> (32 - b)))
#define SJ_ROTL64(a,b) (((a) << (b)) | ((a) >> (64 - b)))
#define SJ_U8TO64_LE(p)                                                  \
	(((uint64_t)SJ_U8TO32_LE(p)) | ((uint64_t)SJ_U8TO32_LE((p) + 4) << 32))
#define SJ_U8TO32_LE(p)                                            \
	(((uint32_t)((p)[0])      ) | ((uint32_t)((p)[1]) <<  8) |  \
	 ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define SJ_U32TO8_BE(p, v)                                           \
	(p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
	(p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );
#define SJ_U64TO8_LE(p, v)                        \
	SJ_U32TO8_LE((p),     (uint32_t)((v)      )); \
	SJ_U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));
#define SJ_U32TO8_LE(p, v)                                           \
	(p)[0] = (uint8_t)((v)      ); (p)[1] = (uint8_t)((v) >>  8); \
	(p)[2] = (uint8_t)((v) >> 16); (p)[3] = (uint8_t)((v) >> 24);

#define sj_scrypt_maxN 30  /* (1 << (30 + 1)) = ~2 billion */
#if (SJ_SCRYPT_BLOCK_BYTES == 64)
#define sj_scrypt_r_32kb 8 /* (1 << 8) = 256 * 2 blocks in a chunk * 64 bytes = Max of 32kb in a chunk */
#elif (SJ_SCRYPT_BLOCK_BYTES == 128)
#define sj_scrypt_r_32kb 7 /* (1 << 7) = 128 * 2 blocks in a chunk * 128 bytes = Max of 32kb in a chunk */
#elif (SJ_SCRYPT_BLOCK_BYTES == 256)
#define sj_scrypt_r_32kb 6 /* (1 << 6) = 64 * 2 blocks in a chunk * 256 bytes = Max of 32kb in a chunk */
#elif (SJ_SCRYPT_BLOCK_BYTES == 512)
#define sj_scrypt_r_32kb 5 /* (1 << 5) = 32 * 2 blocks in a chunk * 512 bytes = Max of 32kb in a chunk */
#endif
#define sj_scrypt_maxr sj_scrypt_r_32kb /* 32kb */
#define sj_scrypt_maxp 25  /* (1 << 25) = ~33 million */

#include <stdio.h>
#include <malloc.h>

static void
sj_scrypt_fatal_error_default(const char *msg) {
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

static sj_scrypt_fatal_errorfn sj_scrypt_fatal_error = sj_scrypt_fatal_error_default;

void
sj_scrypt_set_fatal_error_default(sj_scrypt_fatal_errorfn fn) {
	sj_scrypt_fatal_error = fn;
}

typedef struct sj_scrypt_aligned_alloc_t {
	uint8_t *mem, *ptr;
} sj_scrypt_aligned_alloc;

#if defined(SCRYPT_TEST_SPEED)
static uint8_t *sj_mem_base = (uint8_t *)0;
static size_t sj_mem_bump = 0;

/* allocations are assumed to be multiples of 64 bytes and total allocations not to exceed ~1.01gb */
static sj_scrypt_aligned_alloc
sj_scrypt_alloc(uint64_t size) {
	sj_scrypt_aligned_alloc aa;
	if (!sj_mem_base) {
		sj_mem_base = (uint8_t *)malloc((1024 * 1024 * 1024) + (1024 * 1024) + (SJ_SCRYPT_BLOCK_BYTES - 1));
		if (!sj_mem_base)
			sj_scrypt_fatal_error("scrypt-jane: out of memory");
		sj_mem_base = (uint8_t *)(((size_t)sj_mem_base + (SJ_SCRYPT_BLOCK_BYTES - 1)) & ~(SJ_SCRYPT_BLOCK_BYTES - 1));
	}
	aa.mem = sj_mem_base + sj_mem_bump;
	aa.ptr = aa.mem;
	sj_mem_bump += (size_t)size;
	return aa;
}

static void
sj_scrypt_free(sj_scrypt_aligned_alloc *aa) {
	sj_mem_bump = 0;
}
#else
static sj_scrypt_aligned_alloc
sj_scrypt_alloc(uint64_t size) {
	static const size_t max_alloc = (size_t)-1;
	sj_scrypt_aligned_alloc aa;
	size += (SJ_SCRYPT_BLOCK_BYTES - 1);
	if (size > max_alloc)
		sj_scrypt_fatal_error("scrypt-jane: not enough address space on this CPU to allocate required memory");
	aa.mem = (uint8_t *)malloc((size_t)size);
	aa.ptr = (uint8_t *)(((size_t)aa.mem + (SJ_SCRYPT_BLOCK_BYTES - 1)) & ~(SJ_SCRYPT_BLOCK_BYTES - 1));
	if (!aa.mem)
		sj_scrypt_fatal_error("scrypt-jane: out of memory");
	return aa;
}

static void
sj_scrypt_free(sj_scrypt_aligned_alloc *aa) {
	free(aa->mem);
}
#endif



static void
sj_chacha_core(uint32_t state[16]) {
	size_t rounds = 8;
	uint32_t x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,t;

	x0 = state[0];
	x1 = state[1];
	x2 = state[2];
	x3 = state[3];
	x4 = state[4];
	x5 = state[5];
	x6 = state[6];
	x7 = state[7];
	x8 = state[8];
	x9 = state[9];
	x10 = state[10];
	x11 = state[11];
	x12 = state[12];
	x13 = state[13];
	x14 = state[14];
	x15 = state[15];

	#define quarter(a,b,c,d) \
		a += b; t = d^a; d = SJ_ROTL32(t,16); \
		c += d; t = b^c; b = SJ_ROTL32(t,12); \
		a += b; t = d^a; d = SJ_ROTL32(t, 8); \
		c += d; t = b^c; b = SJ_ROTL32(t, 7);

	for (; rounds; rounds -= 2) {
		quarter( x0, x4, x8,x12)
		quarter( x1, x5, x9,x13)
		quarter( x2, x6,x10,x14)
		quarter( x3, x7,x11,x15)
		quarter( x0, x5,x10,x15)
		quarter( x1, x6,x11,x12)
		quarter( x2, x7, x8,x13)
		quarter( x3, x4, x9,x14)
	}

	state[0] += x0;
	state[1] += x1;
	state[2] += x2;
	state[3] += x3;
	state[4] += x4;
	state[5] += x5;
	state[6] += x6;
	state[7] += x7;
	state[8] += x8;
	state[9] += x9;
	state[10] += x10;
	state[11] += x11;
	state[12] += x12;
	state[13] += x13;
	state[14] += x14;
	state[15] += x15;

	#undef quarter
}


/* returns a pointer to item i, where item is len sj_scrypt_mix_word_t's long */
static sj_scrypt_mix_word_t *
sj_scrypt_item(sj_scrypt_mix_word_t *base, sj_scrypt_mix_word_t i, sj_scrypt_mix_word_t len) {
	return base + (i * len);
}


static sj_scrypt_mix_word_t *
sj_scrypt_block(sj_scrypt_mix_word_t *base, sj_scrypt_mix_word_t i) {
	return base + (i * SJ_SCRYPT_BLOCK_WORDS);
}

#define SJ_MM16 __attribute__((aligned(16)))

static void
sj_scrypt_ChunkMix(sj_scrypt_mix_word_t *Bout/*[chunkWords]*/, sj_scrypt_mix_word_t *Bin/*[chunkWords]*/, sj_scrypt_mix_word_t *Bxor/*[chunkWords]*/, uint32_t r) {
	sj_scrypt_mix_word_t SJ_MM16 X[SJ_SCRYPT_BLOCK_WORDS], *block;
	uint32_t i, j, blocksPerChunk = r * 2, half = 0;

	/* 1: X = B_{2r - 1} */
	block = sj_scrypt_block(Bin, blocksPerChunk - 1);
	for (i = 0; i < SJ_SCRYPT_BLOCK_WORDS; i++)
		X[i] = block[i];

	if (Bxor) {
		block = sj_scrypt_block(Bxor, blocksPerChunk - 1);
		for (i = 0; i < SJ_SCRYPT_BLOCK_WORDS; i++)
			X[i] ^= block[i];
	}

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		block = sj_scrypt_block(Bin, i);
		for (j = 0; j < SJ_SCRYPT_BLOCK_WORDS; j++)
			X[j] ^= block[j];

		if (Bxor) {
			block = sj_scrypt_block(Bxor, i);
			for (j = 0; j < SJ_SCRYPT_BLOCK_WORDS; j++)
				X[j] ^= block[j];
		}
		/* SCRYPT_MIX_FN */ sj_chacha_core(X);

		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		block = sj_scrypt_block(Bout, (i / 2) + half);
		for (j = 0; j < SJ_SCRYPT_BLOCK_WORDS; j++)
			block[j] = X[j];
	}
}

#define SJ_U32_SWAP(v) {                                             \
	(v) = (((v) << 8) & 0xFF00FF00 ) | (((v) >> 8) & 0xFF00FF );  \
    (v) = ((v) << 16) | ((v) >> 16);                              \
}

#define SJ_SCRYPT_WORD_ENDIAN_SWAP SJ_U32_SWAP

/* romix pre/post endian conversion function */
static void
sj_scrypt_romix_convert_endian(sj_scrypt_mix_word_t *blocks, size_t nblocks) {
#if !defined(CPU_LE)
	static const union { uint8_t b[2]; uint16_t w; } endian_test = {{1,0}};
	size_t i;
	if (endian_test.w == 0x100) {
		nblocks *= SJ_SCRYPT_BLOCK_WORDS;
		for (i = 0; i < nblocks; i++) {
			SJ_SCRYPT_WORD_ENDIAN_SWAP(blocks[i]);
		}
	}
#endif
}

static void
sj_scrypt_ROMix(sj_scrypt_mix_word_t *X/*[chunkWords]*/, sj_scrypt_mix_word_t *Y/*[chunkWords]*/, sj_scrypt_mix_word_t *V/*[N * chunkWords]*/, uint32_t N, uint32_t r) {
	uint32_t i, j, chunkWords = SJ_SCRYPT_BLOCK_WORDS * r * 2;
	sj_scrypt_mix_word_t *block = V;

	sj_scrypt_romix_convert_endian(X, r * 2);

	/* 1: X = B */
	/* implicit */

	/* 2: for i = 0 to N - 1 do */
	memcpy(block, X, chunkWords * sizeof(sj_scrypt_mix_word_t));
	for (i = 0; i < N - 1; i++, block += chunkWords) {
		/* 3: V_i = X */
		/* 4: X = H(X) */
		sj_scrypt_ChunkMix(block + chunkWords, block, NULL, r);
	}
	sj_scrypt_ChunkMix(X, block, NULL, r);

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 7: j = Integerify(X) % N */
		j = X[chunkWords - SJ_SCRYPT_BLOCK_WORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
		sj_scrypt_ChunkMix(Y, X, sj_scrypt_item(V, j, chunkWords), r);

		/* 7: j = Integerify(Y) % N */
		j = Y[chunkWords - SJ_SCRYPT_BLOCK_WORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
		sj_scrypt_ChunkMix(X, Y, sj_scrypt_item(V, j, chunkWords), r);
	}

	/* 10: B' = X */
	/* implicit */

	sj_scrypt_romix_convert_endian(X, r * 2);
}

#define SJ_SCRYPT_HASH "Keccak-512"
#define SJ_SCRYPT_HASH_DIGEST_SIZE 64
#define SJ_SCRYPT_KECCAK_F 1600
#define SJ_SCRYPT_KECCAK_C (SJ_SCRYPT_HASH_DIGEST_SIZE * 8 * 2) /* 256=512, 512=1024 */
#define SJ_SCRYPT_KECCAK_R (SJ_SCRYPT_KECCAK_F - SJ_SCRYPT_KECCAK_C) /* 256=1088, 512=576 */
#define SJ_SCRYPT_HASH_BLOCK_SIZE (SJ_SCRYPT_KECCAK_R / 8)

typedef uint8_t sj_scrypt_hash_digest[SJ_SCRYPT_HASH_DIGEST_SIZE];

typedef struct sj_scrypt_hash_state_t {
	uint64_t state[SJ_SCRYPT_KECCAK_F / 64];
	uint32_t leftover;
	uint8_t buffer[SJ_SCRYPT_HASH_BLOCK_SIZE];
} sj_scrypt_hash_state;

typedef struct sj_scrypt_hmac_state_t {
	sj_scrypt_hash_state inner, outer;
} sj_scrypt_hmac_state;

static const uint64_t sj_keccak_round_constants[24] = {
	0x0000000000000001ull, 0x0000000000008082ull,
	0x800000000000808aull, 0x8000000080008000ull,
	0x000000000000808bull, 0x0000000080000001ull,
	0x8000000080008081ull, 0x8000000000008009ull,
	0x000000000000008aull, 0x0000000000000088ull,
	0x0000000080008009ull, 0x000000008000000aull,
	0x000000008000808bull, 0x800000000000008bull,
	0x8000000000008089ull, 0x8000000000008003ull,
	0x8000000000008002ull, 0x8000000000000080ull,
	0x000000000000800aull, 0x800000008000000aull,
	0x8000000080008081ull, 0x8000000000008080ull,
	0x0000000080000001ull, 0x8000000080008008ull
};

static void
sj_keccak_block(sj_scrypt_hash_state *S, const uint8_t *in) {
	size_t i;
	uint64_t *s = S->state, t[5], u[5], v, w;

	/* absorb input */
	for (i = 0; i < SJ_SCRYPT_HASH_BLOCK_SIZE / 8; i++, in += 8)
		s[i] ^= SJ_U8TO64_LE(in);
	
	for (i = 0; i < 24; i++) {
		/* theta: c = a[0,i] ^ a[1,i] ^ .. a[4,i] */
		t[0] = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
		t[1] = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
		t[2] = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
		t[3] = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
		t[4] = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];

		/* theta: d[i] = c[i+4] ^ rotl(c[i+1],1) */
		u[0] = t[4] ^ SJ_ROTL64(t[1], 1);
		u[1] = t[0] ^ SJ_ROTL64(t[2], 1);
		u[2] = t[1] ^ SJ_ROTL64(t[3], 1);
		u[3] = t[2] ^ SJ_ROTL64(t[4], 1);
		u[4] = t[3] ^ SJ_ROTL64(t[0], 1);

		/* theta: a[0,i], a[1,i], .. a[4,i] ^= d[i] */
		s[0] ^= u[0]; s[5] ^= u[0]; s[10] ^= u[0]; s[15] ^= u[0]; s[20] ^= u[0];
		s[1] ^= u[1]; s[6] ^= u[1]; s[11] ^= u[1]; s[16] ^= u[1]; s[21] ^= u[1];
		s[2] ^= u[2]; s[7] ^= u[2]; s[12] ^= u[2]; s[17] ^= u[2]; s[22] ^= u[2];
		s[3] ^= u[3]; s[8] ^= u[3]; s[13] ^= u[3]; s[18] ^= u[3]; s[23] ^= u[3];
		s[4] ^= u[4]; s[9] ^= u[4]; s[14] ^= u[4]; s[19] ^= u[4]; s[24] ^= u[4];

		/* rho pi: b[..] = rotl(a[..], ..) */
		v = s[ 1];
		s[ 1] = SJ_ROTL64(s[ 6], 44);
		s[ 6] = SJ_ROTL64(s[ 9], 20);
		s[ 9] = SJ_ROTL64(s[22], 61);
		s[22] = SJ_ROTL64(s[14], 39);
		s[14] = SJ_ROTL64(s[20], 18);
		s[20] = SJ_ROTL64(s[ 2], 62);
		s[ 2] = SJ_ROTL64(s[12], 43);
		s[12] = SJ_ROTL64(s[13], 25);
		s[13] = SJ_ROTL64(s[19],  8);
		s[19] = SJ_ROTL64(s[23], 56);
		s[23] = SJ_ROTL64(s[15], 41);
		s[15] = SJ_ROTL64(s[ 4], 27);
		s[ 4] = SJ_ROTL64(s[24], 14);
		s[24] = SJ_ROTL64(s[21],  2);
		s[21] = SJ_ROTL64(s[ 8], 55);
		s[ 8] = SJ_ROTL64(s[16], 45);
		s[16] = SJ_ROTL64(s[ 5], 36);
		s[ 5] = SJ_ROTL64(s[ 3], 28);
		s[ 3] = SJ_ROTL64(s[18], 21);
		s[18] = SJ_ROTL64(s[17], 15);
		s[17] = SJ_ROTL64(s[11], 10);
		s[11] = SJ_ROTL64(s[ 7],  6);
		s[ 7] = SJ_ROTL64(s[10],  3);
		s[10] = SJ_ROTL64(    v,  1);

		/* chi: a[i,j] ^= ~b[i,j+1] & b[i,j+2] */
		v = s[ 0]; w = s[ 1]; s[ 0] ^= (~w) & s[ 2]; s[ 1] ^= (~s[ 2]) & s[ 3]; s[ 2] ^= (~s[ 3]) & s[ 4]; s[ 3] ^= (~s[ 4]) & v; s[ 4] ^= (~v) & w;
		v = s[ 5]; w = s[ 6]; s[ 5] ^= (~w) & s[ 7]; s[ 6] ^= (~s[ 7]) & s[ 8]; s[ 7] ^= (~s[ 8]) & s[ 9]; s[ 8] ^= (~s[ 9]) & v; s[ 9] ^= (~v) & w;
		v = s[10]; w = s[11]; s[10] ^= (~w) & s[12]; s[11] ^= (~s[12]) & s[13]; s[12] ^= (~s[13]) & s[14]; s[13] ^= (~s[14]) & v; s[14] ^= (~v) & w;
		v = s[15]; w = s[16]; s[15] ^= (~w) & s[17]; s[16] ^= (~s[17]) & s[18]; s[17] ^= (~s[18]) & s[19]; s[18] ^= (~s[19]) & v; s[19] ^= (~v) & w;
		v = s[20]; w = s[21]; s[20] ^= (~w) & s[22]; s[21] ^= (~s[22]) & s[23]; s[22] ^= (~s[23]) & s[24]; s[23] ^= (~s[24]) & v; s[24] ^= (~v) & w;

		/* iota: a[0,0] ^= round constant */
		s[0] ^= sj_keccak_round_constants[i];
	}
}

static void
sj_scrypt_hash_init(sj_scrypt_hash_state *S) {
	memset(S, 0, sizeof(*S));
}

static void
sj_scrypt_hash_update(sj_scrypt_hash_state *S, const uint8_t *in, size_t inlen) {
	size_t want;

	/* handle the previous data */
	if (S->leftover) {
		want = (SJ_SCRYPT_HASH_BLOCK_SIZE - S->leftover);
		want = (want < inlen) ? want : inlen;
		memcpy(S->buffer + S->leftover, in, want);
		S->leftover += (uint32_t)want;
		if (S->leftover < SJ_SCRYPT_HASH_BLOCK_SIZE)
			return;
		in += want;
		inlen -= want;
		sj_keccak_block(S, S->buffer);
	}

	/* handle the current data */
	while (inlen >= SJ_SCRYPT_HASH_BLOCK_SIZE) {
		sj_keccak_block(S, in);
		in += SJ_SCRYPT_HASH_BLOCK_SIZE;
		inlen -= SJ_SCRYPT_HASH_BLOCK_SIZE;
	}

	/* handle leftover data */
	S->leftover = (uint32_t)inlen;
	if (S->leftover)
		memcpy(S->buffer, in, S->leftover);
}

static void
sj_scrypt_hash_finish(sj_scrypt_hash_state *S, uint8_t *hash) {
	size_t i;

	S->buffer[S->leftover] = 0x01;
	memset(S->buffer + (S->leftover + 1), 0, SJ_SCRYPT_HASH_BLOCK_SIZE - (S->leftover + 1));
	S->buffer[SJ_SCRYPT_HASH_BLOCK_SIZE - 1] |= 0x80;
	sj_keccak_block(S, S->buffer);

	for (i = 0; i < SJ_SCRYPT_HASH_DIGEST_SIZE; i += 8) {
		SJ_U64TO8_LE(&hash[i], S->state[i / 8]);
	}
}

static void
sj_scrypt_hash(sj_scrypt_hash_digest hash, const uint8_t *m, size_t mlen) {
	sj_scrypt_hash_state st;
	sj_scrypt_hash_init(&st);
	sj_scrypt_hash_update(&st, m, mlen);
	sj_scrypt_hash_finish(&st, hash);
}

/* hmac */
static void
sj_scrypt_hmac_init(sj_scrypt_hmac_state *st, const uint8_t *key, size_t keylen) {
	uint8_t pad[SJ_SCRYPT_HASH_BLOCK_SIZE] = {0};
	size_t i;

	sj_scrypt_hash_init(&st->inner);
	sj_scrypt_hash_init(&st->outer);

	if (keylen <= SJ_SCRYPT_HASH_BLOCK_SIZE) {
		/* use the key directly if it's <= blocksize bytes */
		memcpy(pad, key, keylen);
	} else {
		/* if it's > blocksize bytes, hash it */
		sj_scrypt_hash(pad, key, keylen);
	}

	/* inner = (key ^ 0x36) */
	/* h(inner || ...) */
	for (i = 0; i < SJ_SCRYPT_HASH_BLOCK_SIZE; i++)
		pad[i] ^= 0x36;
	sj_scrypt_hash_update(&st->inner, pad, SJ_SCRYPT_HASH_BLOCK_SIZE);

	/* outer = (key ^ 0x5c) */
	/* h(outer || ...) */
	for (i = 0; i < SJ_SCRYPT_HASH_BLOCK_SIZE; i++)
		pad[i] ^= (0x5c ^ 0x36);
	sj_scrypt_hash_update(&st->outer, pad, SJ_SCRYPT_HASH_BLOCK_SIZE);
}

static void
sj_scrypt_hmac_update(sj_scrypt_hmac_state *st, const uint8_t *m, size_t mlen) {
	/* h(inner || m...) */
	sj_scrypt_hash_update(&st->inner, m, mlen);
}

static void
sj_scrypt_hmac_finish(sj_scrypt_hmac_state *st, sj_scrypt_hash_digest mac) {
	/* h(inner || m) */
	sj_scrypt_hash_digest innerhash;
	sj_scrypt_hash_finish(&st->inner, innerhash);

	/* h(outer || h(inner || m)) */
	sj_scrypt_hash_update(&st->outer, innerhash, sizeof(innerhash));
	sj_scrypt_hash_finish(&st->outer, mac);
}

static void
sj_scrypt_pbkdf2(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint8_t *out, size_t bytes) {
	sj_scrypt_hmac_state hmac_pw, hmac_pw_salt, work;
	sj_scrypt_hash_digest ti;
	uint8_t be[4];
	uint32_t i, blocks;
	
	/* bytes must be <= (0xffffffff - (SCRYPT_HASH_DIGEST_SIZE - 1)), which they will always be under scrypt */

	/* hmac(password, ...) */
	sj_scrypt_hmac_init(&hmac_pw, password, password_len);

	/* hmac(password, salt...) */
	hmac_pw_salt = hmac_pw;
	sj_scrypt_hmac_update(&hmac_pw_salt, salt, salt_len);

	blocks = ((uint32_t)bytes + (SJ_SCRYPT_HASH_DIGEST_SIZE - 1)) / SJ_SCRYPT_HASH_DIGEST_SIZE;
	for (i = 1; i <= blocks; i++) {
		/* U1 = hmac(password, salt || be(i)) */
		SJ_U32TO8_BE(be, i);
		work = hmac_pw_salt;
		sj_scrypt_hmac_update(&work, be, 4);
		sj_scrypt_hmac_finish(&work, ti);

		/* T[i] = U1 ^ U2 ^ U3... */
                
		memcpy(out, ti, (bytes > SJ_SCRYPT_HASH_DIGEST_SIZE) ? SJ_SCRYPT_HASH_DIGEST_SIZE : bytes);
		out += SJ_SCRYPT_HASH_DIGEST_SIZE;
		bytes -= SJ_SCRYPT_HASH_DIGEST_SIZE;
	}
}


static void
sj_scrypt(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint8_t Nfactor, uint8_t rfactor, uint8_t pfactor, uint8_t *out, size_t bytes) {
	sj_scrypt_aligned_alloc YX, V;
	uint8_t *X, *Y;
	uint32_t N, r, p, chunk_bytes;

	if (Nfactor > sj_scrypt_maxN)
		sj_scrypt_fatal_error("scrypt-jane: N out of range");
	if (rfactor > sj_scrypt_maxr)
		sj_scrypt_fatal_error("scrypt-jane: r out of range");
	if (pfactor > sj_scrypt_maxp)
		sj_scrypt_fatal_error("scrypt-jane: p out of range");

	N = (1 << (Nfactor + 1));
	r = (1 << rfactor);
	p = (1 << pfactor);

	chunk_bytes = SJ_SCRYPT_BLOCK_BYTES * r * 2;
	V = sj_scrypt_alloc((uint64_t)N * chunk_bytes);
	YX = sj_scrypt_alloc((p + 1) * chunk_bytes);

	/* 1: X = PBKDF2(password, salt) */
	Y = YX.ptr;
	X = Y + chunk_bytes;
        sj_scrypt_pbkdf2(password, password_len, salt, salt_len, X, chunk_bytes);

	/* 2: X = ROMix(X) */
	sj_scrypt_ROMix((sj_scrypt_mix_word_t *)X, (sj_scrypt_mix_word_t *)Y, (sj_scrypt_mix_word_t *)V.ptr, N, 1);

	/* 3: Out = PBKDF2(password, X) */
	sj_scrypt_pbkdf2(password, password_len, X, chunk_bytes, out, bytes);

	sj_scrypt_free(&V);
	sj_scrypt_free(&YX);
}

/* Used externally as confirmation of correct OCL code */
int sj_scrypt_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
	uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	uint32_t data[20], ohash[8];

	sj_be32enc_vect(data, (const uint32_t *)pdata, 19);
	data[19] = nonce;
    
        int nfactor = sj_GetNfactor(data[17]);
        
        applog(LOG_DEBUG, "Dat0: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
            data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
    
        sj_scrypt((unsigned char *)data, 80, 
                       (unsigned char *)data, 80, 
                       nfactor, 0, 0, (unsigned char *)ohash, 32);
    
        uint32_t *o = ohash;
	applog(LOG_DEBUG, "Nonce: %x, Output buffe0: %x %x %x %x %x %x %x %x", nonce, o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]);
    
	tmp_hash7 = ohash[7];

	applog(LOG_DEBUG, "Nonce %x harget %08lx diff1 %08lx hash %08lx",
                                nonce,
				(long unsigned int)Htarg,
				(long unsigned int)sj_diff1targ,
				(long unsigned int)tmp_hash7);
	if (tmp_hash7 > sj_diff1targ)
		return -1;
	if (tmp_hash7 > Htarg)
		return 0;
	return 1;
}

