#include "sha256.h"

#ifdef USE_SHA256

static void uint32_to_uint8(uint8 *output, const uint32 *input, const size_t len)
{
	for(size_t i = 0, j = 0; j < len; i++, j += 4) 
		for (int k = 0; k < 4; k++)
			output[j + k] = (uint8)(input[i] >> (24 - 8 * k) & 0xFF);
}

static void uint8_to_uint32(uint32 *output, const uint8 *input, const size_t len)
{
	for(size_t i = 0, j = 0; j < len; i++, j += 4)
	{ 
		output[i] = 0;
		for (int k = 0; k < 4; k++)
			output[i] |= ((uint64)input[j + k]) << (24 - 8 * k);
	}
}

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define F0(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define F1(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define G0(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHR(x,  3))
#define G1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

static const uint32 Key_out[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void SHA256_compress(SHA256_CTX *ctx)
{
	uint32 W[64], M[16], a, b, c, d, e, f, g, h, T1, T2;
	//printf("==============================================================\nBlock Contents:\n");

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];
	uint8_to_uint32(M, ctx->buf, 64);

	for (int i = 0; i < 64; i++)
	{
		if (i < 16)
		{
			W[i] = M[i];
			//printf("M[%d] = %08X\n", i, W[i]);
		}
		else
			W[i] = G1(W[i-2]) + W[i-7] + G0(W[i-15]) + W[i-16];
        T1 = h + F1(e) + CH(e, f, g) + Key_out[i] + W[i];
		T2 = F0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
	ctx->curlen = 0;

	return ;
}

int SHA256_Init(SHA256_CTX *ctx)
{
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	ctx->length[0] = 0;
	ctx->length[1] = 0;
	ctx->curlen = 0;
	memset(ctx->buf, 0, 64);
	/*
	printf("==============================================================\nInitial hash value:\n");
	for (int i = 0; i < 8; i++)
		printf("H[%d] = %08X\n", i, ctx->state[i]);
	*/
	return 1;
}

int SHA256_Update(SHA256_CTX *ctx, const unsigned char *data, size_t len)
{
	size_t n;
	ctx->length[0] += len >> 29;
	ctx->length[1] += len << 3;	
	if (ctx->length[1] < (len << 3))
		ctx->length[0]++;

	while (len > 0)
	{
		n = MIN(len, (64 - ctx->curlen));
		memcpy(ctx->buf + ctx->curlen, data, n);
		ctx->curlen += n;
		data += n;
		len -= n;

		if (ctx->curlen == 64)
			SHA256_compress(ctx);
	}
	return 1;
}

int SHA256_Final(unsigned char *md, SHA256_CTX *ctx)
{
	uint8 length[8];
	const uint8 PAD[64] = { 0x80 };

	uint32_to_uint8(length, ctx->length, 8);
	memcpy(ctx->buf + ctx->curlen, PAD, 64 - ctx->curlen);
	if (ctx->curlen >= 56)
	{		
		SHA256_compress(ctx);
		memset(ctx->buf, 0, 56);
	}	
	memcpy(ctx->buf + 56, length, 8);
	SHA256_compress(ctx);
	uint32_to_uint8(md, ctx->state, SHA256_DIGEST_SIZE);

	return 1;
}

unsigned char *SHA256(unsigned char *md, const unsigned char *data, size_t len)
{
	SHA256_CTX ctx;
	if (!SHA256_Init(&ctx))
		return NULL;
	if (!SHA256_Update(&ctx, data, len))
		return NULL;
	if (!SHA256_Final(md, &ctx))
		return NULL;
	return md;
}

void SHA256_KDF(unsigned char  *Z, unsigned short input_len, unsigned short K_out_byte_len, unsigned char *Key_out)
{
	unsigned short i, j, t;
	unsigned int bitklen;
	SHA256_CTX md;
	unsigned char Ha[SHA256_len / 8];
	unsigned char ct[4] = { 0,0,0,1 };
    bitklen = K_out_byte_len * 8;
    //set number of output blocks
	if (bitklen%SHA256_len)
		t = bitklen / SHA256_len + 1;
	else
		t = bitklen / SHA256_len;
    //s4: Key_out=Ha1||Ha2||...
	for (i = 1; i<t; i++)
	{
		//s2: Hai=Hv(Z||ct)
		SHA256_Init(&md);
        SHA256_Update(&md, Z, input_len);
		SHA256_Update(&md, ct, 4);
		SHA256_Final(Ha, &md);
        memcpy((Key_out + (SHA256_len / 8)*(i - 1)), Ha, SHA256_len / 8);
		if (ct[3] == 0xff)
		{
			ct[3] = 0;
			if (ct[2] == 0xff)
			{
				ct[2] = 0;
				if (ct[1] == 0xff)
				{
					ct[1] = 0;
					ct[0]++;
				}
				else ct[1]++;
			}
			else ct[2]++;
		}
		else ct[3]++;
	}
    //s3: K_out_byte_len/v proccessing part block?
	SHA256_Init(&md);
    SHA256_Update(&md, Z, input_len);
	SHA256_Update(&md, ct, 4);
	SHA256_Final(Ha, &md);
	if (bitklen%SHA256_len)
	{
		i = (SHA256_len - bitklen + SHA256_len * (bitklen / SHA256_len)) / 8;
		j = (bitklen - SHA256_len * (bitklen / SHA256_len)) / 8;
        memcpy((Key_out + (SHA256_len / 8)*(t - 1)), Ha, j);
	}
	else
	{
        memcpy((Key_out + (SHA256_len / 8)*(t - 1)), Ha, SHA256_len / 8);
	}
}

#endif/* USE_SHA256 */
