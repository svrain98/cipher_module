#include <stdio.h>
#include "gmp.h"
#include "KISA_SHA256.h"


#define RSA2048_EM_BYTE_LEN  256;
#define USE_CRT


typedef struct _RSA_PUBKEY_
{
	int   RSA_SIZE;
	mpz_t n;
	mpz_t e;
}RSA_PUBKEY;

typedef struct _RSA_PRIKEY_
{
	int   RSA_SIZE;
	mpz_t n;
	mpz_t e;
	mpz_t p;
	mpz_t q;
	mpz_t d;
#ifdef USE_CRT
	mpz_t dp;
	mpz_t dq;
	mpz_t qinv;
#endif

}RSA_PRIKEY;
void RSA_KEY_init(RSA_PUBKEY *pub, RSA_PRIKEY *pri);
int  RSA_KEY_gen(RSA_PUBKEY *pub, RSA_PRIKEY *pri, int RSA_SIZE);
void RSA_KEY_clear(RSA_PUBKEY *pub, RSA_PRIKEY *pri);

void RSA_enc_primitive(mpz_t c, mpz_t m, RSA_PUBKEY *pub);
void RSA_dec_primitive(mpz_t m, mpz_t c, RSA_PRIKEY *pri);

void mpz_mul_mod(mpz_t rop, mpz_t a, mpz_t b, mpz_t n);
void mpz_sub_mod(mpz_t rop, mpz_t a, mpz_t b, mpz_t n);
void mpz_add_mod(mpz_t rop, mpz_t a, mpz_t b, mpz_t n);
    
int  RSA_PKCS1_SHA256_MGF(unsigned char *mask, int masklen, unsigned char *mgfseed, int mgfseedlen);


int RSA_PKCS1_RSA2048_SHA256_OAEP_encode(unsigned char *EM, int EM_len,
										unsigned char *M, int M_len,
										unsigned char *L, int L_len,
										unsigned char *S, int S_len);


int RSA_PKCS1_RSA2048_SHA256_OAEP_decode(unsigned char *EM, int EM_len,
											unsigned char *M, int *M_len,
											unsigned char *L, int L_len);

int mpz_msb_bit_scan(const mpz_t a); int ostr2mpz(mpz_t a, const unsigned char *ostr, const int ostrlen); 
int mpz2ostr(unsigned char *ostr, int *ostrlen, const mpz_t a);
int RSA_RSA2048_SHA256_OAEP_enc(unsigned char *C, int *C_len, unsigned char *M, int M_len,
								unsigned char *L, int L_len, RSA_PUBKEY *pub);
int RSA_RSA2048_SHA256_OAEP_dec(unsigned char *M, int *M_len, unsigned char *C, int C_len,
								unsigned char *L, int L_len, RSA_PRIKEY *pri);
int RSA_EMSA_PSS_encode(unsigned char *EM, int EM_len, unsigned char *M, int M_len, unsigned char *Salt, int Salt_len);
//입력 : EM, EM_len, M, M_len//출력 : T/F
int RSA_EMSA_PSS_decode(unsigned char *EM, int EM_len, unsigned char *M, int M_len);

//입력 : pri, M, M_len//출력 : S, S_len

int RSA_RSA2048_SHA256_PSS_sign(unsigned char *S, int *S_len, unsigned char *M, int M_len, RSA_PRIKEY *pri);


//입력 : pub, M, M_len, S_len//출력 : T/F

int RSA_RSA2048_SHA256_PSS_verify(unsigned char *M, int M_len, unsigned char *S, int S_len, RSA_PUBKEY *pub);