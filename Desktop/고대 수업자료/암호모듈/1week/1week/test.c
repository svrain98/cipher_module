#include "KISA_SHA256.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "gmp.h"
#include "RSA.h"


clock_t elapsed; 
float sec;
#define START_WATCH \
{\
 elapsed = -clock(); \
}\

#define STOP_WATCH \
{\
 elapsed += clock();\
 sec = (float)elapsed/CLOCKS_PER_SEC;\
}\

#define PRINT_TIME(qstr) \
{\
 printf("\n[%s: %.5f s]\n",qstr,sec);\
}\



void test_sha256() {

	BYTE pszMessage[20] = "abc";
	UINT uPlainTextLen = 3;
	BYTE pszDigest[SHA256_DIGEST_VALUELEN];

	SHA256_Encrpyt(pszMessage, uPlainTextLen, pszDigest);

	for (int i = 0; i < SHA256_DIGEST_VALUELEN; i++) {
		printf("%02X", pszDigest[i]);
	}
}

void test_gmp() {

	mpz_t p, e, d, m, c, out;
	gmp_randstate_t state;

	mpz_init(p);
	mpz_init(e);
	mpz_init(d);
	mpz_init(m);
	mpz_init(c);
	mpz_init(out);
	gmp_randinit_default(state);

	//1
	mpz_urandomb(p, state, 1024);
	p->_mp_d[0] = p->_mp_d[0] | 1;
	while (!mpz_probab_prime_p(p, 56)) {

		mpz_urandomb(p, state, 1024);
		p->_mp_d[0] = p->_mp_d[0] | 1;

	}

	//2
	mpz_set(e, 0x10001);

	//3
	mpz_sub_ui(m, p, 1);
	mpz_invert(d, e, m);

	//4
	mpz_urandomb(m, state, 512);

	//5
	mpz_powm(c, m, e, p);

	//6
	mpz_powm(out, c, d, p);

	//7
	gmp_printf("%Zx\n", m);
	gmp_printf("%Zx\n", out);

	printf("%d\n", mpz_cmp(m, out));

	//gmp_printf("p = %Zx\n", p);

	mpz_clear(p);
	mpz_clear(e);
	mpz_clear(d);
	mpz_clear(m);
	mpz_clear(c);
	mpz_clear(out);
	gmp_randclear(state);

}
// a,b,>=0, a>=b
void __mpz_add_new(mpz_t c, mpz_t a, mpz_t b)
{
	int   i, carry = 0;
	mpz_t out;

	mpz_init2(out, (mpz_size(a) + 1) << 5);

	for (i = 0; i<mpz_size(b); i++)
	{
		if (carry) {
			out->_mp_d[i] = a->_mp_d[i] + b->_mp_d[i] + 1;
			carry = a->_mp_d[i] >= (~b->_mp_d[i]);
		}
		else {
			out->_mp_d[i] = a->_mp_d[i] + b->_mp_d[i];
			carry = out->_mp_d[i] < a->_mp_d[i];
		}
	}

	for (; i < mpz_size(a); i++)
	{
		out->_mp_d[i] = a->_mp_d[i] + carry;
		carry = out->_mp_d[i] < carry;
	}

	if (carry) {
		out->_mp_d[i] = 1;
		out->_mp_size = mpz_size(a) + 1;
	}
	else
		out->_mp_size = mpz_size(a);

	mpz_set(c, out);

	mpz_clear(out);
}

// a,b,>=0, a>=b
void __mpz_sub_new(mpz_t c, mpz_t a, mpz_t b)
{
	int   i, borrow = 0;
	mpz_t out;
		
	mpz_init2(out, (mpz_size(a)+1) << 5);
	if (mpz_sgn(a) == 0)
	{
		out->_mp_d[0] = 0;
		out->_mp_size = 0;
	}

	for (i = 0; i < mpz_size(b); i++)
	{
		if (borrow) {
			out->_mp_d[i] = a->_mp_d[i] - b->_mp_d[i] - 1;
			borrow = a->_mp_d[i]-borrow < b->_mp_d[i];
		}
		else {
			out->_mp_d[i] = a->_mp_d[i] - b->_mp_d[i];
			borrow = a->_mp_d[i] < b->_mp_d[i];
		}
	}
	if (mpz_size(a) > mpz_size(b)) {
		for (; i < mpz_size(a); i++)
		{
			out->_mp_d[i] = a->_mp_d[i] - borrow;
			borrow = a->_mp_d[i] < borrow;
		}
	}
	out->_mp_size = mpz_size(a);

	while (out->_mp_d[i-1] == 0) {
		out->_mp_size=(out->_mp_size)-1;
		i--;
	}
	mpz_set(c, out);

	mpz_clear(out);
}

// a,b, in Z
void mpz_add_new(mpz_t c, mpz_t a, mpz_t b)
{
	if (mpz_sgn(a) == mpz_sgn(b)) {
		//부호가 같은 경우
		if (mpz_size(a) >= mpz_size(b)) {
			__mpz_add_new(c, a, b);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
		else {
			__mpz_add_new(c, b, a);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
	}
	else {
		//부호가 다른 경우
		if (mpz_cmpabs(a, b) >= 0) {
			__mpz_sub_new(c, a, b);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
		else {
			__mpz_sub_new(c, b, a);
			c->_mp_size = c->_mp_size*mpz_sgn(b);
		}
	}

	return;
}

// a,b, in Z
void mpz_sub_new(mpz_t c, mpz_t a, mpz_t b)
{
	if (mpz_sgn(a) == 0) {
		mpz_set(c, b);
		c->_mp_size *= -1;
		return;
	}
	if (mpz_sgn(a) == mpz_sgn(b)) {
		//부호가 같은 경우
		if (mpz_cmpabs(a, b) >= 0) {
			__mpz_sub_new(c, a, b);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
		else {
			__mpz_sub_new(c, b, a);
			c->_mp_size = c->_mp_size*mpz_sgn(a)*-1;
		}
	}
	else {
		//부호가 다른 경우
		if ((mpz_size(a) >= mpz_size(b))) {
			__mpz_add_new(c, a, b);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
		else {
			__mpz_add_new(c, b, a);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
	}

	return;
}
void mpz_mul_new(mpz_t c, mpz_t a, mpz_t b)
{
	int i, j;
	mpz_t out;
	unsigned long long int carry = 0;

	mpz_init2(out, (mpz_size(a) + mpz_size(b) << 5) + 1);

	for (i = 0; i < out->_mp_alloc; i++) out->_mp_d[i] = 0;

	for (i = 0; i < mpz_size(b); i++) {
			carry = 0;
		for (j = 0; j < mpz_size(a); j++) {
			carry = (unsigned long long int)(b->_mp_d[i]) * (unsigned long long int)(a->_mp_d[j])
				+ (unsigned long long int)out->_mp_d[i + j]
				+ (unsigned long long int)(carry >> 32);
			out->_mp_d[i + j] = (unsigned int)carry;
		}
		out->_mp_d[i + j] = (unsigned int)((unsigned long long int)(carry >> 32));

	}
	out->_mp_size = (mpz_size(a) + mpz_size(b));
	if (out->_mp_d[out->_mp_size - 1] == 0) out->_mp_size--;
	out->_mp_size = (mpz_size(a) + mpz_size(b))*mpz_sgn(a)*mpz_sgn(b);

	mpz_set(c, out);
	mpz_clear(out);
}

void test_add_sub()
{
	int             i, cnt1 = 7, cnt2 = 7, cnt3 = 7;
	mpz_t           a, b, c, d;
	gmp_randstate_t state;


	mpz_init(a);
	mpz_init(b);
	mpz_init(c);
	mpz_init(d);
	gmp_randinit_default(state);
	for (i = 0; i < 1000; i++) {

		mpz_urandomb(a, state, 1024);
		a->_mp_size = a->_mp_d[0] & 0x1f;
		a->_mp_size = (a->_mp_d[0] & 0x1) ? (a->_mp_size) : (a->_mp_size * (-1));
		mpz_urandomb(b, state, 1024);
		b->_mp_size = b->_mp_d[0] & 0x1f;
		b->_mp_size = (b->_mp_d[0] & 0x1) ? (b->_mp_size) : (b->_mp_size * (-1));

		mpz_add(c, a, b);
		mpz_add_new(d, a, b);
		/*printf("%d\n", mpz_sgn(a));
		printf("%d\n", a->_mp_size);*/
		printf(" add: ");
		if (mpz_cmp(c, d)) {

			printf("false\n");
			cnt1++;
		}
		else {
			printf("true\n");
		}

		mpz_sub(c, a, b);
		mpz_sub_new(d, a, b);
		printf(" sub: ");
		if (mpz_cmp(c, d)) {
			printf("false\n");
			cnt2++;
		}
		else {
			printf("true\n");
		}
		mpz_mul(c, a, b);
		mpz_mul_new(d, a, b);
		printf(" mul: ");
		if (mpz_cmp(c, d)) {
			printf("false\n");
			cnt3++;
		}
		else {
			printf("true\n");
		}
	}
	printf("%d %d %d\n", cnt1, cnt2, cnt3);
	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(c);
	mpz_clear(d);
	gmp_randclear(state);
}

	
void test_cmp_speed() {
	int i;
	mpz_t           a, b,c,d,e;

	gmp_randstate_t state;
	gmp_randinit_default(state);


	mpz_init(a);
	mpz_init(b);
	mpz_init(c);
	mpz_init(d);
	mpz_init(e);

		mpz_urandomb(d, state, 4096);//mult 출력
	do {
		mpz_urandomb(a, state, 2048);
		mpz_urandomb(b, state, 2048);
		mpz_gcd(e, a, d);
	} while (mpz_cmp_si(e,1));//소수
	START_WATCH;
	for (i = 0; i < 100000; i++) mpz_add(c, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_add");

	START_WATCH;
	for (i = 0; i < 100000; i++) mpz_add_new(c, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_new_add");

	START_WATCH;
	for (i = 0; i < 100000; i++) mpz_sub(c, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_sub");

	START_WATCH;
	for (i = 0; i < 100000; i++) mpz_sub_new(c, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_new_sub");

	START_WATCH;
	for (i = 0; i < 100000; i++) mpz_mul(c, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_mul");

	START_WATCH;
	for (i = 0; i < 100000; i++) mpz_mul_new(c, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_new_mul");

	START_WATCH;
	for (i = 0; i < 100000; i++) mpz_mod(c, d, a);
	STOP_WATCH;
	PRINT_TIME("mod");

	START_WATCH;
	for (i = 0; i < 100000; i++) mpz_invert(c, a, b);
	STOP_WATCH;
	PRINT_TIME("invert");

	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(c);
	mpz_clear(d);
	mpz_clear(e);

}
void mpz_ltor_binary_powm(mpz_t c, mpz_t a, mpz_t e, mpz_t n) {
	int i, j;
	mpz_t out;
	mpz_init(out);
	mpz_set_ui(out, 1);
	for (i = mpz_size(e) - 1; i >= 0; i--) {
		for (j = 31; j >= 0; j--) {
			mpz_mul(out, out, out);
			mpz_mod(out, out, n);
			if ((e->_mp_d[i] >> j) & 1) {
				mpz_mul(out, out, a);
				mpz_mod(out, out, n);
			}
		}
	}

	mpz_set(c, out);
}
void ltor_test() {
	int i;
	mpz_t a, c, d, e, n;
	gmp_randstate_t state;

	mpz_init(a);
	mpz_init(c);
	mpz_init(d);
	mpz_init(e);
	mpz_init(n);
	gmp_randinit_default(state);


	for (i = 0; i < 10; i++) {
		mpz_urandomb(n, state, 2048);
		mpz_urandomm(a, state, n);
		mpz_urandomb(e, state, 2048);
		mpz_powm(c, a, e, n);
		mpz_ltor_binary_powm(d, a, e, n);


		if (mpz_cmp(c, d)) {
			printf("false\n");
		}
		else printf("true\n");
	}

	START_WATCH;
	for (i = 0; i < 100; i++) {
		mpz_powm(c, a, e, n);
	}
	STOP_WATCH;
	PRINT_TIME("mpz_powm");

	START_WATCH;
	for (i = 0; i < 100; i++) {
		mpz_ltor_binary_powm(c, a, e, n);
	}
	STOP_WATCH;
	PRINT_TIME("mpz_ltor_binary_powm");

	mpz_clear(a);
	mpz_clear(c);
	mpz_clear(d);
	mpz_clear(e);
	mpz_clear(n);
	gmp_randclear(state);

}
void RSA_test() {
	
	int RSA_SIZE;
	mpz_t m,mp,c;
	RSA_PUBKEY pub;
	RSA_PRIKEY pri;
	gmp_randstate_t state;
	mpz_init(m);
	mpz_init(mp);
	mpz_init(c);
	gmp_randinit_default(state);
	RSA_KEY_init(&pub, &pri);
	RSA_KEY_gen(&pub,&pri,2048);

	for (int i = 0; i < 100; i++) {
		mpz_urandomm(m, state, pub.n);
		mpz_powm(c, m, pub.e, pub.n);
		mpz_powm(mp, c, pri.d, pri.n);
		if (!mpz_cmp(m, mp))
			printf("pass");
		else
			printf("false");
	}
	RSA_KEY_clear(&pub, &pri);

	mpz_clear(m);
	mpz_clear(mp);
	mpz_clear(c);
	gmp_randclear(state);



}

void enc_dec_speed_test()
{
	mpz_t m, tmp, c, c1;
	RSA_PUBKEY pub;
	RSA_PRIKEY pri;
	RSA_KEY_init(&pub, &pri);
	mpz_init(m);
	mpz_init(c);
	mpz_init(c1);
	mpz_init(tmp);
	gmp_randstate_t state;
	gmp_randinit_default(state);
	RSA_KEY_gen(&pub, &pri, 2048);
	mpz_urandomm(m, state, pub.n);
	START_WATCH;
	for (int i = 0; i < 100; i++)
		RSA_enc_primitive(c, m, &pub);
	STOP_WATCH;
	PRINT_TIME("RSA_enc_primitive");
	START_WATCH;
	for (int i = 0; i < 100; i++)
		mpz_powm(c, m, pub.e, pub.n);
	STOP_WATCH;
	PRINT_TIME("mpz_powm_pub");
	START_WATCH;
	for (int i = 0; i < 100; i++)
		RSA_dec_primitive(tmp, c, &pri);
	STOP_WATCH;
	PRINT_TIME("RSA_dec_primitive");
	START_WATCH;
	for (int i = 0; i < 100; i++)
		mpz_powm(tmp, c, pri.d, pri.n);
	STOP_WATCH;
	PRINT_TIME("mpz_powm_pri");
	if (mpz_cmp(tmp, m) == 0)
		printf("RIGHT\n");
	RSA_KEY_clear(&pub, &pri);
	mpz_clear(m);
	mpz_clear(c);
	mpz_clear(tmp);
}
void test_oaep_en_de() {
	unsigned char EM[1000] = { 0, };
	int EM_len = 256;
	unsigned char M[100] = { 1,2,3,4,5, }, RES[100] = { 0, };
	int M_len = 6, RES_len;
	unsigned char L[100] = { 0, };
	int L_len = 50;
	unsigned char S[100] = { 0, };
	int S_len = SHA256_DIGEST_VALUELEN;
	int i;


	if (RSA_PKCS1_RSA2048_SHA256_OAEP_encode(&EM, EM_len, &M, M_len, &L, L_len, &S, S_len) != 0)
		printf("\nerror1\n");
	printf("\nEM= ");
	for (i = 0; i < EM_len; i++)
		printf("%02X", EM[i]);
	if (RSA_PKCS1_RSA2048_SHA256_OAEP_decode(&EM, EM_len, &RES, &RES_len, &L, L_len) !=0)
		printf("\nerror2\n");	
	if(M_len != RES_len)
		printf("\nerror3\n");
	for(i=0;i<M_len;i++)
		if(M[i]!=RES[i])
			printf("\nerror4\n");
	/*for (int i = 0; i < 2; i++) {
		printf("%02X", EM[i]);
	}
	/*printf("\n디비길이\n");
	for (int i = 2; i <2+S_len ; i++) {
		printf("%02X", EM[i]);
	}
	printf("\n디비\n");
	for (int i = 2+S_len; i < EM_len; i++) {
		printf("%02X", EM[i]);
	}*/
	printf("\n");
	printf("\nM= ");
	for (i = 0; i < M_len; i++)
		printf("%02X", M[i]);
	printf("\nEM= ");
	/*for (i = 0; i < EM_len; i++)
		printf("%02X", EM[i]);*/
	printf("\nRES= ");
	for (i = 0; i < RES_len; i++)
		printf("%02X", RES[i]);

}
void test_mpz_oaep_ende()
{
	RSA_PUBKEY pub;
	RSA_PRIKEY pri;
	int RSA_SIZE = 2048;
	RSA_KEY_init(&pub, &pri);
	RSA_KEY_gen(&pub, &pri, RSA_SIZE);
	unsigned char M[100] = { 1,2,3,4,5,6,7,};
	unsigned char L[100] = { 0, };
	int L_len = 50;
	unsigned char S[100] = { 0, };
	int S_len = SHA256_DIGEST_VALUELEN;
	unsigned char C[1000] = { 0, };
	int C_len = 256;
	int M_len = 7;
	/*gmp_randstate_t state;
	gmp_randinit_default(state);
	mpz_t tmp;
	mpz_init(tmp);
	mpz_urandomb(tmp, state, 100 << 3);
	mpz(M, &M_len, tmp);*/
	printf("M=");
	for(int i=0;i<M_len;i++)
		printf("%02X", M[i]);
	printf("\nC="); 
	START_WATCH;
	RSA_RSA2048_SHA256_OAEP_enc(&C, &C_len, &M, M_len, &L, L_len, &pub);
	for (int i = 0; i < C_len; i++)
		printf("%02X", C[i]);
	STOP_WATCH;
	PRINT_TIME("en_time=");
	printf("\nRES=");
	START_WATCH;
	RSA_RSA2048_SHA256_OAEP_dec(&M, &M_len, &C, C_len, &L, L_len, &pri);
	for (int i = 0; i < M_len; i++)
		printf("%02X", M[i]);
	STOP_WATCH;
	PRINT_TIME("dec_time=");

	/*mpz_clear(tmp);
	gmp_randclear(state);*/
	RSA_KEY_clear(&pub,&pri);
}
void test_pss_ec() {
	unsigned char M[256] = "RSA_PSS_ENCODE_TEST_MESSAGE";
	unsigned char Salt[256] = { 0, };
	unsigned char mp[256] = { 0, };
	unsigned char H[256] = { 0x7f, 0x41, 0xe9, 0xd6, 0x86, 0xf4, 0x70, 0xe5, 0x8d, 0x37, 0x34, 0xd6, 0xf5, 0x7e, 0x82, 0x37, 0x98, 0x0a, 0x95, 0xb1, 0xb8, 0xab, 0x6e, 0x4b, 0x74, 0x7d, 0x9b, 0xca, 0xe4, 0xde, 0x77, 0xd2, 0, };
	int mp_len, Salt_len, H_len, M_len;
	int i;
	/******input*********/  
	M_len = strlen(M);
	Salt_len = SHA256_DIGEST_VALUELEN; 
	H_len = SHA256_DIGEST_VALUELEN;
	/******input*********/
	SHA256_Encrpyt(M, M_len, &mp[8]);

	if (Salt_len != H_len)
		return -1;

	mp_len = (H_len << 1) + 8;
	for (int i = 0; i < Salt_len; i++) {
		mp[100 - Salt_len + i] = Salt[i];

	}
	SHA256_Encrpyt(mp, mp_len, H);
	printf("M=");
	for (i = 0; i < M_len; i++)
		printf("0x%02x, ", M[i]);
	printf("\n");
	printf("\n");

	printf("Salt=");
	for (i = 0; i < Salt_len; i++)
		printf("0x%02x, ", Salt[i]);
	printf("\n");
	printf("\n");

	printf("mp=");
	for (i = 0; i < mp_len; i++)
		printf("0x%02x, ", mp[i]);
	printf("\n");
	printf("\n");

	printf("H=");
	for (i = 0; i < H_len; i++)
		printf("0x%02x, ", H[i]);
	printf("\n");


}
void test_pss() {
	unsigned char Salt[40] = { 1,2,3,4,5, };
	int Salt_len = 32;
	unsigned char M[20] = { 1,2,3,4,5, };
	int M_len = 5;
	unsigned char EM[256];
	int EM_len = 256;
	RSA_EMSA_PSS_encode(&EM, EM_len, &M, M_len, &Salt,Salt_len);
	if (RSA_EMSA_PSS_decode(&EM, EM_len, &M, M_len) == 0)
		printf("true\n");
	for (int i = 0; i < M_len; i++)
		printf("%d", M[i]);
}
void test_sign_verify() {
	unsigned char Salt[40] = { 1,2,3,4,5, };
	int Salt_len = 32;
	unsigned char M[20] = { 9,8,5,4,3, };
	int M_len = 5;
	unsigned char EM[256];
	int EM_len = 256;
	RSA_EMSA_PSS_encode(&EM, EM_len, &M, M_len, &Salt, Salt_len);
	int S_len = 256;
	unsigned char S[1000] = { 0, };
	RSA_PUBKEY pub;
	RSA_PRIKEY pri;
	RSA_KEY_init(&pub, &pri);
	RSA_KEY_gen(&pub, &pri, 2048);
	int k1=RSA_RSA2048_SHA256_PSS_sign(&S, &S_len, &EM, EM_len, &pri);
	int k2=RSA_RSA2048_SHA256_PSS_verify(&EM, EM_len, &S, S_len, &pub);
	if (RSA_EMSA_PSS_decode(&EM, EM_len, &M, M_len) == 0)
		printf("true1\n");
	if (k1 != k2)
		printf("false1\n");
}
void main(void)
{

	//test_sha256();
	//test_add_sub();
	//gmp_cmp();
	//test_cmp_speed();
	//ltor_test();
	//RSA_test();
	//enc_dec_speed_test();
	//test_oaep_en_de();
	//test_mpz_oaep_ende();
	//test_pss_ec();
	//test_pss();
	test_sign_verify();
	system("pause");

}