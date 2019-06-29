#include <string.h>
#include "RSA.h"


void mpz_add_mod(mpz_t rop, mpz_t a, mpz_t b, mpz_t n)
{
	mpz_add(rop, a, b);
	mpz_mod(rop, rop, n);
}
void mpz_sub_mod(mpz_t rop, mpz_t a, mpz_t b, mpz_t n)
{
	mpz_sub(rop, a, b);
	mpz_mod(rop, rop, n);
}
void mpz_mul_mod(mpz_t rop, mpz_t a, mpz_t b, mpz_t n)
{
	mpz_mul(rop, a, b);
	mpz_mod(rop, rop, n);
}

void RSA_KEY_init(RSA_PUBKEY *pub, RSA_PRIKEY *pri)
{
	// pubkey init
	mpz_init(pub->e);
	mpz_init(pub->n);
	pub->RSA_SIZE = 0;

	// prikey init
	mpz_init(pri->e);
	mpz_init(pri->n);
	mpz_init(pri->p);
	mpz_init(pri->q);
	mpz_init(pri->d);
	pri->RSA_SIZE = 0;
#ifdef USE_CRT
	mpz_init(pri->dp);
	mpz_init(pri->dq);
	mpz_init(pri->qinv);
#endif
}

int RSA_KEY_gen(RSA_PUBKEY *pub, RSA_PRIKEY *pri, int RSA_SIZE)
{
	int             mr_test;
	mpz_t           tmp;
	gmp_randstate_t state;

	if (!((RSA_SIZE == 2048) || (RSA_SIZE == 3072)))
		return -1;

	mpz_init(tmp);
	gmp_randinit_default(state);

	pri->RSA_SIZE = RSA_SIZE;

	// pri e
	mpz_set_ui(pri->e, 0x10001);
	//pri->e->_mp_d[0] = 0x10001;
	//pri->e->_mp_size = 1;

	// pri p
	while (mpz_size(pri->p) != 32)
		mpz_urandomb(pri->p, state, (RSA_SIZE >> 1));
	while (1)
	{
		pri->p->_mp_d[0] = pri->p->_mp_d[0] & 0xfffffffe;
		pri->p->_mp_d[31] = pri->p->_mp_d[31] | 0x80000000;
		mpz_gcd(tmp, pri->e, pri->p);

		if ((tmp->_mp_d[0] == 1) && (tmp->_mp_size == 1))
		{
			pri->p->_mp_d[0] = pri->p->_mp_d[0] | 1;
			if (mpz_probab_prime_p(pri->p, 56))
				break;
		}
		mpz_add_ui(pri->p, pri->p, 2);
		if (mpz_size(pri->p) > 32) {
			while (mpz_size(pri->p) != 32)
				mpz_urandomb(pri->p, state, (RSA_SIZE >> 1));
		}
	}


	// pri q
	while (mpz_size(pri->q) != 32)
		mpz_urandomb(pri->q, state, (RSA_SIZE >> 1));
	while (1)
	{
		pri->q->_mp_d[0] = pri->q->_mp_d[0] & 0xfffffffe;
		pri->q->_mp_d[31] = pri->q->_mp_d[31] | 0x80000000;
		mpz_gcd(tmp, pri->e, pri->q);

		if ((tmp->_mp_d[0] == 1) && (tmp->_mp_size == 1))
		{
			pri->q->_mp_d[0] = pri->q->_mp_d[0] | 1;
			if (mpz_probab_prime_p(pri->q, 56))
				break;
		}
		mpz_add_ui(pri->q, pri->q, 2);
		if (mpz_size(pri->q) > 32) {
			while (mpz_size(pri->q) != 32)
				mpz_urandomb(pri->q, state, (RSA_SIZE >> 1));
		}
	}
	// pri n
	mpz_mul(pri->n, pri->p, pri->q);

	// pri d
	pri->p->_mp_d[0] = pri->p->_mp_d[0] & 0xfffffffe;
	pri->q->_mp_d[0] = pri->q->_mp_d[0] & 0xfffffffe;
	mpz_mul(tmp, pri->p, pri->q);
	pri->p->_mp_d[0] = pri->p->_mp_d[0] | 1;
	pri->q->_mp_d[0] = pri->q->_mp_d[0] | 1;
	mpz_invert(pri->d, pri->e, tmp);

#ifdef USE_CRT
	//dp 생성
	pri->p->_mp_d[0] &= 0xfffffffe;
	pri->q->_mp_d[0] &= 0xfffffffe;
	mpz_mod(pri->dp, pri->d, pri->p);
	//dq 계산
	mpz_mod(pri->dq, pri->d, pri->q);
	pri->p->_mp_d[0] |= 0x00000001;
	pri->q->_mp_d[0] |= 0x00000001;
	//qinv 계산
	mpz_invert(pri->qinv, pri->q, pri->p);
#endif


	// pub e
	mpz_set(pub->e, pri->e);
	// pub n
	mpz_set(pub->n, pri->n);
	pub->RSA_SIZE = pri->RSA_SIZE;

	mpz_clear(tmp);
	gmp_randclear(state);
}

void RSA_KEY_clear(RSA_PUBKEY *pub, RSA_PRIKEY *pri)
{

	memset(pub->e->_mp_d, 0, (mpz_size(pub->e) << 2));
	memset(pub->n->_mp_d, 0, (mpz_size(pub->n) << 2));

	memset(pri->e->_mp_d, 0, (mpz_size(pri->e) << 2));
	memset(pri->n->_mp_d, 0, (mpz_size(pri->n) << 2));
	memset(pri->p->_mp_d, 0, (mpz_size(pri->p) << 2));
	memset(pri->q->_mp_d, 0, (mpz_size(pri->q) << 2));
	memset(pri->d->_mp_d, 0, (mpz_size(pri->d) << 2));

	// pubkey clear
	mpz_clear(pub->e);
	mpz_clear(pub->n);
	pub->RSA_SIZE = 0;

	// prikey clear
	mpz_clear(pri->e);
	mpz_clear(pri->n);
	mpz_clear(pri->p);
	mpz_clear(pri->q);
	mpz_clear(pri->d);
	pri->RSA_SIZE = 0;

#ifdef USE_CRT
	mpz_clear(pri->dp);
	mpz_clear(pri->dq);
	mpz_clear(pri->qinv);
#endif
}



void RSA_enc_primitive(mpz_t c, mpz_t m, RSA_PUBKEY *pub)
{
	// m^e mod n = c
	mpz_t key;
	mpz_t in_2;
	mpz_init(in_2);
	mpz_init(key);
	mpz_set(in_2, m);
	mpz_set_si(key, 0x10001);
	if ((pub->e->_mp_size == 1) && (pub->e->_mp_d[0] == 0x10001)) {
		//e = 2^16 + 1
		for (int i = 0; i < 16; i++)
		{
			mpz_mul_mod(in_2, in_2, in_2, pub->n);
		}
		mpz_mul_mod(c, in_2, m, pub->n);
	}
	else {
		mpz_powm(c, m, pub->e, pub->n);
	}
	mpz_clear(key);
	mpz_clear(in_2);
}

void RSA_dec_primitive(mpz_t m, mpz_t c, RSA_PRIKEY *pri)
{
	// c^d mod n = m
#ifdef USE_CRT
	//garner crt
	mpz_t x, y;
	mpz_init(x);
	mpz_init(y);
	mpz_mod(x, c, pri->p);
	mpz_powm(x, x, pri->dp, pri->p);
	mpz_mod(y, c, pri->q);
	mpz_powm(y, y, pri->dq, pri->q);
	mpz_sub_mod(m, x, y, pri->n);
	mpz_mul_mod(m, m, pri->qinv, pri->n);
	mpz_mul_mod(m, m, pri->q, pri->n);
	mpz_add_mod(m, m, y, pri->n);
	mpz_clear(x);
	mpz_clear(y);

#else
	mpz_powm(m, c, pri->d, pri->n);
#endif
}

int RSA_PKCS1_SHA256_MGF(unsigned char *mask, int masklen, unsigned char *mgfseed, int mgfseedlen) {
	int           hlen, looplen;
	unsigned int  counter;
	unsigned char *T, *tmgf;

	hlen = SHA256_DIGEST_VALUELEN;

	looplen = (masklen / hlen) + ((masklen%hlen) != 0);

	//masklen이 int형이므로 2^32를 넘어갈 수가 없음. 그래서 생략됨

	T = (unsigned char*)calloc(1, (looplen*hlen) + 8);
	tmgf = (unsigned char*)calloc(1, (mgfseedlen + 4) + 8);
	memcpy(tmgf, mgfseed, mgfseedlen);

	for (counter = 0; counter < (unsigned long)looplen; counter++) {
		tmgf[mgfseedlen] = (unsigned char)(counter >> 24);
		tmgf[mgfseedlen + 1] = (unsigned char)((counter >> 16) & 0xff);
		tmgf[mgfseedlen + 2] = (unsigned char)((counter >> 8) & 0xff);
		tmgf[mgfseedlen + 3] = (unsigned char)(counter & 0xff);
		SHA256_Encrpyt(tmgf, mgfseedlen + 4, &T[counter*hlen]);
	}


	memcpy(mask, T, masklen);
	free(T);
	free(tmgf);

	return 0;
}



int RSA_PKCS1_RSA2048_SHA256_OAEP_encode(unsigned char *EM, int EM_len,
	unsigned char *M, int M_len,
	unsigned char *L, int L_len,
	unsigned char *S, int S_len)
{
	unsigned char *DB;
	unsigned char *tmp;
	unsigned char *mgf1, *mgf2;
	int DB_len = EM_len - S_len - 1;
	DB = (unsigned char*)calloc(EM_len, 1);
	tmp = (unsigned char*)calloc(EM_len, 1);
	mgf1 = (unsigned char*)calloc(EM_len, 1);
	mgf2 = (unsigned char*)calloc(EM_len, 1);

	// 1. EM_LEN==?256, M_len<=?(256-64-2), S_len=32(?) 
	if (EM_len != 256)
		return -1;
	if (M_len > EM_len -(2* SHA256_DIGEST_VALUELEN) - 2)
		return -1;
	if (S_len != SHA256_DIGEST_VALUELEN)
		return -1;
	// 2. EM[0] = ?0
	EM[0] = 0;
	// 3. DB = LHash || PS || 0x01 || M
	SHA256_Encrpyt(L, L_len, DB);
	for (int i = L_len; i < DB_len - 1 - M_len; i++)
		DB[i] = 0x00;
	DB[DB_len - 1 - M_len] = 0x01;
	memcpy(DB + DB_len - M_len, M, M_len);
	RSA_PKCS1_SHA256_MGF(mgf1, DB_len, S, S_len);
	// 4. EM= 00 || maskedseed || maskedDB
		//4.1 maskedDB = DB ^ mgf(seed)
	for (int i = 0; i < DB_len; i++)
	{
		tmp[i] = mgf1[i] ^ DB[i];
		EM[EM_len - DB_len + i] = tmp[i];
	}
	//	printf("디비디비딥");
	/*for (int i = 0; i < DB_len; i++) {
		printf("%02x",tmp[i]);
	}*/
	RSA_PKCS1_SHA256_MGF(mgf2,S_len, tmp, DB_len);
		//4.2 maskedseed = seed ^ mgf(maskedDB)
	for (int i = 0; i < S_len; i++)
	{
		EM[EM_len - DB_len -S_len + i] = S[i] ^ mgf2[i];
		printf("%02x", EM[EM_len - DB_len - S_len + i]);
	}
	return 0;
	
}
//EM이 decode에서 변함
int RSA_PKCS1_RSA2048_SHA256_OAEP_decode(unsigned char *EM, int EM_len,
	unsigned char *M, int *M_len,
	unsigned char *L, int L_len)
{
	// 1. EM_LEN==?256, M_len<=?(256-64-2)
	int RSA_SIZE = 256, MAX_M_LEN = 190, H_LEN = SHA256_DIGEST_VALUELEN;
	int DB_LEN, i, j;
	unsigned char MASK[256];
	// 1. EM_LEN==?256, M_len<=?(256-64-2), S_len=32(?) 
	if (EM_len != RSA_SIZE)
	{
		return -1;
	}
	if (*M_len > EM_len - (2 * 32) - 2)
	{
		return -1;
	}
	// 2. EM= 00 || maskedseed || maskedDB, EM[0] = ?0
	if (EM[0] != 0)
	{
	
		return -1;
	}
	// 3. seed = maskedseed ^ mgf(maskedDB)
	DB_LEN = RSA_SIZE - H_LEN - 1;
	RSA_PKCS1_SHA256_MGF(MASK, H_LEN, &EM[H_LEN + 1], DB_LEN);
	for (i = 0; i < H_LEN; i++)
		EM[1 + i] = MASK[i] ^ EM[i + 1];
	// 4. DB = maskedDB ^ mgf(seed)
	RSA_PKCS1_SHA256_MGF(MASK, DB_LEN, &EM[1], H_LEN);
	for (i = 0; i < DB_LEN; i++)
		EM[1 + H_LEN + i] = MASK[i] ^ EM[1 + H_LEN + i];
	// 5. DB = LHASH || PS || 0x01 || M
		//5.1 LHash=?Hash(Label)
	SHA256_Encrpyt(L, L_len, MASK);
	for (i = 0; i < H_LEN; i++)
		if (EM[1 + H_LEN+i] != MASK[i])
			return -1;

		//5.2 DB[32] => 0 or 1
	i = (H_LEN << 1) + 1;
	while ((i < RSA_SIZE) && (EM[i] == 0))
		i = i + 1;
	if (i > (RSA_SIZE - 1))
		return -1;

	if (EM[i] != 0x01)

		return -1;
		//5.3 M 복사
	j = i = i + 1;
	*M_len = RSA_SIZE - i;
	for (; i < RSA_SIZE; i++)
		M[i - j] = EM[i];

	for (i = 0; i < RSA_SIZE; i++)
		MASK[i] = 0;
	return 0;
}
int mpz_msb_bit_scan(const mpz_t a) 
{
	int i = 31, size; 
	size = a->_mp_size - 1;
	while ((i >= 0) && !(a->_mp_d[size] & (0x1 << i)))//a의 i번째와 1 and 연산 1이면 1 0이면 , 0이면 i-- 
		i--; 
	if (i<0) 
		return -1; 
	return ((size << 5) + i + 1); 
}

int mpz2ostr(unsigned char *ostr, int *ostrlen, const mpz_t a) {
	int i, bytelen;
	if ((a == 0) || (ostr == 0))
		return -1;
	if (a->_mp_size == 0) 
	{
		*ostrlen = 0; 
		return 0;
	}
	*ostrlen = (mpz_msb_bit_scan(a) + 7) >> 3;
	bytelen = *ostrlen - 1;
	for (i = 0; i < *ostrlen; i++)
	{
		ostr[i] = (a->_mp_d[(bytelen - i) >> 2] >> (((bytelen - i) & 0x3) << 3)) & 0xff; 
	}
	return 0;
}
int ostr2mpz(mpz_t a, const unsigned char *ostr, const int ostrlen) {
	int i, bytelen;
	if (ostrlen == 0)
	{
		a->_mp_size = 0;
		return 0; 
	}
	if ((a == 0) || (ostr == 0))
		return -1;
	bytelen = ostrlen - 1;
	a->_mp_size = (ostrlen + 3) >> 2;
	if (a->_mp_alloc < a->_mp_size)
		mpz_realloc2(a, (a->_mp_size << 5)); 
	memset((unsigned int *)a->_mp_d, 0, (a->_mp_size << 2)); 
	for (i = bytelen; i >= 0; i--)
	{
		a->_mp_d[(bytelen - i) >> 2] |= ((ostr[i]) << (((bytelen - i) & 0x3) << 3)); 
	}
	return 0;
}

int RSA_RSA2048_SHA256_OAEP_enc(unsigned char *C, int *C_len, unsigned char *M, 
								int M_len, unsigned char *L, int L_len, RSA_PUBKEY *pub) 
{ 
	//1. EM, SEED  변수 선언
	mpz_t SEED;
	mpz_t em;
	mpz_t c;
	mpz_init(em);
	mpz_init(c);
	mpz_init(SEED);
	unsigned char EM[1000] = { 0, };
	unsigned char S[100] = { 0, };
	int EM_len = (pub->RSA_SIZE)/8;
	int H_LEN = SHA256_DIGEST_VALUELEN;
	int S_len = H_LEN;
	int diff;
	int i;
	//2. SEED 생성 = urandomb(SEED,state,(H_LEN<<3))
	gmp_randstate_t state;
	gmp_randinit_default(state);
	mpz_urandomb(SEED, state, (H_LEN << 3));
	//3. mpz2ostr(S,S_LEN,SEED)
	diff = H_LEN - ((mpz_msb_bit_scan(SEED) + 7) >> 3);
	mpz2ostr(&S[diff], &S_len, SEED);
	//mpz2ostr(S, S_len, SEED);
	//4. RSA_PKCS1_RSA2048_SHA256_OAEP_encode(EM, EM_len,M,M_len,L, L_len,S,S_len);      //인코딩 실패시 에러
	if (RSA_PKCS1_RSA2048_SHA256_OAEP_encode(EM, EM_len, M, M_len, L, L_len, S, S_len) != 0)
		printf("error");
	//5. ostr2mpz(em,EM,EM_LEN);
	ostr2mpz(em, EM, EM_len);
	//6. RSA_enc_primitive(c, em, pub)
	RSA_enc_primitive(c, em, pub);
	//7. mpz2ostr(C,C_LEN,c)
	mpz2ostr(C, C_len, c);
	for (i = 0; i < SEED->_mp_size; i++) SEED->_mp_d[i] = 0;
	for (i = 0; i < c->_mp_size; i++) c->_mp_d[i] = 0;
	for (i = 0; i < em->_mp_size; i++) em->_mp_d[i] = 0;
	for (i = 0; i < EM_len; i++) EM[i] = 0;
	for (i = 0; i < S_len; i++) S[i] = 0;

	mpz_clear(em);
	mpz_clear(c);
	mpz_clear(SEED);
	gmp_randclear(state);
	return 0;
}
	int RSA_RSA2048_SHA256_OAEP_dec(unsigned char *M, int *M_len, unsigned char *C, 
									int C_len, unsigned char *L, int L_len, RSA_PRIKEY *pri)
{ 
	//1. EM 등  변수 선언
	int H_LEN = SHA256_DIGEST_VALUELEN;
	//1. EM 등  변수 선언
	unsigned char	EM[1000] = { 0, };
	int EM_len = 256;
	int S_len = H_LEN;
	int diff, i;
	mpz_t 	SEED;
	mpz_t	c;
	mpz_t	em;
	mpz_init(c);
	mpz_init(em);
	mpz_init(SEED);
	gmp_randstate_t state;
	gmp_randinit_default(state);
	//2. ostr2mpz(c,C,C_LEN);
	ostr2mpz(c, C, C_len);
	//3. RSA_dec_primitive(em,c,pri)
	RSA_dec_primitive(em, c, pri);
	//4. mpz2ostr(EM,EM_LEN,em)
	diff = 256 - ((mpz_msb_bit_scan(em) + 7) >> 3);
	mpz2ostr(&EM[diff], &EM_len, em);
		EM_len = 256;
	//5. RSA_PKCS1_RSA2048_SHA256_OAEP_decode(M, M_len, EM, EM_len,L, L_len);    // 실패시 에러
	if (RSA_PKCS1_RSA2048_SHA256_OAEP_decode(EM, EM_len, M,M_len,L, L_len)!=0)
		printf("error");
		//zero
	for (i = 0; i < SEED->_mp_size; i++) SEED->_mp_d[i] = 0;
	for (i = 0; i < c->_mp_size; i++) c->_mp_d[i] = 0;
	for (i = 0; i < em->_mp_size; i++) em->_mp_d[i] = 0;
	for (i = 0; i < EM_len; i++) EM[i] = 0;

	mpz_clear(em);
	mpz_clear(c);
	mpz_clear(SEED);
	gmp_randclear(state);
	return 0;
}
	//입력 : EM_len, M, M_len, Salt, Salt_len//출력 : EM

	int RSA_EMSA_PSS_encode(unsigned char *EM, int EM_len, unsigned char *M, int M_len, unsigned char *Salt, int Salt_len)
	{
		unsigned char *DB;
		unsigned char *mgf;
		unsigned char *mp;
		unsigned char *mH;
		unsigned char *H;
		int mH_len = 32;
		int H_len = 32;
		int DB_len = EM_len - 32 - 1;
		int mp_len = 72;
		DB = (unsigned char*)calloc(EM_len, 1);
		mgf = (unsigned char*)calloc(EM_len, 1);
		mp = (unsigned char*)calloc(EM_len, 1);
		mH = (unsigned char*)calloc(EM_len, 1);
		H = (unsigned char*)calloc(EM_len, 1);
		SHA256_Encrpyt(M, M_len, mH);
		if (EM_len != 256)
			return -1;
		for (int i = 0; i < 8; i++)
			mp[i] = 0;
		for (int i = 8; i < 40; i++) {
			mp[i] = mH[i - 8];
		}
		for (int i = 40; i < 72; i++)
			mp[i] = Salt[i - 40];
		SHA256_Encrpyt(mp, mp_len, H);
		RSA_PKCS1_SHA256_MGF(mgf, DB_len, H, H_len);
		for (int i = 0; i < EM_len - 72-2; i++)
			DB[i] = 0;
		for (int i = EM_len-72-2; i < EM_len-72-1; i++) {
			DB[i] = 1;
		}
		for (int i = EM_len - 72-1; i < 256 - 32 - 1; i++) {
			DB[i] = Salt[i - (EM_len-72-1)];
		}
		for (int i = 0; i < DB_len; i++) {
			EM[i] = DB[i] ^ mgf[i];
		}
		for (int i = DB_len; i < DB_len + 32; i++) {
			EM[i] = H[i - DB_len];
		}
		EM[EM_len - 1] = 0xbc;
		EM[0] = EM[0] & 0x7f;
	}

	//입력 : EM, EM_len, M, M_len//출력 : T/F

	int RSA_EMSA_PSS_decode(unsigned char *EM, int EM_len, unsigned char *M, int M_len)
	{
		unsigned char *mH;
		unsigned char *DB;
		unsigned char *mp;
		unsigned char *Salt;
		unsigned char *H;
		unsigned char *mgf;
		mgf = (unsigned char*)calloc(EM_len, 1);
		mH = (unsigned char*)calloc(EM_len, 1);
		DB = (unsigned char*)calloc(EM_len, 1);
		mp = (unsigned char*)calloc(EM_len, 1);
		Salt = (unsigned char*)calloc(EM_len, 1);
		H = (unsigned char*)calloc(EM_len, 1);

		int H_len = 32;
		int Salt_len = 32;
		int DB_len = EM_len - 32 - 1;
		int mH_len = 32;
		int mp_len = 72;
		SHA256_Encrpyt(M, M_len, mH);
		for (int i = 0; i < 32; i++)
			H[i] = EM[i + EM_len - 32 - 1];
		RSA_PKCS1_SHA256_MGF(mgf, DB_len, H,H_len);
		for (int i = 0; i < DB_len; i++)
			DB[i] = mgf[i] ^ EM[i];
		for (int i = 0; i < 32; i++)
			Salt[i] = DB[i + EM_len - 72 - 1];
		//mp만들기
		for (int i = 0; i < 8; i++)
			mp[i] = 0;
		for (int i = 8; i < 40; i++) {
			mp[i] = mH[i - 8];
		}
		for (int i = 40; i < 72; i++)
			mp[i] = Salt[i - 40];
		SHA256_Encrpyt(mp, mp_len, H);
		for (int i = 0; i < 32; i++) {
			if (EM[EM_len - 32 - 1+i] != H[i])
			{
				printf("%d:error1\n",i);
				return -1;
			}
		}
		DB[0] = DB[0] & 0x7f;
		for (int i = 0; i < EM_len - 72 - 2; i++) {
			if (DB[i] != 0)
			{
				printf("error2\n");
				return -1;
			}
		}
		if (DB[EM_len - 72 - 2] != 1)
		{
			printf("error3\n");
			return -1;
		}
		return 0;

	}
	int RSA_RSA2048_SHA256_PSS_sign(unsigned char *S, int *S_len, unsigned char *M, int M_len, RSA_PRIKEY *pri)
	{
		mpz_t m;
		mpz_t s;
		mpz_t salt;
		gmp_randstate_t state;
		mpz_init(m);
		mpz_init(s);
		mpz_init(salt);
		gmp_randinit_default(state);
		mpz_urandomb(salt, state, 256);
		printf("M: ");
		for (int i = 0; i < M_len; i++)
			printf("%d", M[i]);
		printf("\n");
		ostr2mpz(m, M, M_len);
		RSA_dec_primitive(s, m, pri);
		mpz2ostr(S, &S_len, s);
		mpz_clear(m);
		mpz_clear(s);
		printf("S: ");
		for (int i = 0; i < S_len; i++)
			printf("%d", S[i]);
		printf("\n");
		return 0;
	}
	int RSA_RSA2048_SHA256_PSS_verify(unsigned char *M, int M_len, unsigned char *S, int S_len, RSA_PUBKEY *pub)
	{
		mpz_t s;
		mpz_t m;
		mpz_init(m);
		mpz_init(s);
		ostr2mpz(s, S, S_len);
		RSA_enc_primitive(m, s, pub);
		mpz2ostr(M, &M_len, m);
		printf("M: ");
		for (int i = 0; i < M_len; i++)
			printf("%d", M[i]);
		printf("\n");
		mpz_clear(m);
		mpz_clear(s);
		return 0;

	}