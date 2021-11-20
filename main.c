#include <gmp.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio_ext.h>

#define P "9320483326403141908015992162623600634575383430682887743382352056156178908367184167231123764417028100440493342112733863272018608164976018482157886751640476408611107448081659328189987279478473107665608224322577609602668215373049415828076115411711894932867991657795009176799957724525869703082152176991423"

#define X "40622201812345"

// P is the large prime munber.
mpz_t p, x;

void decrypt()
{
	//Decryption Check
	mpz_t c1_powx, c1_powx_inv, c1, c2, m2;
	mpz_inits(c1, c2, c1_powx, c1_powx_inv, m2, NULL);


	printf("Enter a value of C1,C2 ");
	gmp_scanf("%Zd,%Zd", c1, c2);
	//Compute c1^x mod p
	mpz_powm(c1_powx, c1, x, p);

	//Compute (c1^x)^-1
	mpz_invert(c1_powx_inv, c1_powx, p);

	//Compute c2 * (c1^x)^-1
	// m = c2 * (c1^d) ^ -1 mod p
	mpz_mul(m2, c2, c1_powx_inv);
	mpz_mod(m2, m2, p);

	gmp_printf("\n============================ Plain Text ====================================== \n");
	gmp_printf("Decrpyted message: %Zd\n", m2);

	mpz_clears(m2, c1, c2, c1_powx, c1_powx_inv, NULL);
}


void encrypt() {

	// m is the plain text message. C1 and C2 are the Cipher text generated.
	mpz_t m, c1, c2;

	/*
	  Public Key p, e1, e2
	  g and h are e1 and e2 in the algorithm. i.e. e1 will be the primitive root mod p and e2 = e1^d mod p
	*/
	mpz_t g, h;

	/*
	  Private Key. x is d in the algorithm. 1 < d < p-2
	  Temporary variables.
	*/
	mpz_t  r, generator;
	mpz_t h_pow_r;
	mpz_t p_sub_1_div2, g_x, g_pow_2, one;
	gmp_randstate_t g_state;
	gmp_randstate_t r_state;

	// Initializatin
	mpz_init(m);
	mpz_inits(p_sub_1_div2, g_x, g_pow_2, one, NULL);
	mpz_inits(c1, c2, h, g, generator, r, x, h_pow_r, NULL);
	gmp_randinit_mt(g_state);
	gmp_randinit_mt(r_state);
	mpz_set_str(x, X, 10);

	// Input the plain text for eccryption.
	printf("Enter a number to encrypt m : ");
	gmp_scanf("%Zd", m);

	//find random g
	srand(time(0));
	int seed = rand();
	gmp_randseed_ui(g_state, seed);
	mpz_urandomb(g, g_state, 1000); // A random number between 0 to 2^1000 -1

	//find random r
	srand(time(0));
	seed = rand();
	gmp_randseed_ui(r_state, seed);
	mpz_urandomb(r, r_state, 1000);

	mpz_set_ui(one, 1);
	mpz_set(p_sub_1_div2, p);
	mpz_submul_ui(p_sub_1_div2, one, 0.5);
		
	//calculate generator that is safe from attacks.
	while (mpz_cmp(g, p) != 0) {
		mpz_powm(g_x, g, p_sub_1_div2, p); //g^((p-1)/2) mod p
		mpz_powm_ui(g_pow_2, g, 2, p); //g^2 mod p

		if (!(mpz_cmp_ui(g_x, 1) == 0) && !(mpz_cmp_ui(g_pow_2, 1) == 0)) {
			mpz_set(generator, g);
			break;
		}
		else {
			srand(time(0));
			int seed = rand();
			gmp_randseed_ui(g_state, seed);
			mpz_urandomb(g, g_state, 1000);
		}
	}

	//Compute c1 = g^r mod p (C1 = e1 ^ r mod p where r is the random interger belonging to the group)
	mpz_powm(c1, generator, r, p);

	//Compute h = g^x mod p (e2 = e1 ^d mod p)
	mpz_powm(h, generator, x, p);

	//Compute h^r
	mpz_powm(h_pow_r, h, r, p);

	//Compute c2 = m * h^r (C2 = m * e2^r mod p)
	mpz_mul(c2, m, h_pow_r);

	gmp_printf("\n============================ Cipher Text ====================================== \n");
	gmp_printf("\nC1: %Zd \n\nC2: %Zd\n\n", c1, c2);

	// Clear fileds
	mpz_clear(m);
	mpz_clears(p_sub_1_div2, g_pow_2, g_x, NULL);
	mpz_clears(c1, c2,  one, g, h_pow_r, h, generator, r, NULL);
	gmp_randclear(r_state);
	gmp_randclear(g_state);

}

int main()
{
	mpz_set_str(p, P, 10);
	mpz_set_str(x, X, 10);
	char input[100] = {0};

	while (1) {
	__fpurge(stdin);
	printf("\nEnter 1 to encrypt and 0 to decrypt:");
	memset(input, 0, 100);
	fgets(input, 100, stdin);
	input[strlen(input)-1] = '\0';
	int is_encrypt = atoi(input);

	/* atoi() will return 0 for special characters also hence strncmp is used.*/
	if(!( (is_encrypt == 1) ^ ((is_encrypt == 0) && !strncmp(input, "0", 1))))
	{
		printf("\n Invalid encrypt/decrypt value. Enter 1 to encrypt 0 to decrypt.\n");
		continue;
	}

	if (is_encrypt == 1) {
		// Elgamal encryption.
		printf("\nEncrypting!!!!!!!!!!!!!!!!!\n");
		encrypt();
	}

	if (is_encrypt == 0) {
		// Elgamal Decryption.
		printf("\nDecrypting!!!!!!!!!!!!!!!!!\n");
		decrypt();
	}

	}

	mpz_clears(p, x, NULL);
	return 0;
}
