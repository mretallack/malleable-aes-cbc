

#include <string.h>
#include <stdint.h>


#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <openssl/aes.h>



void encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
	AES_KEY enc_key;
	
	AES_set_encrypt_key(key, 16*8, &enc_key);

	AES_cbc_encrypt(plaintext, ciphertext, plaintext_len, &enc_key, iv, AES_ENCRYPT);

}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
	AES_KEY dec_key;

	AES_set_decrypt_key(key, 16*8, &dec_key); // Size of key is in bits

	AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &dec_key, iv, AES_DECRYPT);

}

void bitWiseXor(const unsigned char *AStr, const unsigned char *BStr, int len, unsigned char *res)
{
	int i;
	for (i=0; i<len; i++)
	{
		res[i]=AStr[i]^BStr[i];
	}
}

void attack(unsigned char *iv)
{
	// ok, calc A^B
	// we know A and B

	const char *AStr = "               1";
	const char *BStr = "           10000";

	unsigned char resAB[32];

	bitWiseXor(AStr, BStr, 16, resAB);

	bitWiseXor(resAB, iv, 16, iv);

	printf("modified iv is:\n");
	BIO_dump_fp (stdout, (const char *)iv, 16);

}

int main (void)
{

	// A 128 bit key 
	unsigned char *key = (unsigned char *)"0123456789012345";

	// A 128 bit IV 
	unsigned char *iv = (unsigned char *) "0123456789012345";

	unsigned char tmp_iv[17];

	// Message to be encrypted 
	unsigned char *plaintext =
			(unsigned char *)"               1"
					 "$ to be         "
					 "transfered from "
					 "Alice to Bob    "
					 "Today           ";

	int plaintext_len = strlen ((char *)plaintext);

	unsigned char ciphertext[128];
	unsigned char decryptedtext[128];

	memcpy(tmp_iv, iv, 16);
	encrypt (plaintext, plaintext_len, key, tmp_iv, ciphertext);

	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, plaintext_len);

	// and refresh IV because the encrypt will mod the IV 
	memcpy(tmp_iv, iv, 16);

	printf("iv is:\n");
	BIO_dump_fp (stdout, (const char *)tmp_iv, 16);

	// ok, perform the attack on the IV here
	attack(tmp_iv);

	// Decrypt the ciphertext 
	decrypt(ciphertext, plaintext_len, key, tmp_iv, decryptedtext);

	// add a null so it prints (writes over last byte)
	decryptedtext[plaintext_len] = '\0';

	printf("Decrypted after change is:\n");
	BIO_dump_fp (stdout, (const char *)decryptedtext, plaintext_len);

	/* Show the decrypted text */
	printf("Decrypted text is:\n");
	printf("%s\n", decryptedtext);

	return 0;
}

