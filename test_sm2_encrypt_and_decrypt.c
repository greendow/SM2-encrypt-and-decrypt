/**************************************************
* File name: test_sm2_encrypt_and_decrypt.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Dec 9th, 2018
* Description: implement SM2 encrypt data and decrypt
    ciphertext test functions
**************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm2_cipher_error_codes.h"
#include "sm2_create_key_pair.h"
#include "sm2_encrypt_and_decrypt.h"
#include "test_sm2_encrypt_and_decrypt.h"

/*********************************************************/
int test_with_input_defined_in_standard(void)
{
	int error_code;
	unsigned char msg[] = {"encryption standard"};
	int msg_len = (int)(strlen((char *)msg));
	unsigned char pub_key[] = {0x04, 0x09, 0xf9, 0xdf, 0x31, 0x1e, 0x54, 0x21, 0xa1,
	                                 0x50, 0xdd, 0x7d, 0x16, 0x1e, 0x4b, 0xc5, 0xc6,
					 0x72, 0x17, 0x9f, 0xad, 0x18, 0x33, 0xfc, 0x07,
					 0x6b, 0xb0, 0x8f, 0xf3, 0x56, 0xf3, 0x50, 0x20,
					 0xcc, 0xea, 0x49, 0x0c, 0xe2, 0x67, 0x75, 0xa5,
					 0x2d, 0xc6, 0xea, 0x71, 0x8c, 0xc1, 0xaa, 0x60,
					 0x0a, 0xed, 0x05, 0xfb, 0xf3, 0x5e, 0x08, 0x4a,
					 0x66, 0x32, 0xf6, 0x07, 0x2d, 0xa9, 0xad, 0x13};
	unsigned char pri_key[32] = {0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1,
	                             0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95,
	                             0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a,
	                             0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8};
	unsigned char std_c1[65] = {0x04, 0x04, 0xeb, 0xfc, 0x71, 0x8e, 0x8d, 0x17, 0x98,
	                                  0x62, 0x04, 0x32, 0x26, 0x8e, 0x77, 0xfe, 0xb6,
					  0x41, 0x5e, 0x2e, 0xde, 0x0e, 0x07, 0x3c, 0x0f,
					  0x4f, 0x64, 0x0e, 0xcd, 0x2e, 0x14, 0x9a, 0x73,
					  0xe8, 0x58, 0xf9, 0xd8, 0x1e, 0x54, 0x30, 0xa5,
					  0x7b, 0x36, 0xda, 0xab, 0x8f, 0x95, 0x0a, 0x3c,
					  0x64, 0xe6, 0xee, 0x6a, 0x63, 0x09, 0x4d, 0x99,
					  0x28, 0x3a, 0xff, 0x76, 0x7e, 0x12, 0x4d, 0xf0};
	unsigned char std_c3[32] = {0x59, 0x98, 0x3c, 0x18, 0xf8, 0x09, 0xe2, 0x62,
	                            0x92, 0x3c, 0x53, 0xae, 0xc2, 0x95, 0xd3, 0x03,
				    0x83, 0xb5, 0x4e, 0x39, 0xd6, 0x09, 0xd1, 0x60,
				    0xaf, 0xcb, 0x19, 0x08, 0xd0, 0xbd, 0x87, 0x66};
	unsigned char std_c2[19] = {0x21, 0x88, 0x6c, 0xa9, 0x89, 0xca, 0x9c, 0x7d,
	                            0x58, 0x08, 0x73, 0x07, 0xca, 0x93, 0x09, 0x2d,
				    0x65, 0x1e, 0xfa};
	unsigned char c1[65], c3[32];
	unsigned char *c2, *plaintext;
	int i;

	if ( !(c2 = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}
	if ( error_code = sm2_encrypt_data_test(msg,
	                                        msg_len,
						pub_key,
						c1,
						c3,
						c2) )
	{
		printf("Create SM2 ciphertext by using input defined in standard failed!\n");
		free(c2);
		return error_code;
	}

	if ( memcmp(c1, std_c1, sizeof(std_c1)) )
	{
		printf("C1 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}
	if ( memcmp(c3, std_c3, sizeof(std_c3)) )
	{
		printf("C3 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}
	if ( memcmp(c2, std_c2, sizeof(std_c2)) )
	{
		printf("C2 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}

	printf("Create SM2 ciphertext by using input defined in standard succeeded!\n");
	printf("SM2 ciphertext:\n\n");
	printf("C1 component:\n");
	for (i = 0; i < sizeof(std_c1); i++)
	{
		printf("0x%x  ", c1[i]);
	}
	printf("\n\n");
	printf("C3 component:\n");
	for (i = 0; i < sizeof(std_c3); i++)
	{
		printf("0x%x  ", c3[i]);
	}
	printf("\n\n");
	printf("Message: %s\n", msg);
	printf("The length of message is %d bytes.\n", msg_len);
	printf("The length of C2 component is %d bytes.\n", msg_len);
	printf("C2 component:\n");
	for (i = 0; i < sizeof(std_c2); i++)
	{
		printf("0x%x  ", c2[i]);
	}
	printf("\n\n");

	if ( !(plaintext = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}

	if ( error_code = sm2_decrypt(c1,
		                      c3,
				      c2,
				      msg_len,
				      pri_key,
				      plaintext) )
	{
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext by using private key defined in standard failed!\n");
		return error_code;
	}
	if ( memcmp(plaintext, msg, msg_len) )
	{
		printf("Decrypted plaintext is different from the input message!\n");
		return SM2_DECRYPT_FAIL;
	}
	printf("Input message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", msg[i]);
	}
	printf("\n");
	printf("Decrypted message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", plaintext[i]);
	}
	printf("\n");
	printf("Decrypt SM2 ciphertext by using private key defined in standard succeeded!\n");

	free(plaintext);
	free(c2);
	return 0;
}

/*********************************************************/
int test_sm2_encrypt_and_decrypt(void)
{
	int error_code;
	unsigned char msg[] = {"encryption standard"};
	int msg_len = (int)(strlen((char *)msg));
	SM2_KEY_PAIR key_pair;
	unsigned char c1[65], c3[32];
	unsigned char *c2, *plaintext;
	int i;

	if ( error_code = sm2_create_key_pair(&key_pair) )
	{
		printf("Create SM2 key pair failed!\n");
		return (-1);
	}
	printf("Create SM2 key pair succeeded!\n");
	printf("Private key:\n");
	for (i = 0; i < sizeof(key_pair.pri_key); i++)
	{
		printf("0x%x  ", key_pair.pri_key[i]);
	}
	printf("\n\n");
	printf("Public key:\n");
	for (i = 0; i < sizeof(key_pair.pub_key); i++)
	{
		printf("0x%x  ", key_pair.pub_key[i]);
	}
	printf("\n\n");

	printf("/*********************************************************/\n");
	if ( !(c2 = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}
	if ( error_code = sm2_encrypt_data_test(msg,
	                                        msg_len,
						key_pair.pub_key,
						c1,
						c3,
						c2) )
	{
		printf("Create SM2 ciphertext failed!\n");
		free(c2);
		return error_code;
	}

	printf("Create SM2 ciphertext succeeded!\n");
	printf("SM2 ciphertext:\n\n");
	printf("C1 component:\n");
	for (i = 0; i < sizeof(c1); i++)
	{
		printf("0x%x  ", c1[i]);
	}
	printf("\n\n");
	printf("C3 component:\n");
	for (i = 0; i < sizeof(c3); i++)
	{
		printf("0x%x  ", c3[i]);
	}
	printf("\n\n");
	printf("Message: %s\n", msg);
	printf("The length of message is %d bytes.\n", msg_len);
	printf("The length of C2 component is %d bytes.\n", msg_len);
	printf("C2 component:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", c2[i]);
	}
	printf("\n\n");

	if ( !(plaintext = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}

	if ( error_code = sm2_decrypt(c1,
		                      c3,
				      c2,
				      msg_len,
				      key_pair.pri_key,
				      plaintext) )
	{
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext failed!\n");
		return error_code;
	}
	if ( memcmp(plaintext, msg, msg_len) )
	{
		printf("Decrypted plaintext is different from the input message!\n");
		return SM2_DECRYPT_FAIL;
	}
	printf("Input message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", msg[i]);
	}
	printf("\n");
	printf("Decrypted message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", plaintext[i]);
	}
	printf("\n");
	printf("Decrypt SM2 ciphertext succeeded!\n");

	free(plaintext);
	free(c2);
	return 0;
}
