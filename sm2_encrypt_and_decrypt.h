/**************************************************
* File name: sm2_encrypt_and_decrypt.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Dec 8th, 2018
* Description: declare SM2 encrypt data and decrypt
    ciphertext functions
**************************************************/

#ifndef HEADER_SM2_ENCRYPT_AND_DECRYPT_COMPUTATION_H
  #define HEADER_SM2_ENCRYPT_AND_DECRYPT_COMPUTATION_H

#ifdef  __cplusplus
  extern "C" {
#endif

/**************************************************
* Name: sm2_encrypt_data_test
* Function: compute SM2 encryption with a fixed internal 
    random number k given in GM/T 0003.5-2012
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    pub_key[in]      SM2 public key
    c1[out]          the first segment of ciphertext
    c3[out]          the middle segment of ciphertext
    c2[out]          the last segment of ciphertext
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. This function is only used for testing! When a 
   ciphertext is created by invoking this function,
   a fixed random number value k is used. The random
   number value is given in GM/T 0003.5-2012.
2. "pub_key" is a octet string of 65 byte length. It 
   is a concatenation of 04 || X || Y. X and Y both are 
   SM2 public key coordinates of 32 byte length.
3. SM2 ciphertext is defined as a concatenation of 
   c1 || c3 || c2 in GM/T 0003.4-2012.
4. c1 is a octet string of 65 byte length. It is a 
   point on the elliptic curve. It is a concatenation 
   of 04 || X || Y. X and Y both are coordinates of 
   32 byte length.
5. c3 is a octet string of 32 byte length. It is a 
   SM3 digest value.
6. c2 is a octet string. Its length equals the length 
   of input message.
**************************************************/
int sm2_encrypt_data_test(const unsigned char *message,
                          const int message_len,
			  const unsigned char *pub_key,
			  unsigned char *c1,
			  unsigned char *c3,
			  unsigned char *c2);

/**************************************************
* Name: sm2_encrypt_data
* Function: compute SM2 encryption
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    pub_key[in]      SM2 public key
    c1[out]          the first segment of ciphertext
    c3[out]          the middle segment of ciphertext
    c2[out]          the last segment of ciphertext
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. pub_key is a octet string of 65 byte length. It 
   is a concatenation of 04 || X || Y. X and Y both are 
   SM2 public key coordinates of 32 byte length.
2. SM2 ciphertext is defined as a concatenation of 
   c1 || c3 || c2 in GM/T 0003.4-2012.
3. c1 is a octet string of 65 byte length. It is a 
   point on the elliptic curve. It is a concatenation 
   of 04 || X || Y. X and Y both are coordinates of 
   32 byte length.
4. c3 is a octet string of 32 byte length. It is a 
   SM3 digest value.
5. c2 is a octet string. Its length equals the length 
   of input message.
**************************************************/
int sm2_encrypt(const unsigned char *message,
                const int message_len,
		const unsigned char *pub_key,
		unsigned char *c1,
		unsigned char *c3,
		unsigned char *c2);

/**************************************************
* Name: sm2_decrypt
* Function: decrypt SM2 ciphertext
* Parameters:
    c1[in]            the first segment of ciphertext
    c3[in]            the middle segment of ciphertext
    c2[in]            the last segment of ciphertext
    c2_len[in]        c2 length, size in bytes
    pri_key[in]       SM2 private key
    plaintext[out]    decrypted result
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. SM2 ciphertext is defined as a concatenation of 
   c1 || c3 || c2 in GM/T 0003.4-2012.
2. c1 is a octet string of 65 byte length. It is a 
   point on the elliptic curve. It is a concatenation 
   of 04 || X || Y. X and Y both are coordinates of 
   32 byte length.
3. c3 is a octet string of 32 byte length. It is a 
   SM3 digest value.
4. c2 is a octet string. The length of plaintext is 
   equal to c2_len.
5. pri_key is a octet string of 32 byte length.
**************************************************/
int sm2_decrypt(const unsigned char *c1,
                const unsigned char *c3,
		const unsigned char *c2,
		const int c2_len,
		const unsigned char *pri_key,
		unsigned char *plaintext);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_SM2_ENCRYPT_AND_DECRYPT_COMPUTATION_H */
