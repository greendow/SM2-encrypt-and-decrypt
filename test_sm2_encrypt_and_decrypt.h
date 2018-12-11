/**************************************************
* File name: test_sm2_encrypt_and_decrypt.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Dec 9th, 2018
* Description: declare SM2 encrypt data and decrypt
    ciphertext test functions
**************************************************/

#ifndef HEADER_SM2_ENCRYPT_DATA_AND_DECRYPT_CIPHERTEXT_TEST_H
  #define HEADER_SM2_ENCRYPT_DATA_AND_DECRYPT_CIPHERTEXT_TEST_H

#ifdef  __cplusplus
  extern "C" {
#endif

/**************************************************
* Name: test_with_input_defined_in_standard
* Function: test SM2 encrypt data and decrypt ciphertext
    with standard input from GM/T 0003.5-2012
* Return value:
    0:                test executes successfully
    any other value:  an error occurs
**************************************************/
int test_with_input_defined_in_standard(void);

/**************************************************
* Name: test_sm2_encrypt_and_decrypt
* Function: test SM2 encrypt data and decrypt ciphertext
* Return value:
    0:                test executes successfully
    any other value:  an error occurs
**************************************************/
int test_sm2_encrypt_and_decrypt(void);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_SM2_ENCRYPT_DATA_AND_DECRYPT_CIPHERTEXT_TEST_H */