/**************************************************
* File name: sm2_cipher_error_codes.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Dec 9th, 2018
* Description: define error codes used in SM2
    computation functions
**************************************************/

#ifndef HEADER_ERROR_CODES_LIST_OF_SM2_CIPHER_H
  #define HEADER_ERROR_CODES_LIST_OF_SM2_CIPHER_H

#define INVALID_NULL_VALUE_INPUT     0x1000
#define INVALID_INPUT_LENGTH         0x1001
#define CREATE_SM2_KEY_PAIR_FAIL     0x1002
#define COMPUTE_SM3_DIGEST_FAIL      0x1003
#define ALLOCATION_MEMORY_FAIL       0x1004
#define COMPUTE_SM2_SIGNATURE_FAIL   0x1005
#define INVALID_SM2_SIGNATURE        0x1006
#define VERIFY_SM2_SIGNATURE_FAIL    0x1007
#define EC_POINT_IS_AT_INFINITY      0x1008
#define COMPUTE_SM2_CIPHERTEXT_FAIL  0x1009
#define COMPUTE_SM2_KDF_FAIL         0x100a
#define INVALID_SM2_CIPHERTEXT       0x100b
#define SM2_DECRYPT_FAIL             0x100c

#endif  /* end of HEADER_ERROR_CODES_LIST_OF_SM2_CIPHER_H */