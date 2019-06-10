/**************************************************
* File name: sm2_encrypt_and_decrypt.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Dec 8th, 2018
* Description: implement SM2 encrypt data and decrypt
    ciphertext functions
**************************************************/

#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "sm2_cipher_error_codes.h"
#include "sm2_encrypt_and_decrypt.h"

/*********************************************************/
int sm2_encrypt_data_test(const unsigned char *message,
                          const int message_len,
			  const unsigned char *pub_key,
			  unsigned char *c1,
			  unsigned char *c3,
			  unsigned char *c2)
{
	int error_code;
	unsigned char k[32] = {0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a,
	                       0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0, 0x2d, 0xcc,
	                       0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce,
	                       0x6d, 0x54, 0xb8, 0x0d, 0xea, 0xc1, 0xbc, 0x21};
	unsigned char pub_key_x[32], pub_key_y[32], c1_x[32], c1_y[32], x2[32], y2[32];
	unsigned char c1_point[65], x2_y2[64];
	unsigned char *t = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_k = NULL, *bn_c1_x = NULL, *bn_c1_y = NULL;
	BIGNUM *bn_pub_key_x = NULL, *bn_pub_key_y = NULL;
	BIGNUM *bn_x2 = NULL, *bn_y2 = NULL;
	const BIGNUM *bn_order, *bn_cofactor;
	EC_GROUP *group = NULL;
	const EC_POINT *generator;
	EC_POINT *pub_key_pt = NULL, *c1_pt = NULL, *s_pt = NULL, *ec_pt = NULL;
	const EVP_MD *md;
	EVP_MD_CTX *md_ctx = NULL;
	int i, flag;

	memcpy(pub_key_x, (pub_key + 1), sizeof(pub_key_x));
	memcpy(pub_key_y, (pub_key + 1 + sizeof(pub_key_x)), sizeof(pub_key_y));

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(t = (unsigned char *)malloc(message_len)) )
	{
		goto clean_up;
	}
	if ( !(ctx = BN_CTX_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_k = BN_CTX_get(ctx);
	bn_c1_x = BN_CTX_get(ctx);
	bn_c1_y = BN_CTX_get(ctx);
	bn_pub_key_x = BN_CTX_get(ctx);
	bn_pub_key_y = BN_CTX_get(ctx);
	bn_x2 = BN_CTX_get(ctx);	
	bn_y2 = BN_CTX_get(ctx);
	if ( !(bn_y2) )
	{
		goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}
	
	if ( !(pub_key_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(c1_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(s_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	
	if ( !(md_ctx = EVP_MD_CTX_new()) )
	{
		goto clean_up;
	}	

	error_code = COMPUTE_SM2_CIPHERTEXT_FAIL;
	if ( !(BN_bin2bn(pub_key_x, sizeof(pub_key_x), bn_pub_key_x)) )
	{
		goto clean_up;
	}
	if ( !(BN_bin2bn(pub_key_y, sizeof(pub_key_y), bn_pub_key_y)) )
	{
		goto clean_up;
	}

	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
		goto clean_up;
	}
	if ( !(bn_cofactor = EC_GROUP_get0_cofactor(group)) )
	{
		goto clean_up;
	}
	if ( !(generator = EC_GROUP_get0_generator(group)) )
	{
		goto clean_up;
	}

	if ( !(EC_POINT_set_affine_coordinates_GFp(group,
	                                           pub_key_pt,
						   bn_pub_key_x,
						   bn_pub_key_y,
						   ctx)) )
	{
		goto clean_up;
	}

	/* Compute EC point s = [h]Pubkey, h is the cofactor.
	   If s is at infinity, the function returns and reports an error. */
	if ( !(EC_POINT_mul(group, s_pt, NULL, pub_key_pt, bn_cofactor, ctx)) )
	{
		goto clean_up;
	}
	if ( EC_POINT_is_at_infinity(group, s_pt) )
	{
		error_code = EC_POINT_IS_AT_INFINITY;
		goto clean_up;
	}
	md = EVP_sm3();

	do
	{
		if ( !(BN_bin2bn(k, sizeof(k), bn_k)) )
		{
			goto clean_up;
		}
		if ( BN_is_zero(bn_k) )
		{
			continue;
		}
		if ( !(EC_POINT_mul(group, c1_pt, bn_k, NULL, NULL, ctx)) )
		{
			goto clean_up;
		}
		if ( !(EC_POINT_mul(group, ec_pt, NULL, pub_key_pt, bn_k, ctx)) )
		{
			goto clean_up;
		}
		if ( !(EC_POINT_get_affine_coordinates_GFp(group,
		                                           ec_pt,
							   bn_x2,
							   bn_y2,
							   ctx)) )
		{
			goto clean_up;
		}
		if ( BN_bn2binpad(bn_x2,
		                  x2,
				  sizeof(x2)) != sizeof(x2) )
		{
			goto clean_up;
		}
		if ( BN_bn2binpad(bn_y2,
		                  y2,
				  sizeof(y2)) != sizeof(y2) )
		{
			goto clean_up;
		}
		memcpy(x2_y2, x2, sizeof(x2));
		memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));
		
		if ( !(ECDH_KDF_X9_62(t,
		                      message_len,
				      x2_y2,
				      sizeof(x2_y2),
				      NULL,
				      0,
				      md)) )
		{
			error_code = COMPUTE_SM2_KDF_FAIL;
			goto clean_up;
		}

		/* If each component of t is zero, the random number k 
		   should be re-generated. 
		   A fixed random number k is used in this test function,
		   so this case will not happen.*/
		flag = 1;
		for (i = 0; i < message_len; i++)
		{
			if ( t[i] != 0 )
			{
				flag = 0;
				break;
			}
		}		
	} while (flag);
	
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           c1_pt,
						   bn_c1_x,
						   bn_c1_y,
						   ctx)) )
	{
		goto clean_up;
	}

	if ( BN_bn2binpad(bn_c1_x,
	                  c1_x,
			  sizeof(c1_x)) != sizeof(c1_x) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_c1_y,
	                  c1_y,
			  sizeof(c1_y)) != sizeof(c1_y) )
	{
		goto clean_up;
	}
	c1_point[0] = 0x4;
	memcpy((c1_point + 1), c1_x, sizeof(c1_x));
	memcpy((c1_point + 1 + sizeof(c1_x)), c1_y, sizeof(c1_y));
	memcpy(c1, c1_point, sizeof(c1_point));
	
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
        EVP_DigestUpdate(md_ctx, message, message_len);
	EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
        EVP_DigestFinal_ex(md_ctx, c3, NULL);
	
	for (i = 0; i < message_len; i++)
	{
		c2[i] = message[i] ^ t[i];
	}
	error_code = 0;
	
clean_up:
        if (t)
	{
		free(t);
	}
        if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}

	if (pub_key_pt)
	{
		EC_POINT_free(pub_key_pt);
	}
	if (c1_pt)
	{
		EC_POINT_free(c1_pt);
	}
	if (s_pt)
	{
		EC_POINT_free(s_pt);
	}
	if (ec_pt)
	{
		EC_POINT_free(ec_pt);
	}
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
	}

	return error_code;
}

/*********************************************************/
int sm2_encrypt(const unsigned char *message,
                const int message_len,
		const unsigned char *pub_key,
		unsigned char *c1,
		unsigned char *c3,
		unsigned char *c2)
{
	int error_code;
	unsigned char pub_key_x[32], pub_key_y[32], c1_x[32], c1_y[32], x2[32], y2[32];
	unsigned char c1_point[65], x2_y2[64];
	unsigned char *t = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_k = NULL, *bn_c1_x = NULL, *bn_c1_y = NULL;
	BIGNUM *bn_pub_key_x = NULL, *bn_pub_key_y = NULL;
	BIGNUM *bn_x2 = NULL, *bn_y2 = NULL;
	const BIGNUM *bn_order, *bn_cofactor;
	EC_GROUP *group = NULL;
	const EC_POINT *generator;
	EC_POINT *pub_key_pt = NULL, *c1_pt = NULL, *s_pt = NULL, *ec_pt = NULL;
	const EVP_MD *md;
	EVP_MD_CTX *md_ctx = NULL;
	int i, flag;

	memcpy(pub_key_x, (pub_key + 1), sizeof(pub_key_x));
	memcpy(pub_key_y, (pub_key + 1 + sizeof(pub_key_x)), sizeof(pub_key_y));

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(t = (unsigned char *)malloc(message_len)) )
	{
		goto clean_up;
	}
	if ( !(ctx = BN_CTX_new()) )
	{
	        goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_k = BN_CTX_get(ctx);
	bn_c1_x = BN_CTX_get(ctx);
	bn_c1_y = BN_CTX_get(ctx);
	bn_pub_key_x = BN_CTX_get(ctx);
	bn_pub_key_y = BN_CTX_get(ctx);
	bn_x2 = BN_CTX_get(ctx);	
	bn_y2 = BN_CTX_get(ctx);
	if ( !(bn_y2) )
	{
		goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}
	
	if ( !(pub_key_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(c1_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(s_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	
	if ( !(md_ctx = EVP_MD_CTX_new()) )
	{
		goto clean_up;
	}	

	error_code = COMPUTE_SM2_CIPHERTEXT_FAIL;
	if ( !(BN_bin2bn(pub_key_x, sizeof(pub_key_x), bn_pub_key_x)) )
	{
		goto clean_up;
	}
	if ( !(BN_bin2bn(pub_key_y, sizeof(pub_key_y), bn_pub_key_y)) )
	{
		goto clean_up;
	}

	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
		goto clean_up;
	}
	if ( !(bn_cofactor = EC_GROUP_get0_cofactor(group)) )
	{
		goto clean_up;
	}
	if ( !(generator = EC_GROUP_get0_generator(group)) )
	{
		goto clean_up;
	}

	if ( !(EC_POINT_set_affine_coordinates_GFp(group,
	                                           pub_key_pt,
						   bn_pub_key_x,
						   bn_pub_key_y,
						   ctx)) )
	{
		goto clean_up;
	}

	/* Compute EC point s = [h]Pubkey, h is the cofactor.
	   If s is at infinity, the function returns and reports an error. */
	if ( !(EC_POINT_mul(group, s_pt, NULL, pub_key_pt, bn_cofactor, ctx)) )
	{
		goto clean_up;
	}
	if ( EC_POINT_is_at_infinity(group, s_pt) )
	{
		error_code = EC_POINT_IS_AT_INFINITY;
		goto clean_up;
	}
	md = EVP_sm3();

	do
	{
		if ( !(BN_rand_range(bn_k, bn_order)) )
		{
			goto clean_up;
		}
		if ( BN_is_zero(bn_k) )
		{
			continue;
		}
		if ( !(EC_POINT_mul(group, c1_pt, bn_k, NULL, NULL, ctx)) )
		{
			goto clean_up;
		}
		if ( !(EC_POINT_mul(group, ec_pt, NULL, pub_key_pt, bn_k, ctx)) )
		{
			goto clean_up;
		}
		if ( !(EC_POINT_get_affine_coordinates_GFp(group,
		                                           ec_pt,
							   bn_x2,
							   bn_y2,
							   ctx)) )
		{
			goto clean_up;
		}
		if ( BN_bn2binpad(bn_x2,
		                  x2,
				  sizeof(x2)) != sizeof(x2) )
		{
			goto clean_up;
		}
		if ( BN_bn2binpad(bn_y2,
		                  y2,
				  sizeof(y2)) != sizeof(y2) )
		{
			goto clean_up;
		}
		memcpy(x2_y2, x2, sizeof(x2));
		memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));
		
		if ( !(ECDH_KDF_X9_62(t,
		                      message_len,
				      x2_y2,
				      sizeof(x2_y2),
				      NULL,
				      0,
				      md)) )
		{
			error_code = COMPUTE_SM2_KDF_FAIL;
			goto clean_up;
		}

		/* If each component of t is zero, the random number k 
		   should be re-generated. */
		flag = 1;
		for (i = 0; i < message_len; i++)
		{
			if ( t[i] != 0 )
			{
				flag = 0;
				break;
			}
		}		
	} while (flag);
	
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           c1_pt,
						   bn_c1_x,
						   bn_c1_y,
						   ctx)) )
	{
		goto clean_up;
	}

	if ( BN_bn2binpad(bn_c1_x,
	                  c1_x,
			  sizeof(c1_x)) != sizeof(c1_x) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_c1_y,
	                  c1_y,
			  sizeof(c1_y)) != sizeof(c1_y) )
	{
		goto clean_up;
	}
	c1_point[0] = 0x4;
	memcpy((c1_point + 1), c1_x, sizeof(c1_x));
	memcpy((c1_point + 1 + sizeof(c1_x)), c1_y, sizeof(c1_y));
	memcpy(c1, c1_point, sizeof(c1_point));
	
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
        EVP_DigestUpdate(md_ctx, message, message_len);
	EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
        EVP_DigestFinal_ex(md_ctx, c3, NULL);
	
	for (i = 0; i < message_len; i++)
	{
		c2[i] = message[i] ^ t[i];
	}
	error_code = 0;
	
clean_up:
        if (t)
	{
		free(t);
	}
        if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}

	if (pub_key_pt)
	{
		EC_POINT_free(pub_key_pt);
	}
	if (c1_pt)
	{
		EC_POINT_free(c1_pt);
	}
	if (s_pt)
	{
		EC_POINT_free(s_pt);
	}
	if (ec_pt)
	{
		EC_POINT_free(ec_pt);
	}
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
	}

	return error_code;
}

/*********************************************************/
int sm2_decrypt(const unsigned char *c1,
                const unsigned char *c3,
		const unsigned char *c2,
		const int c2_len,
		const unsigned char *pri_key,
		unsigned char *plaintext)
{
	int error_code;
	unsigned char c1_x[32], c1_y[32], x2[32], y2[32];
	unsigned char x2_y2[64], digest[32];
	unsigned char *t = NULL, *M = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_d = NULL, *bn_c1_x = NULL, *bn_c1_y = NULL;
	BIGNUM *bn_x2 = NULL, *bn_y2 = NULL;
	const BIGNUM *bn_cofactor;
	EC_GROUP *group = NULL;
	EC_POINT *c1_pt = NULL, *s_pt = NULL, *ec_pt = NULL;
	const EVP_MD *md;
	EVP_MD_CTX *md_ctx = NULL;
	int message_len, i, flag;

	message_len = c2_len;
	memcpy(c1_x, (c1 + 1), sizeof(c1_x));
	memcpy(c1_y, (c1 + 1 + sizeof(c1_x)), sizeof(c1_y));

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(ctx = BN_CTX_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_c1_x = BN_CTX_get(ctx);
	bn_c1_y = BN_CTX_get(ctx);
	bn_x2 = BN_CTX_get(ctx);
	bn_y2 = BN_CTX_get(ctx);
	if ( !(bn_y2) )
	{
		goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}
	
	if ( !(c1_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(s_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}

	if ( !(md_ctx = EVP_MD_CTX_new()) )
	{
		goto clean_up;
	}

	error_code = SM2_DECRYPT_FAIL;
	if ( !(BN_bin2bn(pri_key, 32, bn_d)) )
	{
		goto clean_up;
	}
	if ( !(BN_bin2bn(c1_x, sizeof(c1_x), bn_c1_x)) )
	{
		goto clean_up;
	}
	if ( !(BN_bin2bn(c1_y, sizeof(c1_y), bn_c1_y)) )
	{
		goto clean_up;
	}
	
	if ( !(EC_POINT_set_affine_coordinates_GFp(group,
	                                           c1_pt,
						   bn_c1_x,
						   bn_c1_y,
						   ctx)) )
	{
		goto clean_up;
	}
	if ( EC_POINT_is_on_curve(group, c1_pt, ctx) != 1 )
	{
		error_code = INVALID_SM2_CIPHERTEXT;
		goto clean_up;
	}

	if ( !(bn_cofactor = EC_GROUP_get0_cofactor(group)) )
	{
		goto clean_up;
	}
	if ( !(EC_POINT_mul(group, s_pt, NULL, c1_pt, bn_cofactor, ctx)) )
	{
		goto clean_up;
	}
	if ( EC_POINT_is_at_infinity(group, s_pt) )
	{
		error_code = INVALID_SM2_CIPHERTEXT;;
		goto clean_up;
	}

	if ( !(EC_POINT_mul(group, ec_pt, NULL, c1_pt, bn_d, ctx)) )
	{
		goto clean_up;
	}
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           ec_pt,
						   bn_x2,
						   bn_y2,
						   ctx)) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_x2,
		          x2,
			  sizeof(x2)) != sizeof(x2) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_y2,
		          y2,
			  sizeof(x2)) != sizeof(y2) )
	{
		goto clean_up;
	}
	memcpy(x2_y2, x2, sizeof(x2));
	memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));
	md = EVP_sm3();
	
	if ( !(t = (unsigned char *)malloc(message_len)) )
	{
		goto clean_up;
	}
	if ( !(ECDH_KDF_X9_62(t,
	                      message_len,
			      x2_y2,
			      sizeof(x2_y2),
			      NULL,
			      0,
			      md)) )
	{
		error_code = COMPUTE_SM2_KDF_FAIL;
		goto clean_up;
	}

	/* If each component of t is zero, the function 
	   returns and reports an error. */
	flag = 1;
	for (i = 0; i < message_len; i++)
	{
		if ( t[i] != 0 )
		{
			flag = 0;
			break;
		}
	}
	if (flag)
	{
		error_code = INVALID_SM2_CIPHERTEXT;
		goto clean_up;
	}
	
	if ( !(M = (unsigned char *)malloc(message_len)) )
	{
		goto clean_up;
	}
	for (i = 0; i < message_len; i++)
	{
		M[i] = c2[i] ^ t[i];
	}

	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
        EVP_DigestUpdate(md_ctx, M, message_len);
	EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
        EVP_DigestFinal_ex(md_ctx, digest, NULL);
	
	if ( memcmp(digest, c3, sizeof(digest)) )
	{
		error_code = INVALID_SM2_CIPHERTEXT;
		goto clean_up;
	}
	memcpy(plaintext, M, message_len);
	error_code = 0;

clean_up:
        if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}

	if (c1_pt)
	{
		EC_POINT_free(c1_pt);
	}
	if (s_pt)
	{
		EC_POINT_free(s_pt);
	}
	if (ec_pt)
	{
		EC_POINT_free(ec_pt);
	}
	
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
	}
	
	if (t)
	{
		free(t);
	}
	if (M)
	{
		free(M);
	}

	return error_code;
}
