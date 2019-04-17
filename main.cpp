#include "sgx_tcrypto.h"
#include "oecrypto/aes.h"
#include "oecrypto/cmac.h"
#include "oecrypto/ec.h"
#include "oecrypto/hash.h"
#include "oecrypto/hmac.h"
#include "oecrypto/kdf.h"
#include "oecrypto/rsa.h"
#include "oecrypto/sha.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct _sgx_ecc_state_handle_impl {
	
} sgx_ecc_state_handle_impl;

// HASHING SHA-256 ONLY

sgx_status_t SGXAPI sgx_sha256_msg(const uint8_t *p_src, uint32_t src_len, sgx_sha256_hash_t *p_hash)
{
	sgx_sha_state_handle_t h;
	sgx_sha256_init(&h);
	sgx_sha256_update(p_src, src_len, h);
	sgx_sha256_get_hash(h, p_hash);
	sgx_sha1_close(h);
	return 0;
}

sgx_status_t SGXAPI sgx_sha256_init(sgx_sha_state_handle_t* p_sha_handle)
{
	oe_sha256_context_t* ctx = (oe_sha256_context_t*) malloc(sizeof(oe_sha256_context_t));
	oe_sha256_init(ctx);
	*p_sha_handle = ctx;
	return 0;
}

sgx_status_t SGXAPI sgx_sha256_update(const uint8_t *p_src, uint32_t src_len, sgx_sha_state_handle_t sha_handle)
{
	oe_sha256_update((oe_sha256_context_t*) sha_handle, p_src, src_len);
	return 0;
}

sgx_status_t SGXAPI sgx_sha256_get_hash(sgx_sha_state_handle_t sha_handle, sgx_sha256_hash_t *p_hash)
{
	OE_SHA256 hash;
	oe_sha256_final((oe_sha256_context_t*)sha_handle, &hash);
	memcpy(p_hash, hash.buf, sizeof(hash.buf));
	// Also, can just send sgx_sha256_hash_t to OE function, since OE_SHA256 and sgx_sha256_hash_t are both 32 byte arrays.
	return 0;
}

sgx_status_t SGXAPI sgx_sha256_close(sgx_sha_state_handle_t sha_handle)
{
	free(sha_handle);
	return 0;
}

sgx_status_t SGXAPI sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t* p_key,
	const uint8_t *p_src,
	uint32_t src_len,
	uint8_t *p_dst,
	const uint8_t *p_iv,
	uint32_t iv_len,
	const uint8_t *p_aad,
	uint32_t aad_len,
	sgx_aes_gcm_128bit_tag_t *p_out_mac)
{
	oe_aes_gcm_context_t* ctx = NULL;

	oe_aes_gcm_init(&ctx, (const uint8_t*) p_key, sizeof(*p_key), p_iv, iv_len, p_aad, aad_len, true);
	for (uint32_t i = 0; i < src_len; i += 16)
	{
		uint32_t len = (src_len - i < 16) ? src_len - i : 16;
		oe_aes_gcm_update(ctx, p_src + i, p_dst + i, len);
	}
	oe_aes_gcm_final(ctx, (oe_aes_gcm_tag_t*)p_out_mac);
	oe_aes_gcm_free(ctx);

	return 0;
}

sgx_status_t SGXAPI sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *p_key,
	const uint8_t *p_src,
	uint32_t src_len,
	uint8_t *p_dst,
	const uint8_t *p_iv,
	uint32_t iv_len,
	const uint8_t *p_aad,
	uint32_t aad_len,
	const sgx_aes_gcm_128bit_tag_t *p_in_mac)
{
	oe_aes_gcm_context_t* ctx = NULL;
	oe_aes_gcm_tag_t mac;

	oe_aes_gcm_init(&ctx, (const uint8_t*)p_key, sizeof(*p_key), p_iv, iv_len, p_aad, aad_len, false);
	for (uint32_t i = 0; i < src_len; i += 16)
	{
		uint32_t len = (src_len - i < 16) ? src_len - i : 16;
		oe_aes_gcm_update(ctx, p_src + i, p_dst + i, len);
	}

	oe_aes_gcm_final(ctx, &mac);
	oe_aes_gcm_free(ctx);

	if (memcmp(mac.buf, p_in_mac, sizeof(mac.buf)) != 0)
	{
		memset(p_dst, 0, src_len);
		return -1;
	}
		
	return 0;
}

sgx_status_t SGXAPI sgx_rijndael128_cmac_msg(
	const sgx_cmac_128bit_key_t *p_key,
	const uint8_t *p_src,
	uint32_t src_len,
	sgx_cmac_128bit_tag_t *p_mac)
{
	oe_aes_cmac_t cmac;
	oe_aes_cmac_sign(*p_key, sizeof(sgx_cmac_128bit_key_t), p_src, src_len, &cmac);
	memcpy(*p_mac, &cmac.impl, sizeof(*p_mac));
	return 0;
}

sgx_status_t SGXAPI sgx_cmac128_init(const sgx_cmac_128bit_key_t *p_key, sgx_cmac_state_handle_t* p_cmac_handle)
{
	oe_aes_cmac_context_t* ctx;
	oe_aes_cmac_init(&ctx, (const uint8_t*)p_key, sizeof(*p_key));
	*p_cmac_handle = ctx;
	return 0;
}

sgx_status_t SGXAPI sgx_cmac128_update(const uint8_t *p_src, uint32_t src_len, sgx_cmac_state_handle_t cmac_handle)
{
	oe_aes_cmac_update((oe_aes_cmac_context_t*)cmac_handle, p_src, src_len);
	return 0;
}

sgx_status_t SGXAPI sgx_cmac128_final(sgx_cmac_state_handle_t cmac_handle, sgx_cmac_128bit_tag_t *p_hash)
{
	oe_aes_cmac_t cmac;
	oe_aes_cmac_final((oe_aes_cmac_context_t*)cmac_handle, &cmac);
	memcpy(p_hash, &cmac.impl, sizeof(cmac));
	return 0;
}

sgx_status_t SGXAPI sgx_cmac128_close(sgx_cmac_state_handle_t cmac_handle)
{
	oe_aes_cmac_free((oe_aes_cmac_context_t*)cmac_handle);
	return 0;
}

sgx_status_t SGXAPI sgx_hmac_sha256_msg(
	const unsigned char *p_src,
	int src_len,
	const unsigned char *p_key,
	int key_len,
	unsigned char *p_mac,
	int mac_len)
{
	sgx_hmac_state_handle_t hmac;
	sgx_hmac256_init(p_key, key_len, &hmac);
	sgx_hmac256_update(p_src, src_len, &hmac);
	sgx_hmac256_final(p_mac, mac_len, &hmac);
	sgx_hmac256_close(hmac);
	return 0;
}

sgx_status_t SGXAPI sgx_hmac256_init(
	const unsigned char *p_key,
	int key_len,
	sgx_hmac_state_handle_t *p_hmac_handle)
{
	oe_hmac_sha256_context_t* hmac = (oe_hmac_sha256_context_t*)malloc(sizeof(oe_hmac_sha256_context_t));
	oe_hmac_sha256_init(hmac, p_key, key_len);
	*p_hmac_handle = hmac;
	return 0;
}

sgx_status_t SGXAPI sgx_hmac256_update(const uint8_t *p_src, int src_len, sgx_hmac_state_handle_t hmac_handle)
{
	oe_hmac_sha256_update((oe_hmac_sha256_context_t*)hmac_handle, p_src, src_len);
	return 0;
}

sgx_status_t SGXAPI sgx_hmac256_final(unsigned char *p_hash, int hash_len, sgx_hmac_state_handle_t hmac_handle)
{
	OE_SHA256 sha256;
	oe_hmac_sha256_final((oe_hmac_sha256_context_t*)hmac_handle, &sha256);
	memcpy(p_hash, sha256.buf, sizeof(sha256.buf));
	return 0;
}

sgx_status_t SGXAPI sgx_hmac256_close(sgx_hmac_state_handle_t hmac_handle)
{
	oe_hmac_sha256_free((oe_hmac_sha256_context_t*)hmac_handle);
	free(hmac_handle);
	return 0;
}

sgx_status_t SGXAPI sgx_aes_ctr_encrypt(
	const sgx_aes_ctr_128bit_key_t *p_key,
	const uint8_t *p_src,
	const uint32_t src_len,
	uint8_t *p_ctr,
	const uint32_t ctr_inc_bits,
	uint8_t *p_dst)
{
	oe_aes_ctr_context_t* ctx;

	oe_aes_ctr_init(&ctx, (const uint8_t*)p_key, sizeof(*p_key), p_ctr, ctr_inc_bits / 8, true);
	oe_aes_ctr_crypt(ctx, p_src, p_dst, src_len);
	oe_aes_ctr_free(ctx);
	return 0;
}

sgx_status_t SGXAPI sgx_aes_ctr_decrypt(
	const sgx_aes_ctr_128bit_key_t *p_key,
	const uint8_t *p_src,
	const uint32_t src_len,
	uint8_t *p_ctr,
	const uint32_t ctr_inc_bits,
	uint8_t *p_dst)
{
	oe_aes_ctr_context_t* ctx;

	oe_aes_ctr_init(&ctx, (const uint8_t*)p_key, sizeof(*p_key), p_ctr, ctr_inc_bits / 8, false);
	oe_aes_ctr_crypt(ctx, p_src, p_dst, src_len);
	oe_aes_ctr_free(ctx);
	return 0;
}

sgx_status_t SGXAPI sgx_ecc256_open_context(sgx_ecc_state_handle_t* p_ecc_handle)
{
	*p_ecc_handle = (sgx_ecc_state_handle_t)OE_EC_TYPE_SECP256R1;
	return 0;
}

sgx_status_t SGXAPI sgx_ecc256_close_context(sgx_ecc_state_handle_t ecc_handle)
{
	/* Don't need to do anything with the handle. */
	return 0;
}

sgx_status_t SGXAPI sgx_ecc256_create_key_pair(sgx_ec256_private_t *p_private,
	sgx_ec256_public_t *p_public,
	sgx_ecc_state_handle_t ecc_handle)
{
	oe_ec_private_key_t privkey;
	oe_ec_public_key_t pubkey;
	oe_ec_generate_key_pair((oe_ec_type_t) (int) ecc_handle, &privkey, &pubkey);

	// Export
	oe_ec_type_t type;
	size_t privkey_size = sizeof(*p_private);
	size_t pubkey_x_size = sizeof(p_public->gx);
	size_t pubkey_y_size = sizeof(p_public->gy);

	oe_ec_private_key_to_buffer(
		&privkey,
		&type,
		(uint8_t*)p_private,
		&privkey_size);

	oe_ec_public_key_to_coordinates(
		&pubkey,
		&type,
		(uint8_t*)p_public->gx,
		&pubkey_x_size,
		(uint8_t*)p_public->gy,
		&pubkey_y_size);

	return 0;
}

sgx_status_t sgx_ecc256_check_point(
	const sgx_ec256_public_t *p_point,
	const sgx_ecc_state_handle_t ecc_handle,
	int *p_valid)
{
	oe_result_t result = oe_ec_valid_raw_public_key(
		(oe_ec_type_t)(int)ecc_handle,
		p_point->gx,
		sizeof(p_point->gx),
		p_point->gy,
		sizeof(p_point->gy));

	*p_valid = (result == 0);
	return 0;
}

sgx_status_t SGXAPI sgx_ecc256_compute_shared_dhkey(sgx_ec256_private_t *p_private_b,
	sgx_ec256_public_t *p_public_ga,
	sgx_ec256_dh_shared_t *p_shared_key,
	sgx_ecc_state_handle_t ecc_handle)
{
	oe_ec_private_key_t privkey;
	oe_ec_private_key_from_buffer(&privkey, (oe_ec_type_t)(int)ecc_handle, p_private_b->r, sizeof(p_private_b->r));

	oe_ec_public_key_t pubkey;
	oe_ec_public_key_from_coordinates(
		&pubkey,
		(oe_ec_type_t)(int)ecc_handle,
		p_public_ga->gx,
		sizeof(p_public_ga->gx),
		p_public_ga->gy,
		sizeof(p_public_ga->gy));

	size_t sz = sizeof(p_shared_key->s);
	oe_ecdh_compute_shared_secret(
		&privkey,
		&pubkey,
		p_shared_key->s,
		&sz);
	return 0;
}

sgx_status_t SGXAPI sgx_ecdsa_sign(const uint8_t *p_data,
	uint32_t data_size,
	sgx_ec256_private_t *p_private,
	sgx_ec256_signature_t *p_signature,
	sgx_ecc_state_handle_t ecc_handle)
{
	oe_ec_private_key_t privkey;
	oe_ec_private_key_from_buffer(&privkey, (oe_ec_type_t)(int)ecc_handle, p_private->r, sizeof(p_private->r));

	sgx_sha256_hash_t hash;
	sgx_sha256_msg(p_data, data_size, &hash);

	/* sgx signature is uint32_t[] instead of uint8_t[]. just cast it for the prototype. */
	size_t xsz = sizeof(p_signature->x);
	size_t ysz = sizeof(p_signature->y);
	oe_ecdsa_signature_sign(
		&privkey,
		OE_HASH_TYPE_SHA256,
		&hash,
		sizeof(hash),
		(uint8_t*)p_signature->x,
		&xsz,
		(uint8_t*)p_signature->y,
		&ysz);
	return 0;
}

sgx_status_t SGXAPI sgx_ecdsa_verify(const uint8_t *p_data,
	uint32_t data_size,
	const sgx_ec256_public_t *p_public,
	sgx_ec256_signature_t *p_signature,
	uint8_t *p_result,
	sgx_ecc_state_handle_t ecc_handle)
{
	oe_ec_public_key_t pubkey;
	oe_ec_public_key_from_coordinates(
		&pubkey,
		(oe_ec_type_t)(int)ecc_handle,
		p_public->gx,
		sizeof(p_public->gx),
		p_public->gy,
		sizeof(p_public->gy));

	uint8_t sig[128];
	size_t sig_size = sizeof(sig);
	oe_ecdsa_signature_write_der(
		sig,
		&sig_size,
		(const uint8_t*)p_signature->x,
		sizeof(p_signature->x),
		(const uint8_t*)p_signature->y,
		sizeof(p_signature->y));

	sgx_sha256_hash_t hash;
	sgx_sha256_msg(p_data, data_size, &hash);

	oe_result_t res = 
		oe_ec_public_key_verify(&pubkey, OE_HASH_TYPE_SHA256, &hash, sizeof(hash), sig, sig_size);

	*p_result = res == 0;
	return 0;
}

sgx_status_t SGXAPI sgx_ecdsa_verify_hash(const uint8_t *p_data,
	const sgx_ec256_public_t *p_public,
	sgx_ec256_signature_t *p_signature,
	uint8_t *p_result,
	sgx_ecc_state_handle_t ecc_handle)
{
	oe_ec_public_key_t pubkey;
	oe_ec_public_key_from_coordinates(
		&pubkey,
		(oe_ec_type_t)(int)ecc_handle,
		p_public->gx,
		sizeof(p_public->gx),
		p_public->gy,
		sizeof(p_public->gy));

	uint8_t sig[128];
	size_t sig_size = sizeof(sig);
	oe_ecdsa_signature_write_der(
		sig,
		&sig_size,
		(const uint8_t*)p_signature->x,
		sizeof(p_signature->x),
		(const uint8_t*)p_signature->y,
		sizeof(p_signature->y));

	oe_result_t res =
		oe_ec_public_key_verify(&pubkey, OE_HASH_TYPE_SHA256, p_data, OE_SHA256_SIZE, sig, sig_size);

	*p_result = res == 0;

	return 0;
}

sgx_status_t sgx_rsa3072_sign(const uint8_t *p_data,
	uint32_t data_size,
	const sgx_rsa3072_key_t *p_key,
	sgx_rsa3072_signature_t *p_signature)
{
	oe_rsa_private_key_t key;

	// Load params
	oe_rsa_private_key_load_parameters(&key, p_key->mod, sizeof(p_key->mod), p_key->d, sizeof(p_key->d), p_key->e, sizeof(p_key->e));

	// Hash first
	sgx_sha256_hash_t hash;
	sgx_sha256_msg(p_data, data_size, &hash);

	// Now sign
	size_t sig_size = sizeof(*p_signature);
	oe_rsa_private_key_sign(&key, OE_HASH_TYPE_SHA256, &hash, sizeof(hash), (uint8_t*) p_signature, &sig_size);
	return 0;
}

sgx_status_t sgx_rsa3072_verify(const uint8_t *p_data,
	uint32_t data_size,
	const sgx_rsa3072_public_key_t *p_public,
	const sgx_rsa3072_signature_t *p_signature,
	sgx_rsa_result_t *p_result)
{
	oe_rsa_public_key_t key;

	// Load params
	oe_rsa_public_key_load_parameters(&key, p_public->mod, sizeof(p_public->mod), p_public->exp, sizeof(p_public->exp));

	// Hash first
	sgx_sha256_hash_t hash;
	sgx_sha256_msg(p_data, data_size, &hash);

	// Now verify
	size_t sig_size = sizeof(*p_signature);
	oe_result_t res =  oe_rsa_public_key_verify(&key, OE_HASH_TYPE_SHA256, &hash, sizeof(hash), (const uint8_t*)p_signature, sizeof(*p_signature));

	// check for res == OE_VERIFY_FAILED. Set p_result appropriately.
	return 0;
}

sgx_status_t sgx_create_rsa_key_pair(int n_byte_size, int e_byte_size, unsigned char *p_n, unsigned char *p_d, unsigned char *p_e,
	unsigned char *p_p, unsigned char *p_q, unsigned char *p_dmp1,
	unsigned char *p_dmq1, unsigned char *p_iqmp)
{
	if (e_byte_size > 8)
		return -1;

	uint64_t num = 0;
	for (int i = 0; i < e_byte_size; i++)
	{
		num |= (p_e[i] << (8 * i));
	}

	oe_rsa_public_key_t public_key;
	oe_rsa_private_key_t private_key;
	oe_rsa_generate_key_pair(n_byte_size * 8, num, &private_key, &public_key);

	size_t nsz = n_byte_size;
	size_t psz = n_byte_size / 2;
	size_t qsz = n_byte_size / 2;
	size_t dsz = n_byte_size;
	size_t esz = e_byte_size;
	oe_rsa_private_key_get_parameters(
		&private_key,
		p_n,
		&nsz,
		p_p,
		&psz,
		p_q,
		&qsz,
		p_d,
		&dsz,
		p_e,
		&esz);

	size_t dpsz = n_byte_size / 2;
	size_t dqsz = n_byte_size / 2;
	size_t dinvsz = n_byte_size / 2;
	oe_rsa_private_key_get_crt_parameters(
		&private_key,
		p_dmp1,
		&dpsz,
		p_dmq1,
		&dqsz,
		p_iqmp,
		&dinvsz);
	
	oe_rsa_private_key_free(&private_key);
	oe_rsa_public_key_free(&public_key);
	return 0;
}

sgx_status_t sgx_rsa_priv_decrypt_sha256(void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len)
{
	oe_rsa_private_key_decrypt((const oe_rsa_private_key_t*)rsa_key, pin_data, pin_len, pout_data, pout_len);
	return 0;
}

sgx_status_t sgx_rsa_pub_encrypt_sha256(void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len)
{
	oe_rsa_public_key_encrypt((const oe_rsa_public_key_t*)rsa_key, pin_data, pin_len, pout_data, pout_len);
	return 0;
}

sgx_status_t sgx_create_rsa_priv2_key(int mod_size, int exp_size, const unsigned char *p_rsa_key_e, const unsigned char *p_rsa_key_p, const unsigned char *p_rsa_key_q,
	const unsigned char *p_rsa_key_dmp1, const unsigned char *p_rsa_key_dmq1, const unsigned char *p_rsa_key_iqmp,
	void **new_pri_key2)
{
	unsigned char* be_p = (unsigned char*)malloc(mod_size / 2);
	unsigned char* be_q = (unsigned char*)malloc(mod_size / 2);
	unsigned char* be_e = (unsigned char*)malloc(exp_size);
	oe_rsa_private_key_t* key = (oe_rsa_private_key_t*)malloc(sizeof(oe_rsa_private_key_t));

	for (int i = 0; i < mod_size / 2; i++)
	{
		be_p[i] = p_rsa_key_p[mod_size / 2 - 1 - i];
		be_q[i] = p_rsa_key_q[mod_size / 2 - 1 - i];
	}

	for (int i = 0; i < exp_size; i++)
	{
		be_e[i] = p_rsa_key_e[exp_size - 1 - i];
	}

	// Other params are uneeded.
	oe_rsa_private_key_load_parameters(key, be_p, mod_size / 2, be_q, mod_size / 2, be_e, exp_size);
	*new_pri_key2 = key;

	free(be_p);
	free(be_q);
	free(be_e);
	return 0;
}

sgx_status_t sgx_create_rsa_pub1_key(int mod_size, int exp_size, const unsigned char *le_n, const unsigned char *le_e, void **new_pub_key1)
{
	unsigned char* be_n = (unsigned char*)malloc(mod_size);
	unsigned char* be_e = (unsigned char*)malloc(exp_size);
	oe_rsa_public_key_t* key = (oe_rsa_public_key_t*)malloc(sizeof(oe_rsa_public_key_t));

	for (int i = 0; i < mod_size; i++)
	{
		be_n[i] = le_n[mod_size - 1 - i];
	}

	for (int i = 0; i < exp_size; i++)
	{
		be_e[i] = le_e[exp_size - 1 - i];
	}

	oe_rsa_public_key_load_parameters(key, be_n, mod_size, be_e, exp_size);
	*new_pub_key1 = key;
	free(be_n);
	free(be_e);
	return 0;
}

sgx_status_t sgx_free_rsa_key(void *p_rsa_key, sgx_rsa_key_type_t key_type, int mod_size, int exp_size)
{
	if (key_type == SGX_RSA_PRIVATE_KEY)
		oe_rsa_private_key_free((oe_rsa_private_key_t*)p_rsa_key);
	else
		oe_rsa_public_key_free((oe_rsa_public_key_t*)p_rsa_key);
	free(p_rsa_key);
	return 0;
}

sgx_status_t sgx_calculate_ecdsa_priv_key(const unsigned char* hash_drg, int hash_drg_len,
	const unsigned char* sgx_nistp256_r_m1, int sgx_nistp256_r_m1_len,
	unsigned char* out_key, int out_key_len)
{
	// Intel calculates d = (hash_drg mod sgx_nistp256_r_m1) + 1.  This produces a valid private key
	// since d = 1 +  h mod (N - 1), which means d is in [1, N - 1].
	//
	// This is the routine that is done to derive a valid ECC private key in OE from a random seed.

	/* First, derive a key from the given key. */
	uint8_t key[OE_SHA256_SIZE];
	uint8_t key_prev[OE_SHA256_SIZE];

	oe_kdf_derive_key(
		OE_KDF_HMAC_SHA256_CTR,
		hash_drg,
		hash_drg_len,
		NULL,
		0,
		key,
		sizeof(key));

	/*
	 * If the derived key is not a valid ECC private key, then we use the
	 * derived key to derive another candidate key. The main requirement
	 * for the derived key is to be between [1, N-1], where N is the order
	 * (number of points) on the elliptic curve. For most curves, it's
	 * very likely that derived key is already within that range.
	 */
	while (!oe_ec_valid_raw_private_key(OE_EC_TYPE_SECP256R1, key, sizeof(key)))
	{
		/* Copy to a temporary buffer before doing the key derivation. */
		memcpy(key_prev, key, sizeof(key));

		/* Derive a new key. */
		oe_kdf_derive_key(
			OE_KDF_HMAC_SHA256_CTR,
			key_prev,
			sizeof(key_prev),
			NULL,
			0,
			key,
			sizeof(key));
	}
	
	memcpy(out_key, key, out_key_len);
	return 0;
}

sgx_status_t sgx_ecc256_calculate_pub_from_priv(const sgx_ec256_private_t *p_att_priv_key,
	sgx_ec256_public_t  *p_att_pub_key)
{
	oe_ec_public_key_t pkey;
	oe_ec_private_key_t privkey;
	oe_ec_generate_key_pair_from_private(OE_EC_TYPE_SECP256R1, p_att_priv_key->r, sizeof(p_att_priv_key), &privkey, &pkey);
	
	oe_ec_type_t type;
	size_t gxsz = sizeof(p_att_pub_key->gx);
	size_t gysz = sizeof(p_att_pub_key->gy);
	oe_ec_public_key_to_coordinates(&pkey, &type, p_att_pub_key->gx, &gxsz, p_att_pub_key->gy, &gysz);
	oe_ec_private_key_free(&privkey);
	oe_ec_public_key_free(&pkey);
	return 0;
}

sgx_status_t sgx_aes_gcm128_enc_init(
	const uint8_t *p_key,
	const uint8_t *p_iv,
	uint32_t iv_len,
	const uint8_t *p_aad,
	uint32_t aad_len,
	sgx_aes_state_handle_t *aes_gcm_state)
{
	oe_aes_gcm_context_t* ctx = NULL;
	oe_aes_gcm_init(&ctx, (const uint8_t*)p_key, 16, p_iv, iv_len, p_aad, aad_len, true);
	*aes_gcm_state = ctx;
	return 0;
}

sgx_status_t sgx_aes_gcm128_enc_update(
	uint8_t *p_src,
	uint32_t src_len,
	uint8_t *p_dst,
	sgx_aes_state_handle_t aes_gcm_state)
{
	for (uint32_t i = 0; i < src_len; i += 16)
	{
		uint32_t len = (src_len - i < 16) ? src_len - i : 16;
		oe_aes_gcm_update((oe_aes_gcm_context_t*)aes_gcm_state, p_src + i, p_dst + i, len);
	}
	return 0;
}

sgx_status_t sgx_aes_gcm128_enc_get_mac(uint8_t *mac, sgx_aes_state_handle_t aes_gcm_state)
{
	oe_aes_gcm_final((oe_aes_gcm_context_t*)aes_gcm_state, (oe_aes_gcm_tag_t*)mac);
	return 0;
}

sgx_status_t sgx_aes_gcm_close(sgx_aes_state_handle_t aes_gcm_state)
{
	oe_aes_gcm_free((oe_aes_gcm_context_t*)aes_gcm_state);
	return 0;
}

int main(int argc, char** argv)
{
	return 0;
}