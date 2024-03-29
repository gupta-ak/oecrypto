// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_KDF_H
#define _OE_KDF_H

#include "fix.h"

OE_EXTERNC_BEGIN

/* Key deriviation functions specified by NIST SP800-108 */
typedef enum _oe_kdf_mode
{
    OE_KDF_HMAC_SHA256_CTR
} oe_kdf_mode_t;

/**
 * Creates the fixed data as specified by NIST SP800-108.
 * Specfically, it produces the byte array in the form of
 * Label || 0x00 || Context || OutputKeySizeInBits.
 *
 * @param label The label data
 * @param label_size The length of the label
 * @param context The context data
 * @param context_size The length of the context
 * @param output_key_size The size of the desired derived key in bytes
 * @param fixed_data The pointer to an output buffer where the fixed data
 * will be written to
 * @param fixed_data_size The size of the output fixed data buffer
 *
 * @return OE_OK upon success
 * @return OE_CONSTRAINT_FAILED if derived key size is too large
 * @return OE_FAILURE if there is generic failure
 * @return OE_INVALID_PARAMETER if there is an invalid parameter
 * @return OE_OUT_OF_MEMORY if there is no memory available
 */
oe_result_t oe_kdf_create_fixed_data(
    const uint8_t* label,
    size_t label_size,
    const uint8_t* context,
    size_t context_size,
    size_t output_key_size,
    uint8_t** fixed_data,
    size_t* fixed_data_size);

/**
 * Derives a key based off the input key and some user defined data.
 * The key will be derived using the algorithms specified by NIST SP800-108.
 *
 * @param mode The KDF algorithm to use.
 * @param key The key used to derive the output key
 * @param key_size The size of the input key
 * @param fixed_data The optional user-defined data used to derive the key
 * @param fixed_data_size The size of the optional user-defined data
 * @param derived_key The buffer where the output key will be written to
 * @param derived_key_size The size of the output key
 *
 * @return OE_OK upon success
 * @return OE_CONSTRAINT_FAILED if derived key size is too large
 * @return OE_FAILURE if there is generic failure
 * @return OE_INVALID_PARAMETER if there is an invalid parameter
 * @return OE_OUT_OF_MEMORY if there is no memory available
 */
oe_result_t oe_kdf_derive_key(
    oe_kdf_mode_t mode,
    const uint8_t* key,
    size_t key_size,
    const uint8_t* fixed_data,
    size_t fixed_data_size,
    uint8_t* derived_key,
    size_t derived_key_size);

OE_EXTERNC_END

#endif /* _OE_KDF_H */
