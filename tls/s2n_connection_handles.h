/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#pragma once

#include "tls/s2n_connection.h"
#include "tls/s2n_prf.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_evp.h"

/* s2n PRF p_hash components */
struct s2n_connection_prf_handles {
    struct s2n_hash_evp_digest p_hash_s2n_hmac_inner;
    const struct s2n_hash_implementation *p_hash_s2n_hmac_inner_impl;
    struct s2n_hash_evp_digest p_hash_s2n_hmac_inner_just_key;
    const struct s2n_hash_implementation *p_hash_s2n_hmac_inner_just_key_impl;
    struct s2n_hash_evp_digest p_hash_s2n_hmac_outer;
    const struct s2n_hash_implementation *p_hash_s2n_hmac_outer_impl;
    struct s2n_signed_evp_digest p_hash_evp_hmac;
    const struct s2n_p_hash_implementation *p_hash_impl;
};

/* s2n hash state components */
struct s2n_connection_hash_handles {
    struct s2n_hash_evp_digest md5;
    const struct s2n_hash_implementation *md5_hash_impl;
    struct s2n_hash_evp_digest sha1;
    const struct s2n_hash_implementation *sha1_hash_impl;
    struct s2n_hash_evp_digest sha224;
    const struct s2n_hash_implementation *sha224_hash_impl;
    struct s2n_hash_evp_digest sha256;
    const struct s2n_hash_implementation *sha256_hash_impl;
    struct s2n_hash_evp_digest sha384;
    const struct s2n_hash_implementation *sha384_hash_impl;
    struct s2n_hash_evp_digest sha512;
    const struct s2n_hash_implementation *sha512_hash_impl;
    struct s2n_hash_evp_digest md5_sha1;
    const struct s2n_hash_implementation *md5_sha1_hash_impl;
    struct s2n_hash_evp_digest md5_copy_working_space;
    const struct s2n_hash_implementation *md5_copy_working_space_hash_impl;
    struct s2n_hash_evp_digest sha1_copy_working_space;
    const struct s2n_hash_implementation *sha1_copy_working_space_hash_impl;
    struct s2n_hash_evp_digest hash_copy_working_space;
    const struct s2n_hash_implementation *hash_copy_working_space_hash_impl;
    struct s2n_hash_evp_digest prf_md5;
    const struct s2n_hash_implementation *prf_md5_hash_impl;
    struct s2n_hash_evp_digest prf_sha1;
    const struct s2n_hash_implementation *prf_sha1_hash_impl;
    struct s2n_hash_evp_digest initial_signature_hash;
    const struct s2n_hash_implementation *initial_signature_hash_impl;
    struct s2n_hash_evp_digest secure_signature_hash;
    const struct s2n_hash_implementation *secure_signature_hash_impl;
};

/* s2n hmac state components from hash states within each hmac */
struct s2n_connection_hmac_handles {
    struct s2n_hash_evp_digest initial_client_mac_inner;
    const struct s2n_hash_implementation *initial_client_mac_inner_impl;
    struct s2n_hash_evp_digest initial_client_mac_inner_just_key;
    const struct s2n_hash_implementation *initial_client_mac_inner_just_key_impl;
    struct s2n_hash_evp_digest initial_client_mac_outer;
    const struct s2n_hash_implementation *initial_client_mac_outer_impl;
    struct s2n_hash_evp_digest initial_client_mac_copy_inner;
    const struct s2n_hash_implementation *initial_client_mac_copy_inner_impl;
    struct s2n_hash_evp_digest initial_client_mac_copy_inner_just_key;
    const struct s2n_hash_implementation *initial_client_mac_copy_inner_just_key_impl;
    struct s2n_hash_evp_digest initial_client_mac_copy_outer;
    const struct s2n_hash_implementation *initial_client_mac_copy_outer_impl;
    struct s2n_hash_evp_digest initial_server_mac_inner;
    const struct s2n_hash_implementation *initial_server_mac_inner_impl;
    struct s2n_hash_evp_digest initial_server_mac_inner_just_key;
    const struct s2n_hash_implementation *initial_server_mac_inner_just_key_impl;
    struct s2n_hash_evp_digest initial_server_mac_outer;
    const struct s2n_hash_implementation *initial_server_mac_outer_impl;
    struct s2n_hash_evp_digest secure_client_mac_inner;
    const struct s2n_hash_implementation *secure_client_mac_inner_impl;
    struct s2n_hash_evp_digest secure_client_mac_inner_just_key;
    const struct s2n_hash_implementation *secure_client_mac_inner_just_key_impl;
    struct s2n_hash_evp_digest secure_client_mac_outer;
    const struct s2n_hash_implementation *secure_client_mac_outer_impl;
    struct s2n_hash_evp_digest secure_client_mac_copy_inner;
    const struct s2n_hash_implementation *secure_client_mac_copy_inner_impl;
    struct s2n_hash_evp_digest secure_client_mac_copy_inner_just_key;
    const struct s2n_hash_implementation *secure_client_mac_copy_inner_just_key_impl;
    struct s2n_hash_evp_digest secure_client_mac_copy_outer;
    const struct s2n_hash_implementation *secure_client_mac_copy_outer_impl;
    struct s2n_hash_evp_digest secure_server_mac_inner;
    const struct s2n_hash_implementation *secure_server_mac_inner_impl;
    struct s2n_hash_evp_digest secure_server_mac_inner_just_key;
    const struct s2n_hash_implementation *secure_server_mac_inner_just_key_impl;
    struct s2n_hash_evp_digest secure_server_mac_outer;
    const struct s2n_hash_implementation *secure_server_mac_outer_impl;
};

extern int stash_prf_handles(struct s2n_connection_prf_handles *prf_handles, struct s2n_connection *conn);
extern int stash_hash_handles(struct s2n_connection_hash_handles *hash_handles, struct s2n_connection *conn);
extern int stash_hmac_handles(struct s2n_connection_hmac_handles *hmac_handles, struct s2n_connection *conn);
extern int restore_prf_handles(struct s2n_connection *conn, struct s2n_connection_prf_handles *prf_handles);
extern int restore_hash_handles(struct s2n_connection *conn, struct s2n_connection_hash_handles *hash_handles);
extern int restore_hmac_handles(struct s2n_connection *conn, struct s2n_connection_hmac_handles *hmac_handles);
