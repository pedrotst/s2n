/*
 * Copyright 2017 Amazon.com = Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License = Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS = WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND = either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "tls/s2n_connection_handles.h"

#include "utils/s2n_safety.h"

int stash_prf_handles(struct s2n_connection_prf_handles *prf_handles, struct s2n_connection *conn)
{
    /* Preserve handlers for PRF's p_hash to avoid re-allocation */
    prf_handles->p_hash_s2n_hmac_inner = conn->prf_space.tls.p_hash.s2n_hmac.inner.digest.evp;
    prf_handles->p_hash_s2n_hmac_inner_impl = conn->prf_space.tls.p_hash.s2n_hmac.inner.hash_impl;
    prf_handles->p_hash_s2n_hmac_inner_just_key = conn->prf_space.tls.p_hash.s2n_hmac.inner_just_key.digest.evp;
    prf_handles->p_hash_s2n_hmac_inner_just_key_impl = conn->prf_space.tls.p_hash.s2n_hmac.inner_just_key.hash_impl;
    prf_handles->p_hash_s2n_hmac_outer = conn->prf_space.tls.p_hash.s2n_hmac.outer.digest.evp;
    prf_handles->p_hash_s2n_hmac_outer_impl = conn->prf_space.tls.p_hash.s2n_hmac.outer.hash_impl;
    prf_handles->p_hash_evp_hmac = conn->prf_space.tls.p_hash.evp_hmac;
    prf_handles->p_hash_impl = conn->prf_space.tls.p_hash_impl;

    return 0;
}

int stash_hash_handles(struct s2n_connection_hash_handles *hash_handles, struct s2n_connection *conn)
{
    /* Preserve handlers for hash states to avoid re-allocation */
    hash_handles->md5 = conn->handshake.md5.digest.evp;
    hash_handles->md5_hash_impl = conn->handshake.md5.hash_impl;
    hash_handles->sha1 = conn->handshake.sha1.digest.evp;
    hash_handles->sha1_hash_impl = conn->handshake.sha1.hash_impl;    
    hash_handles->sha224 = conn->handshake.sha224.digest.evp;
    hash_handles->sha224_hash_impl = conn->handshake.sha224.hash_impl;
    hash_handles->sha256 = conn->handshake.sha256.digest.evp;
    hash_handles->sha256_hash_impl = conn->handshake.sha256.hash_impl;
    hash_handles->sha384 = conn->handshake.sha384.digest.evp;
    hash_handles->sha384_hash_impl = conn->handshake.sha384.hash_impl;
    hash_handles->sha512 = conn->handshake.sha512.digest.evp;
    hash_handles->sha512_hash_impl = conn->handshake.sha512.hash_impl;
    hash_handles->md5_sha1 = conn->handshake.md5_sha1.digest.evp;
    hash_handles->md5_sha1_hash_impl = conn->handshake.md5_sha1.hash_impl;
    hash_handles->md5_copy_working_space = conn->handshake.md5_copy_working_space.digest.evp;
    hash_handles->md5_copy_working_space_hash_impl = conn->handshake.md5_copy_working_space.hash_impl;
    hash_handles->sha1_copy_working_space = conn->handshake.sha1_copy_working_space.digest.evp;
    hash_handles->sha1_copy_working_space_hash_impl = conn->handshake.sha1_copy_working_space.hash_impl;
    hash_handles->hash_copy_working_space = conn->handshake.hash_copy_working_space.digest.evp;
    hash_handles->hash_copy_working_space_hash_impl = conn->handshake.hash_copy_working_space.hash_impl;
    hash_handles->prf_md5 = conn->prf_space.ssl3.md5.digest.evp;
    hash_handles->prf_md5_hash_impl = conn->prf_space.ssl3.md5.hash_impl;
    hash_handles->prf_sha1 = conn->prf_space.ssl3.sha1.digest.evp;
    hash_handles->prf_sha1_hash_impl = conn->prf_space.ssl3.sha1.hash_impl;
    hash_handles->initial_signature_hash = conn->initial.signature_hash.digest.evp;
    hash_handles->initial_signature_hash_impl = conn->initial.signature_hash.hash_impl;
    hash_handles->secure_signature_hash = conn->secure.signature_hash.digest.evp;
    hash_handles->secure_signature_hash_impl = conn->secure.signature_hash.hash_impl;

    return 0;
}

int stash_hmac_handles(struct s2n_connection_hmac_handles *hmac_handles, struct s2n_connection *conn)
{
    /* Preserve handlers for hmac states to avoid re-allocation */
    hmac_handles->initial_client_mac_inner = conn->initial.client_record_mac.inner.digest.evp;
    hmac_handles->initial_client_mac_inner_impl = conn->initial.client_record_mac.inner.hash_impl;
    hmac_handles->initial_client_mac_inner_just_key = conn->initial.client_record_mac.inner_just_key.digest.evp;
    hmac_handles->initial_client_mac_inner_just_key_impl = conn->initial.client_record_mac.inner_just_key.hash_impl;
    hmac_handles->initial_client_mac_outer = conn->initial.client_record_mac.outer.digest.evp;
    hmac_handles->initial_client_mac_outer_impl = conn->initial.client_record_mac.outer.hash_impl;
    hmac_handles->initial_client_mac_copy_inner = conn->initial.client_record_mac_copy.inner.digest.evp;
    hmac_handles->initial_client_mac_copy_inner_impl = conn->initial.client_record_mac_copy.inner.hash_impl;
    hmac_handles->initial_client_mac_copy_inner_just_key = conn->initial.client_record_mac_copy.inner_just_key.digest.evp;
    hmac_handles->initial_client_mac_copy_inner_just_key_impl = conn->initial.client_record_mac_copy.inner_just_key.hash_impl;
    hmac_handles->initial_client_mac_copy_outer = conn->initial.client_record_mac_copy.outer.digest.evp;
    hmac_handles->initial_client_mac_copy_outer_impl = conn->initial.client_record_mac_copy.outer.hash_impl;
    hmac_handles->initial_server_mac_inner = conn->initial.server_record_mac.inner.digest.evp;
    hmac_handles->initial_server_mac_inner_impl = conn->initial.server_record_mac.inner.hash_impl;
    hmac_handles->initial_server_mac_inner_just_key = conn->initial.server_record_mac.inner_just_key.digest.evp;
    hmac_handles->initial_server_mac_inner_just_key_impl = conn->initial.server_record_mac.inner_just_key.hash_impl;
    hmac_handles->initial_server_mac_outer = conn->initial.server_record_mac.outer.digest.evp;
    hmac_handles->initial_server_mac_outer_impl = conn->initial.server_record_mac.outer.hash_impl;
    hmac_handles->secure_client_mac_inner = conn->secure.client_record_mac.inner.digest.evp;
    hmac_handles->secure_client_mac_inner_impl = conn->secure.client_record_mac.inner.hash_impl;
    hmac_handles->secure_client_mac_inner_just_key = conn->secure.client_record_mac.inner_just_key.digest.evp;
    hmac_handles->secure_client_mac_inner_just_key_impl = conn->secure.client_record_mac.inner_just_key.hash_impl;
    hmac_handles->secure_client_mac_outer = conn->secure.client_record_mac.outer.digest.evp;
    hmac_handles->secure_client_mac_outer_impl = conn->secure.client_record_mac.outer.hash_impl;
    hmac_handles->secure_client_mac_copy_inner = conn->secure.client_record_mac_copy.inner.digest.evp;
    hmac_handles->secure_client_mac_copy_inner_impl = conn->secure.client_record_mac_copy.inner.hash_impl;
    hmac_handles->secure_client_mac_copy_inner_just_key = conn->secure.client_record_mac_copy.inner_just_key.digest.evp;
    hmac_handles->secure_client_mac_copy_inner_just_key_impl = conn->secure.client_record_mac_copy.inner_just_key.hash_impl;
    hmac_handles->secure_client_mac_copy_outer = conn->secure.client_record_mac_copy.outer.digest.evp;
    hmac_handles->secure_client_mac_copy_outer_impl = conn->secure.client_record_mac_copy.outer.hash_impl;
    hmac_handles->secure_server_mac_inner = conn->secure.server_record_mac.inner.digest.evp;
    hmac_handles->secure_server_mac_inner_impl = conn->secure.server_record_mac.inner.hash_impl;
    hmac_handles->secure_server_mac_inner_just_key = conn->secure.server_record_mac.inner_just_key.digest.evp;
    hmac_handles->secure_server_mac_inner_just_key_impl = conn->secure.server_record_mac.inner_just_key.hash_impl;
    hmac_handles->secure_server_mac_outer = conn->secure.server_record_mac.outer.digest.evp;
    hmac_handles->secure_server_mac_outer_impl = conn->secure.server_record_mac.outer.hash_impl;

    return 0;
}

int restore_prf_handles(struct s2n_connection *conn, struct s2n_connection_prf_handles *prf_handles)
{
    /* Restore s2n_connection handlers for PRF's p_hash */
    conn->prf_space.tls.p_hash.s2n_hmac.inner.digest.evp = prf_handles->p_hash_s2n_hmac_inner;
    conn->prf_space.tls.p_hash.s2n_hmac.inner.hash_impl = prf_handles->p_hash_s2n_hmac_inner_impl;
    conn->prf_space.tls.p_hash.s2n_hmac.inner_just_key.digest.evp = prf_handles->p_hash_s2n_hmac_inner_just_key;
    conn->prf_space.tls.p_hash.s2n_hmac.inner_just_key.hash_impl = prf_handles->p_hash_s2n_hmac_inner_just_key_impl;
    conn->prf_space.tls.p_hash.s2n_hmac.outer.digest.evp = prf_handles->p_hash_s2n_hmac_outer;
    conn->prf_space.tls.p_hash.s2n_hmac.outer.hash_impl = prf_handles->p_hash_s2n_hmac_outer_impl;
    conn->prf_space.tls.p_hash.evp_hmac = prf_handles->p_hash_evp_hmac;
    conn->prf_space.tls.p_hash_impl = prf_handles->p_hash_impl;

    return 0;
}

int restore_hash_handles(struct s2n_connection *conn, struct s2n_connection_hash_handles *hash_handles)
{
    /* Restore s2n_connection handlers for hash states */
    conn->handshake.md5.digest.evp = hash_handles->md5;
    conn->handshake.md5.hash_impl = hash_handles->md5_hash_impl;
    conn->handshake.sha1.digest.evp = hash_handles->sha1;
    conn->handshake.sha1.hash_impl = hash_handles->sha1_hash_impl;    
    conn->handshake.sha224.digest.evp = hash_handles->sha224;
    conn->handshake.sha224.hash_impl = hash_handles->sha224_hash_impl;
    conn->handshake.sha256.digest.evp = hash_handles->sha256;
    conn->handshake.sha256.hash_impl = hash_handles->sha256_hash_impl;
    conn->handshake.sha384.digest.evp = hash_handles->sha384;
    conn->handshake.sha384.hash_impl = hash_handles->sha384_hash_impl;
    conn->handshake.sha512.digest.evp = hash_handles->sha512;
    conn->handshake.sha512.hash_impl = hash_handles->sha512_hash_impl;
    conn->handshake.md5_sha1.digest.evp = hash_handles->md5_sha1;
    conn->handshake.md5_sha1.hash_impl = hash_handles->md5_sha1_hash_impl;
    conn->handshake.md5_copy_working_space.digest.evp = hash_handles->md5_copy_working_space;
    conn->handshake.md5_copy_working_space.hash_impl = hash_handles->md5_copy_working_space_hash_impl;
    conn->handshake.sha1_copy_working_space.digest.evp = hash_handles->sha1_copy_working_space;
    conn->handshake.sha1_copy_working_space.hash_impl = hash_handles->sha1_copy_working_space_hash_impl;
    conn->handshake.hash_copy_working_space.digest.evp = hash_handles->hash_copy_working_space;
    conn->handshake.hash_copy_working_space.hash_impl = hash_handles->hash_copy_working_space_hash_impl;
    conn->prf_space.ssl3.md5.digest.evp = hash_handles->prf_md5;
    conn->prf_space.ssl3.md5.hash_impl = hash_handles->prf_md5_hash_impl;
    conn->prf_space.ssl3.sha1.digest.evp = hash_handles->prf_sha1;
    conn->prf_space.ssl3.sha1.hash_impl = hash_handles->prf_sha1_hash_impl;
    conn->initial.signature_hash.digest.evp = hash_handles->initial_signature_hash;
    conn->initial.signature_hash.hash_impl = hash_handles->initial_signature_hash_impl;
    conn->secure.signature_hash.digest.evp = hash_handles->secure_signature_hash;
    conn->secure.signature_hash.hash_impl = hash_handles->secure_signature_hash_impl;

    return 0;
}

int restore_hmac_handles(struct s2n_connection *conn, struct s2n_connection_hmac_handles *hmac_handles)
{
    /* Restore s2n_connection handlers for hmac states */
    conn->initial.client_record_mac.inner.digest.evp = hmac_handles->initial_client_mac_inner;
    conn->initial.client_record_mac.inner.hash_impl = hmac_handles->initial_client_mac_inner_impl;
    conn->initial.client_record_mac.inner_just_key.digest.evp = hmac_handles->initial_client_mac_inner_just_key;
    conn->initial.client_record_mac.inner_just_key.hash_impl = hmac_handles->initial_client_mac_inner_just_key_impl;
    conn->initial.client_record_mac.outer.digest.evp = hmac_handles->initial_client_mac_outer;
    conn->initial.client_record_mac.outer.hash_impl = hmac_handles->initial_client_mac_outer_impl;
    conn->initial.client_record_mac_copy.inner.digest.evp = hmac_handles->initial_client_mac_copy_inner;
    conn->initial.client_record_mac_copy.inner.hash_impl = hmac_handles->initial_client_mac_copy_inner_impl;
    conn->initial.client_record_mac_copy.inner_just_key.digest.evp = hmac_handles->initial_client_mac_copy_inner_just_key;
    conn->initial.client_record_mac_copy.inner_just_key.hash_impl = hmac_handles->initial_client_mac_copy_inner_just_key_impl;
    conn->initial.client_record_mac_copy.outer.digest.evp = hmac_handles->initial_client_mac_copy_outer;
    conn->initial.client_record_mac_copy.outer.hash_impl = hmac_handles->initial_client_mac_copy_outer_impl;
    conn->initial.server_record_mac.inner.digest.evp = hmac_handles->initial_server_mac_inner;
    conn->initial.server_record_mac.inner.hash_impl = hmac_handles->initial_server_mac_inner_impl;
    conn->initial.server_record_mac.inner_just_key.digest.evp = hmac_handles->initial_server_mac_inner_just_key;
    conn->initial.server_record_mac.inner_just_key.hash_impl = hmac_handles->initial_server_mac_inner_just_key_impl;
    conn->initial.server_record_mac.outer.digest.evp = hmac_handles->initial_server_mac_outer;
    conn->initial.server_record_mac.outer.hash_impl = hmac_handles->initial_server_mac_outer_impl;
    conn->secure.client_record_mac.inner.digest.evp = hmac_handles->secure_client_mac_inner;
    conn->secure.client_record_mac.inner.hash_impl = hmac_handles->secure_client_mac_inner_impl;
    conn->secure.client_record_mac.inner_just_key.digest.evp = hmac_handles->secure_client_mac_inner_just_key;
    conn->secure.client_record_mac.inner_just_key.hash_impl = hmac_handles->secure_client_mac_inner_just_key_impl;
    conn->secure.client_record_mac.outer.digest.evp = hmac_handles->secure_client_mac_outer;
    conn->secure.client_record_mac.outer.hash_impl = hmac_handles->secure_client_mac_outer_impl;
    conn->secure.client_record_mac_copy.inner.digest.evp = hmac_handles->secure_client_mac_copy_inner;
    conn->secure.client_record_mac_copy.inner.hash_impl = hmac_handles->secure_client_mac_copy_inner_impl;
    conn->secure.client_record_mac_copy.inner_just_key.digest.evp = hmac_handles->secure_client_mac_copy_inner_just_key;
    conn->secure.client_record_mac_copy.inner_just_key.hash_impl = hmac_handles->secure_client_mac_copy_inner_just_key_impl;
    conn->secure.client_record_mac_copy.outer.digest.evp = hmac_handles->secure_client_mac_copy_outer;
    conn->secure.client_record_mac_copy.outer.hash_impl = hmac_handles->secure_client_mac_copy_outer_impl;
    conn->secure.server_record_mac.inner.digest.evp = hmac_handles->secure_server_mac_inner;
    conn->secure.server_record_mac.inner.hash_impl = hmac_handles->secure_server_mac_inner_impl;
    conn->secure.server_record_mac.inner_just_key.digest.evp = hmac_handles->secure_server_mac_inner_just_key;
    conn->secure.server_record_mac.inner_just_key.hash_impl = hmac_handles->secure_server_mac_inner_just_key_impl;
    conn->secure.server_record_mac.outer.digest.evp = hmac_handles->secure_server_mac_outer;
    conn->secure.server_record_mac.outer.hash_impl = hmac_handles->secure_server_mac_outer_impl;

    return 0;
}
