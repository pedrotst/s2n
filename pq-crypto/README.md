# Post-quantum cryptography for s2n
This directory contains code for new post-quantum key exchange mechanisms. There are no known computationally feasible
attacks (classical or quantum) against these algorithms when used with the recommended key lengths.

## Quantum computers
Quantum computers use the properties of quantum mechanics to evaluate quantum algorithms. These algorithms can solve some
classically hard (exponential time) problems quickly (polynomial time). Shor's algorithm is one such algorithm which can
factor large integers, thus breaking RSA encryption and digital signature, and another quantum algorithm can solve the
discrete logarithm problem over arbitrary groups thus breaking Diffie–Hellman and elliptic curve Diffie–Hellman key
exchange.

## Post-quantum cryptography
Post-quantum public-key cryptographic algorithms run on a classical computer and are conjectured secure against both
classical and quantum attacks. NIST is in the process of reviewing submissions and standardizing them,
see more info on the [NIST website](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization).
Until the review and standardization is complete the post-quantum key exchanges in s2n **must not** be used for key
establishment by themselves. Instead they should only be used as part of a hybrid key exchange, which combines a
post-quantum key exchange scheme and a classical key exchange scheme.

## Hybrid key exchange
A hybrid key exchange combines both the high assurance of classical key exchange with the conjectured quantum-resistance
of newly proposed key exchanges. s2n implements the hybrid specification from [this RFC](https://tools.ietf.org/html/draft-campagna-tls-bike-sike-hybrid-01).
See [this s2n issue](https://github.com/awslabs/s2n/issues/904) for more up-to-date information.

## SIKE (Supersingular Isogeny Key Encapsulation)
The code in the pq-crypto/sike directory was taken from the [round 1 nist submission](https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/SIKE.zip).
s2n uses the reference implementation to ensure maximum comparability and ease of review. The known answer tests are
[here](https://github.com/awslabs/s2n/blob/master/tests/unit/s2n_sike_p503_kat_test.c) and use the known answer file
from the SIKEp503 round 1 submission.

## BIKE (Bit Flipping Key Encapsulation)
The code in the pq-crypto/bike directory was taken from the [additional implementation](https://bikesuite.org/files/round2/add-impl/Additional_Implementation.2019.03.30.zip).
s2n uses the "additional implementation" which ensures constant time primitives, does not use any external libraries
besides libcrypto, and does not depend on any specific hardware instructions to ensure maximum comparability and ease of
review. The known answer tests are [here](https://github.com/awslabs/s2n/blob/master/tests/unit/s2n_bike1_l1_kat_test.c)
and use the BIKE1_L1.const.kat from the above Additional_Implementation.2019.03.30.zip.

## How to add another PQ KEM
1. Add the code to `pq-crypto/KEM_NAME/`
    1. Update `pq-crypto/Makefile` to build that directory
    1. Update `lib/Makefile` to also include that directory
    1. Update the KEM code to include `pq-crypto/pq_random.h` and use the function `get_random_bytes` for any random data the KEM needs
    1. Create a `pq-crypto/KEM_NAME/KEM_NAME.h` with the size of objects and method definitions
1. Define the new cipher suite and KEM extension value in `tls/s2n_tls_parameters.h`
1. Create the `KEM_NAME` `s2n_kem` struct in `tls/s2n_kem.c`
    1. Add the new kem to the `kem_mapping` with the correct cipher suite value
1. Add known answer tests using `s2n_test_kem_with_kat()` in `tests/unit/s2n_KEM_NAME_kat_test.c`
1. Add fuzz testing in `tests/fuzz/s2n_KEM_NAME_fuzz_test.c`
1. Add formal verification in `tests/saw/KEM_NAME/verify.saw`
1. Create a new `s2n_cipher_suite` in `tls/s2n_cipher_suites.c`
1. Create a new `s2n_cipher_preferences` in `tls/s2n_cipher_prefrences.c` that uses the new cipher suite

## How to use PQ cipher suites
1. Checkout s2n `git clone https://github.com/awslabs/s2n.git`
1. Following the docs/USAGE-GUIDE.md build s2n
1. Use the sample server and client in the bin directory:
```bash
# Terminal 1
# Use the s2nd CLI tool to start a TLS daemon with the KMS-PQ-TLS-1-0-2019-06 cipher preferences listening on port 8888
export PATH_TO_S2N=/path/to/s2n
export LD_LIBRARY_PATH=${PATH_TO_S2N}/test-deps/openssl-1.1.1/lib:${PATH_TO_S2N}/test-deps/openssl-1.1.1/lib:${PATH_TO_S2N}/lib:${PATH_TO_S2N}/bin
export PATH=${PATH_TO_S2N}/bin:$PATH
s2nd --cert ${PATH_TO_S2N}/tests/pems/rsa_2048_sha256_wildcard_cert.pem --key ${PATH_TO_S2N}/tests/pems/rsa_2048_sha256_wildcard_key.pem --negotiate --ciphers KMS-PQ-TLS-1-0-2019-06 0.0.0.0 8888

# Terminal 2
# Use the s2nc TLS CLI client to connect to the TLS server daemon started in Terminal 1 on port 8888
export PATH_TO_S2N=/path/to/s2n
export LD_LIBRARY_PATH=${PATH_TO_S2N}/test-deps/openssl-1.1.1/lib:${PATH_TO_S2N}/test-deps/openssl-1.1.1/lib:${PATH_TO_S2N}/lib:${PATH_TO_S2N}/bin
export PATH=${PATH_TO_S2N}/bin:$PATH
export S2N_ENABLE_CLIENT_MODE=1
s2nc -i --ciphers KMS-PQ-TLS-1-0-2019-06 0.0.0.0 8888
```