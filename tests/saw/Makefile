#####################
# Copyright 2016 Galois, Inc. All Rights Reserved
#
#  Authors:
#	Joey Dodds : jdodds@galois.com
#       Nathan Collins : conathan@galois.com
#	
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
########################

#The scripts are all of the saw files in this directory
SCRIPTS = $(wildcard *.saw)
#A log file will be created for each test in the temp dir
LOGS=$(patsubst %.saw,tmp/%.log,$(SCRIPTS))
SHELL:=/bin/bash
YICES_VERSION=$(shell yices-smt2 --version)
export LIBCRYPTO_ROOT:=$(shell pwd)/../../libcrypto-root
export S2N_ROOT=$(shell pwd)/s2n

.PHONY : all
all:
	@echo "Running formal verification with ${YICES_VERSION}"
	@${MAKE} clean-logs
	@${MAKE} clean_the_dir
	@${MAKE} $(LOGS)
	@${MAKE} failure-tests


############################################
## Clean targets
############################################
.PHONY : clean-logs
clean-logs : 
	$(RM) -- $(wildcard tmp/*.log)

.PHONY : clean-bitcode
clean-bitcode :
	$(RM) -- bitcode/all_llvm.bc

.PHONY : clean-failure-logs
clean-failure-logs :
	$(RM) -- $(wildcard failure_tests/*.log)

.PHONY : clean-sike-logs
clean-sike-logs :
	$(RM) -- $(wildcard sike/*.log)

.PHONY: clean
clean: decruft

.PHONY: decruft
decruft : clean-logs
	${MAKE} -C bitcode decruft
	${RM} -r s2n
	${RM} -r tmp

clean_the_dir :
	${RM} -r s2n
	${RM} -r tmp
	${RM} -r failure_tests/*.log
	${RM} -r sike/*.log
	${RM} -r bike/*.log                                                        
	${RM} -r bitcode/*.bc

###########################################
## Script Tests
###########################################

# To make a log we need the corresponding saw file, the all_llvm file, and a temp directory
# The pipefail command causes the entire command to fail if saw fails, even though we pipe it to tee
# without it we would see only the tee return code
tmp/%.log : %.saw bitcode/all_llvm.bc tmp
	@echo "Running formal verification with ${YICES_VERSION}"
	@echo saw $<
	@set -o pipefail; \
	saw $< | tee $@

###########################################
## SIKE Tests
###########################################

.PHONY : sike
sike : sike_patched_bitcode
	@${MAKE} clean-sike-logs
	@${MAKE} sike/word.log
	@${MAKE} sike/field.log
	@${MAKE} sike/curve.log
	@${MAKE} sike/isogeny.log
	@${MAKE} sike/sidh.log
	@${MAKE} sike/sike.log

sike/word.log :
	@set -o pipefail; \
	saw sike/verify_word.saw | tee $@

sike/field.log :
	@set -o pipefail; \
	saw sike/verify_field.saw | tee $@

sike/curve.log :
	@set -o pipefail; \
	saw sike/verify_curve.saw | tee $@

sike/isogeny.log :
	@set -o pipefail; \
	saw sike/verify_isogeny.saw | tee $@

sike/sidh.log :
	@set -o pipefail; \
	saw sike/verify_sidh.saw | tee $@

sike/sike.log :
	@set -o pipefail; \
	saw sike/verify_sike.saw | tee $@

###########################################
## BIKE Tests
###########################################

.PHONY : bike
bike : bike_patched_bitcode
	@${MAKE} -C bike force_all

###########################################
## Failure Tests
##
## where we patch the code and make sure
## that our proofs fail when it is patched
## with errors
###########################################

#These won't work in parallel, so we just hard code them,
#Otherwise we'd have to make a separate patched folder for each one
.PHONY : failure-tests
failure-tests : bitcode
	@${MAKE} clean-failure-logs
	@${MAKE} failure_tests/tls_early_ccs.log
	@${MAKE} failure_tests/tls_missing_full_handshake.log
	@${MAKE} failure_tests/sha_bad_magic_mod.log
	@${MAKE} failure_tests/cork_one.log
	@${MAKE} failure_tests/cork_two.log


#The bitcode files don't get deleted, in case we want to do tests on them
.SECONDARY : $(wildcard bitcode/*.bc)

# We're just making separate prefix targets for each saw script we want to do
# negative tests on
failure_tests/sha_%.log : bitcode/sha_%.bc
        #this might not be necessary
	cp $< bitcode/all_llvm.bc 
	! saw verify_s2n_hmac_sha256.saw &> $@

failure_tests/tls_%.log : bitcode/tls_%.bc
        #this might not be necessary
	cp $< bitcode/all_llvm.bc 
	! saw handshake.saw &> $@

failure_tests/cork_%.log : bitcode/cork_%.bc
        #this might not be necessary
	cp $< bitcode/all_llvm.bc 
	! saw cork-uncork.saw &> $@


# we patch the s2n dir, build it with the top level s2n makefile, and
# move the resulting, patched and linked llvm bitcode into our bitcode directory
bitcode/%.bc : failure_tests/%.patch
	patch -p1 -d s2n -i ../$<
	${MAKE} -C s2n bc; \
	${MAKE} bitcode/all_llvm.bc; \
        status=$$?; \
	cp bitcode/all_llvm.bc $@
	patch -R -p1 -d s2n -i  ../$<; \
        exit $$status

#if we ask this makefile to create bitcode it will always completely rebuild it
.PHONY : bitcode
bitcode : 
	${MAKE} clean_the_dir
	${MAKE} bitcode/all_llvm.bc

sike_patched_bitcode :
	${MAKE} clean_the_dir
	${MAKE} bitcode/sike_llvm.bc

.PHONY : bike_bitcode
bike_patched_bitcode : clean_the_dir bitcode/bike_llvm.bc

########################################################
## Rules to copy the s2n directory for patching and bulding
########################################################

CRYPTO_C = $(wildcard ../../crypto/*.c) $(wildcard ../../crypto/*.h) ../../crypto/Makefile
CRYPTO_COPY = $(addprefix s2n/crypto/, $(notdir $(CRYPTO_C)))

PQ_CRYPTO_C = $(wildcard ../../pq-crypto/*.c) $(wildcard ../../pq-crypto/*.h) ../../pq-crypto/Makefile
PQ_CRYPTO_COPY = $(addprefix s2n/pq-crypto/, $(notdir $(PQ_CRYPTO_C)))

SIKE_C = $(wildcard ../../pq-crypto/sike/*.c) $(wildcard ../../pq-crypto/sike/*.h) ../../pq-crypto/sike/Makefile
SIKE_COPY = $(addprefix s2n/pq-crypto/sike/, $(notdir $(SIKE_C)))

BIKE_C = $(wildcard ../../pq-crypto/bike/*.c) $(wildcard ../../pq-crypto/bike/*.h) ../../pq-crypto/bike/Makefile    
BIKE_COPY = $(addprefix s2n/pq-crypto/bike/, $(notdir $(BIKE_C)))    

UTILS_C = $(wildcard ../../utils/*.c) $(wildcard ../../utils/*.h) ../../utils/Makefile
UTILS_COPY =$(addprefix s2n/utils/, $(notdir $(UTILS_C)))

TLS_C = $(wildcard ../../tls/*.c) $(wildcard ../../tls/*.h) ../../tls/Makefile
TLS_COPY =$(addprefix s2n/tls/, $(notdir $(TLS_C)))

STUFFER_C = $(wildcard ../../stuffer/*.c) $(wildcard ../../stuffer/*.h) ../../stuffer/Makefile
STUFFER_COPY =$(addprefix s2n/stuffer/, $(notdir $(STUFFER_C)))

API_COPY =$(addprefix s2n/api/, $(notdir $(wildcard ../../api/*.h)))
ERROR_COPY =$(addprefix s2n/error/, $(notdir $(wildcard ../../error/*.h)))

s2n/error :
	mkdir -p $@

s2n/api :
	mkdir -p $@

s2n/crypto :
	mkdir -p $@

s2n/pq-crypto :
	mkdir -p $@

s2n/pq-crypto/sike :
	mkdir -p $@

s2n/pq-crypto/bike :                                                                          
	mkdir -p $@       

s2n/utils :
	mkdir -p $@

s2n/tls :
	mkdir -p $@

s2n/stuffer :
	mkdir -p $@

export BITCODE_DIR := $(CURDIR)/bitcode/

tmp:
	mkdir -p tmp

bitcode/all_llvm.bc : s2n/crypto s2n/pq-crypto s2n/pq-crypto/sike s2n/utils s2n/tls s2n/api s2n/error s2n/stuffer s2n/Makefile s2n/s2n.mk $(CRYPTO_COPY) $(PQ_CRYPTO_COPY) $(SIKE_COPY) $(UTILS_COPY) $(TLS_COPY) $(API_COPY) $(ERROR_COPY) $(STUFFER_COPY)
	${MAKE} -C s2n bc
	${MAKE} -C bitcode all_llvm.bc

bitcode/sike_llvm.bc : s2n/crypto s2n/pq-crypto s2n/pq-crypto/sike s2n/utils s2n/tls s2n/api s2n/error s2n/stuffer s2n/Makefile s2n/s2n.mk $(CRYPTO_COPY) $(PQ_CRYPTO_COPY) $(SIKE_COPY) $(UTILS_COPY) $(TLS_COPY) $(API_COPY) $(ERROR_COPY) $(STUFFER_COPY)
	patch s2n/pq-crypto/sike/api.h sike/patch/api.h.patch
	patch s2n/pq-crypto/sike/ec_isogeny.c sike/patch/ec_isogeny.c.patch
	patch s2n/pq-crypto/sike/sidh.c sike/patch/sidh.c.patch
	patch s2n/pq-crypto/sike/sike_p503_kem.c sike/patch/sike_p503_kem.c.patch
	${MAKE} -C s2n bc
	${MAKE} -C bitcode all_llvm.bc

bitcode/bike_llvm.bc : s2n/crypto s2n/pq-crypto s2n/pq-crypto/bike s2n/utils s2n/tls s2n/api s2n/error s2n/stuffer s2n/Makefile s2n/s2n.mk $(CRYPTO_COPY) $(PQ_CRYPTO_COPY) $(BIKE_COPY) $(UTILS_COPY) $(TLS_COPY) $(API_COPY) $(ERROR_COPY) $(STUFFER_COPY)
	patch s2n/pq-crypto/bike/bike_defs.h bike/patch/bike_defs.h.patch
	patch s2n/pq-crypto/bike/bike1_l1_kem.c bike/patch/bike1_l1_kem.c.patch
	patch s2n/pq-crypto/bike/sampling.c bike/patch/sampling.c.patch
	patch s2n/pq-crypto/bike/decode.c bike/patch/decode.c.patch
	${MAKE} -C s2n bc
	${MAKE} -C bitcode bike_llvm.bc


s2n/%.h : ../../%.h
	cp $< $@

s2n/%.c : ../../%.c
	cp $< $@

s2n/%Makefile : ../../%Makefile
	cp $< $@

s2n/Makefile : ../../Makefile
	cp $< $@

s2n/s2n.mk : ../../s2n.mk
	cp $< $@
