#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"
#include "unistd.h"
#include "stdlib.h"
#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));

sgx_status_t Init(sgx_enclave_id_t eid, sgx_aes_ctr_128bit_key_t* p_key1, sgx_ec256_public_t* pout_public, size_t pk_size, size_t pub_size);
sgx_status_t preprocessing(sgx_enclave_id_t eid, sgx_ec256_signature_t* p_sg, uint8_t* en_s, size_t p_size, size_t en_size);
sgx_status_t request_counter(sgx_enclave_id_t eid, uint8_t* hm, sgx_ec256_signature_t* sprc_signature);
sgx_status_t verify_shares(sgx_enclave_id_t eid, int* retval, unsigned char* shares, size_t shares_size, int m);
sgx_status_t get_secrets(sgx_enclave_id_t eid, uint8_t* dsecrets, uint8_t* dhcs, size_t mnum);
sgx_status_t save_key(sgx_enclave_id_t eid, uint8_t* key);
sgx_status_t get_c(sgx_enclave_id_t eid, int* retval);
sgx_status_t get_v(sgx_enclave_id_t eid, int* retval);
sgx_status_t go_back(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
