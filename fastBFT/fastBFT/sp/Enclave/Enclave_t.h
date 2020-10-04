#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"
#include "unistd.h"
#include "stdlib.h"
#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void Init(sgx_aes_ctr_128bit_key_t* p_key1, sgx_ec256_public_t* pout_public, size_t pk_size, size_t pub_size);
void preprocessing(sgx_ec256_signature_t* p_sg, uint8_t* en_s, size_t p_size, size_t en_size);
void request_counter(uint8_t* hm, sgx_ec256_signature_t* sprc_signature);
int verify_shares(unsigned char* shares, size_t shares_size, int m);
void get_secrets(uint8_t* dsecrets, uint8_t* dhcs, size_t mnum);
void save_key(uint8_t* key);
int get_c();
int get_v();
void go_back();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
