#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"
#include "unistd.h"
#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void save_key(uint8_t* key);
void verify_counter(sgx_ec256_signature_t* sprc_signature, uint8_t* ensecrets, uint8_t* hm, uint8_t* sci, uint8_t* result, uint8_t* hc1);
void update_counter(uint8_t* sc, sgx_ec256_signature_t* up_signature, uint8_t* hc1, uint8_t* result);
int get_c();
int get_v();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
