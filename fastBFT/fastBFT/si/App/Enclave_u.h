#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"
#include "unistd.h"
#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));

sgx_status_t save_key(sgx_enclave_id_t eid, uint8_t* key);
sgx_status_t verify_counter(sgx_enclave_id_t eid, sgx_ec256_signature_t* sprc_signature, uint8_t* ensecrets, uint8_t* hm, uint8_t* sci, uint8_t* result, uint8_t* hc1);
sgx_status_t update_counter(sgx_enclave_id_t eid, uint8_t* sc, sgx_ec256_signature_t* up_signature, uint8_t* hc1, uint8_t* result);
sgx_status_t get_c(sgx_enclave_id_t eid, int* retval);
sgx_status_t get_v(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
