#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_save_key_t {
	uint8_t* ms_key;
} ms_save_key_t;

typedef struct ms_verify_counter_t {
	sgx_ec256_signature_t* ms_sprc_signature;
	uint8_t* ms_ensecrets;
	uint8_t* ms_hm;
	uint8_t* ms_sci;
	uint8_t* ms_result;
	uint8_t* ms_hc1;
} ms_verify_counter_t;

typedef struct ms_verify_c_t {
	uint8_t* ms_ensecrets;
	uint8_t* ms_sicv;
	size_t ms_bsize;
} ms_verify_c_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t save_key(sgx_enclave_id_t eid, uint8_t* key)
{
	sgx_status_t status;
	ms_save_key_t ms;
	ms.ms_key = key;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t verify_counter(sgx_enclave_id_t eid, sgx_ec256_signature_t* sprc_signature, uint8_t* ensecrets, uint8_t* hm, uint8_t* sci, uint8_t* result, uint8_t* hc1)
{
	sgx_status_t status;
	ms_verify_counter_t ms;
	ms.ms_sprc_signature = sprc_signature;
	ms.ms_ensecrets = ensecrets;
	ms.ms_hm = hm;
	ms.ms_sci = sci;
	ms.ms_result = result;
	ms.ms_hc1 = hc1;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t verify_c(sgx_enclave_id_t eid, uint8_t* ensecrets, uint8_t* sicv, size_t bsize)
{
	sgx_status_t status;
	ms_verify_c_t ms;
	ms.ms_ensecrets = ensecrets;
	ms.ms_sicv = sicv;
	ms.ms_bsize = bsize;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

