#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_Init_t {
	sgx_aes_ctr_128bit_key_t* ms_p_key1;
	sgx_ec256_public_t* ms_pout_public;
	size_t ms_pk_size;
	size_t ms_pub_size;
} ms_Init_t;

typedef struct ms_preprocessing_t {
	sgx_ec256_signature_t* ms_p_sg;
	uint8_t* ms_en_s;
	size_t ms_p_size;
	size_t ms_en_size;
} ms_preprocessing_t;

typedef struct ms_request_counter_t {
	uint8_t* ms_hm;
	sgx_ec256_signature_t* ms_sprc_signature;
} ms_request_counter_t;

typedef struct ms_verify_shares_t {
	int ms_retval;
	unsigned char* ms_shares;
	size_t ms_shares_size;
	int ms_m;
} ms_verify_shares_t;

typedef struct ms_get_secrets_t {
	uint8_t* ms_dsecrets;
	uint8_t* ms_dhcs;
	size_t ms_mnum;
} ms_get_secrets_t;

typedef struct ms_save_key_t {
	uint8_t* ms_key;
} ms_save_key_t;

typedef struct ms_get_c_t {
	int ms_retval;
} ms_get_c_t;

typedef struct ms_get_v_t {
	int ms_retval;
} ms_get_v_t;

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
sgx_status_t Init(sgx_enclave_id_t eid, sgx_aes_ctr_128bit_key_t* p_key1, sgx_ec256_public_t* pout_public, size_t pk_size, size_t pub_size)
{
	sgx_status_t status;
	ms_Init_t ms;
	ms.ms_p_key1 = p_key1;
	ms.ms_pout_public = pout_public;
	ms.ms_pk_size = pk_size;
	ms.ms_pub_size = pub_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t preprocessing(sgx_enclave_id_t eid, sgx_ec256_signature_t* p_sg, uint8_t* en_s, size_t p_size, size_t en_size)
{
	sgx_status_t status;
	ms_preprocessing_t ms;
	ms.ms_p_sg = p_sg;
	ms.ms_en_s = en_s;
	ms.ms_p_size = p_size;
	ms.ms_en_size = en_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t request_counter(sgx_enclave_id_t eid, uint8_t* hm, sgx_ec256_signature_t* sprc_signature)
{
	sgx_status_t status;
	ms_request_counter_t ms;
	ms.ms_hm = hm;
	ms.ms_sprc_signature = sprc_signature;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t verify_shares(sgx_enclave_id_t eid, int* retval, unsigned char* shares, size_t shares_size, int m)
{
	sgx_status_t status;
	ms_verify_shares_t ms;
	ms.ms_shares = shares;
	ms.ms_shares_size = shares_size;
	ms.ms_m = m;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_secrets(sgx_enclave_id_t eid, uint8_t* dsecrets, uint8_t* dhcs, size_t mnum)
{
	sgx_status_t status;
	ms_get_secrets_t ms;
	ms.ms_dsecrets = dsecrets;
	ms.ms_dhcs = dhcs;
	ms.ms_mnum = mnum;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t save_key(sgx_enclave_id_t eid, uint8_t* key)
{
	sgx_status_t status;
	ms_save_key_t ms;
	ms.ms_key = key;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t get_c(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_get_c_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_v(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_get_v_t ms;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t go_back(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, NULL);
	return status;
}

