#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_Init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Init_t));
	ms_Init_t* ms = SGX_CAST(ms_Init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_aes_ctr_128bit_key_t* _tmp_p_key1 = ms->ms_p_key1;
	size_t _tmp_pk_size = ms->ms_pk_size;
	size_t _len_p_key1 = _tmp_pk_size;
	sgx_aes_ctr_128bit_key_t* _in_p_key1 = NULL;
	sgx_ec256_public_t* _tmp_pout_public = ms->ms_pout_public;
	size_t _tmp_pub_size = ms->ms_pub_size;
	size_t _len_pout_public = _tmp_pub_size;
	sgx_ec256_public_t* _in_pout_public = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_key1, _len_p_key1);
	CHECK_UNIQUE_POINTER(_tmp_pout_public, _len_pout_public);

	if (_tmp_p_key1 != NULL && _len_p_key1 != 0) {
		_in_p_key1 = (sgx_aes_ctr_128bit_key_t*)malloc(_len_p_key1);
		if (_in_p_key1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_key1, _tmp_p_key1, _len_p_key1);
	}
	if (_tmp_pout_public != NULL && _len_pout_public != 0) {
		if ((_in_pout_public = (sgx_ec256_public_t*)malloc(_len_pout_public)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pout_public, 0, _len_pout_public);
	}
	Init(_in_p_key1, _in_pout_public, _tmp_pk_size, _tmp_pub_size);
err:
	if (_in_p_key1) {
		memcpy(_tmp_p_key1, _in_p_key1, _len_p_key1);
		free(_in_p_key1);
	}
	if (_in_pout_public) {
		memcpy(_tmp_pout_public, _in_pout_public, _len_pout_public);
		free(_in_pout_public);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_preprocessing(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_preprocessing_t));
	ms_preprocessing_t* ms = SGX_CAST(ms_preprocessing_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_signature_t* _tmp_p_sg = ms->ms_p_sg;
	size_t _tmp_p_size = ms->ms_p_size;
	size_t _len_p_sg = _tmp_p_size;
	sgx_ec256_signature_t* _in_p_sg = NULL;
	uint8_t* _tmp_en_s = ms->ms_en_s;
	size_t _tmp_en_size = ms->ms_en_size;
	size_t _len_en_s = _tmp_en_size;
	uint8_t* _in_en_s = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_sg, _len_p_sg);
	CHECK_UNIQUE_POINTER(_tmp_en_s, _len_en_s);

	if (_tmp_p_sg != NULL && _len_p_sg != 0) {
		if ((_in_p_sg = (sgx_ec256_signature_t*)malloc(_len_p_sg)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_sg, 0, _len_p_sg);
	}
	if (_tmp_en_s != NULL && _len_en_s != 0) {
		if ((_in_en_s = (uint8_t*)malloc(_len_en_s)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_en_s, 0, _len_en_s);
	}
	preprocessing(_in_p_sg, _in_en_s, _tmp_p_size, _tmp_en_size);
err:
	if (_in_p_sg) {
		memcpy(_tmp_p_sg, _in_p_sg, _len_p_sg);
		free(_in_p_sg);
	}
	if (_in_en_s) {
		memcpy(_tmp_en_s, _in_en_s, _len_en_s);
		free(_in_en_s);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_request_counter(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_request_counter_t));
	ms_request_counter_t* ms = SGX_CAST(ms_request_counter_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_hm = ms->ms_hm;
	size_t _len_hm = 32;
	uint8_t* _in_hm = NULL;
	sgx_ec256_signature_t* _tmp_sprc_signature = ms->ms_sprc_signature;
	size_t _len_sprc_signature = 64;
	sgx_ec256_signature_t* _in_sprc_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_hm, _len_hm);
	CHECK_UNIQUE_POINTER(_tmp_sprc_signature, _len_sprc_signature);

	if (_tmp_hm != NULL && _len_hm != 0) {
		_in_hm = (uint8_t*)malloc(_len_hm);
		if (_in_hm == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_hm, _tmp_hm, _len_hm);
	}
	if (_tmp_sprc_signature != NULL && _len_sprc_signature != 0) {
		if ((_in_sprc_signature = (sgx_ec256_signature_t*)malloc(_len_sprc_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sprc_signature, 0, _len_sprc_signature);
	}
	request_counter(_in_hm, _in_sprc_signature);
err:
	if (_in_hm) free(_in_hm);
	if (_in_sprc_signature) {
		memcpy(_tmp_sprc_signature, _in_sprc_signature, _len_sprc_signature);
		free(_in_sprc_signature);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_verify_shares(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verify_shares_t));
	ms_verify_shares_t* ms = SGX_CAST(ms_verify_shares_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_shares = ms->ms_shares;
	size_t _tmp_shares_size = ms->ms_shares_size;
	size_t _len_shares = _tmp_shares_size;
	unsigned char* _in_shares = NULL;

	CHECK_UNIQUE_POINTER(_tmp_shares, _len_shares);

	if (_tmp_shares != NULL && _len_shares != 0) {
		_in_shares = (unsigned char*)malloc(_len_shares);
		if (_in_shares == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_shares, _tmp_shares, _len_shares);
	}
	ms->ms_retval = verify_shares(_in_shares, _tmp_shares_size, ms->ms_m);
err:
	if (_in_shares) free(_in_shares);

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_secrets(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_secrets_t));
	ms_get_secrets_t* ms = SGX_CAST(ms_get_secrets_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_dsecrets = ms->ms_dsecrets;
	size_t _len_dsecrets = 32;
	uint8_t* _in_dsecrets = NULL;
	uint8_t* _tmp_dhcs = ms->ms_dhcs;
	size_t _len_dhcs = 64;
	uint8_t* _in_dhcs = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dsecrets, _len_dsecrets);
	CHECK_UNIQUE_POINTER(_tmp_dhcs, _len_dhcs);

	if (_tmp_dsecrets != NULL && _len_dsecrets != 0) {
		if ((_in_dsecrets = (uint8_t*)malloc(_len_dsecrets)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dsecrets, 0, _len_dsecrets);
	}
	if (_tmp_dhcs != NULL && _len_dhcs != 0) {
		if ((_in_dhcs = (uint8_t*)malloc(_len_dhcs)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dhcs, 0, _len_dhcs);
	}
	get_secrets(_in_dsecrets, _in_dhcs, ms->ms_mnum);
err:
	if (_in_dsecrets) {
		memcpy(_tmp_dsecrets, _in_dsecrets, _len_dsecrets);
		free(_in_dsecrets);
	}
	if (_in_dhcs) {
		memcpy(_tmp_dhcs, _in_dhcs, _len_dhcs);
		free(_in_dhcs);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_save_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_save_key_t));
	ms_save_key_t* ms = SGX_CAST(ms_save_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_key = ms->ms_key;
	size_t _len_key = 80;
	uint8_t* _in_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	if (_tmp_key != NULL && _len_key != 0) {
		_in_key = (uint8_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	save_key(_in_key);
err:
	if (_in_key) free(_in_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_c_t));
	ms_get_c_t* ms = SGX_CAST(ms_get_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = get_c();


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_v(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_v_t));
	ms_get_v_t* ms = SGX_CAST(ms_get_v_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = get_v();


	return status;
}

static sgx_status_t SGX_CDECL sgx_go_back(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	go_back();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[9];
} g_ecall_table = {
	9,
	{
		{(void*)(uintptr_t)sgx_Init, 0},
		{(void*)(uintptr_t)sgx_preprocessing, 0},
		{(void*)(uintptr_t)sgx_request_counter, 0},
		{(void*)(uintptr_t)sgx_verify_shares, 0},
		{(void*)(uintptr_t)sgx_get_secrets, 0},
		{(void*)(uintptr_t)sgx_save_key, 0},
		{(void*)(uintptr_t)sgx_get_c, 0},
		{(void*)(uintptr_t)sgx_get_v, 0},
		{(void*)(uintptr_t)sgx_go_back, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][9];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

