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

static sgx_status_t SGX_CDECL sgx_verify_counter(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verify_counter_t));
	ms_verify_counter_t* ms = SGX_CAST(ms_verify_counter_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_signature_t* _tmp_sprc_signature = ms->ms_sprc_signature;
	size_t _len_sprc_signature = 64;
	sgx_ec256_signature_t* _in_sprc_signature = NULL;
	uint8_t* _tmp_ensecrets = ms->ms_ensecrets;
	size_t _len_ensecrets = 128;
	uint8_t* _in_ensecrets = NULL;
	uint8_t* _tmp_hm = ms->ms_hm;
	size_t _len_hm = 32;
	uint8_t* _in_hm = NULL;
	uint8_t* _tmp_sci = ms->ms_sci;
	size_t _len_sci = 16;
	uint8_t* _in_sci = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _len_result = 30;
	uint8_t* _in_result = NULL;
	uint8_t* _tmp_hc1 = ms->ms_hc1;
	size_t _len_hc1 = 32;
	uint8_t* _in_hc1 = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sprc_signature, _len_sprc_signature);
	CHECK_UNIQUE_POINTER(_tmp_ensecrets, _len_ensecrets);
	CHECK_UNIQUE_POINTER(_tmp_hm, _len_hm);
	CHECK_UNIQUE_POINTER(_tmp_sci, _len_sci);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);
	CHECK_UNIQUE_POINTER(_tmp_hc1, _len_hc1);

	if (_tmp_sprc_signature != NULL && _len_sprc_signature != 0) {
		_in_sprc_signature = (sgx_ec256_signature_t*)malloc(_len_sprc_signature);
		if (_in_sprc_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sprc_signature, _tmp_sprc_signature, _len_sprc_signature);
	}
	if (_tmp_ensecrets != NULL && _len_ensecrets != 0) {
		_in_ensecrets = (uint8_t*)malloc(_len_ensecrets);
		if (_in_ensecrets == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ensecrets, _tmp_ensecrets, _len_ensecrets);
	}
	if (_tmp_hm != NULL && _len_hm != 0) {
		_in_hm = (uint8_t*)malloc(_len_hm);
		if (_in_hm == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_hm, _tmp_hm, _len_hm);
	}
	if (_tmp_sci != NULL && _len_sci != 0) {
		if ((_in_sci = (uint8_t*)malloc(_len_sci)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sci, 0, _len_sci);
	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	if (_tmp_hc1 != NULL && _len_hc1 != 0) {
		if ((_in_hc1 = (uint8_t*)malloc(_len_hc1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hc1, 0, _len_hc1);
	}
	verify_counter(_in_sprc_signature, _in_ensecrets, _in_hm, _in_sci, _in_result, _in_hc1);
err:
	if (_in_sprc_signature) {
		memcpy(_tmp_sprc_signature, _in_sprc_signature, _len_sprc_signature);
		free(_in_sprc_signature);
	}
	if (_in_ensecrets) free(_in_ensecrets);
	if (_in_hm) free(_in_hm);
	if (_in_sci) {
		memcpy(_tmp_sci, _in_sci, _len_sci);
		free(_in_sci);
	}
	if (_in_result) {
		memcpy(_tmp_result, _in_result, _len_result);
		free(_in_result);
	}
	if (_in_hc1) {
		memcpy(_tmp_hc1, _in_hc1, _len_hc1);
		free(_in_hc1);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_verify_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verify_c_t));
	ms_verify_c_t* ms = SGX_CAST(ms_verify_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_ensecrets = ms->ms_ensecrets;
	size_t _len_ensecrets = 128;
	uint8_t* _in_ensecrets = NULL;
	uint8_t* _tmp_sicv = ms->ms_sicv;
	size_t _tmp_bsize = ms->ms_bsize;
	size_t _len_sicv = _tmp_bsize;
	uint8_t* _in_sicv = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ensecrets, _len_ensecrets);
	CHECK_UNIQUE_POINTER(_tmp_sicv, _len_sicv);

	if (_tmp_ensecrets != NULL && _len_ensecrets != 0) {
		_in_ensecrets = (uint8_t*)malloc(_len_ensecrets);
		if (_in_ensecrets == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ensecrets, _tmp_ensecrets, _len_ensecrets);
	}
	if (_tmp_sicv != NULL && _len_sicv != 0) {
		if ((_in_sicv = (uint8_t*)malloc(_len_sicv)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sicv, 0, _len_sicv);
	}
	verify_c(_in_ensecrets, _in_sicv, _tmp_bsize);
err:
	if (_in_ensecrets) free(_in_ensecrets);
	if (_in_sicv) {
		memcpy(_tmp_sicv, _in_sicv, _len_sicv);
		free(_in_sicv);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_save_key, 0},
		{(void*)(uintptr_t)sgx_verify_counter, 0},
		{(void*)(uintptr_t)sgx_verify_c, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][3];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, },
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

