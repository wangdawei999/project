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


typedef struct ms_MyStrCpy_t {
	char* ms_DeStr;
	char* ms_SoStr;
	size_t ms_DeLen;
	size_t ms_SoLen;
} ms_MyStrCpy_t;

typedef struct ms_MyAccum_t {
	size_t ms_retval;
	size_t ms_start;
	size_t ms_end;
} ms_MyAccum_t;

typedef struct ms_TeeCalGRAT_t {
	struct mTrsLt* ms_mTLst;
	struct msgRtLt* ms_msRf;
	struct gCarTrust* ms_gCTrust;
	size_t ms_DeLen;
	size_t ms_SoLen;
	size_t ms_gCLen;
	int ms_n;
} ms_TeeCalGRAT_t;

typedef struct ms_TeeCalSEG_t {
	struct mTrsLt* ms_mTLs;
	struct msgRtLt* ms_msRL;
	struct gCarTrust* ms_gCTrust;
	size_t ms_DeLen;
	size_t ms_SoLen;
	size_t ms_gCLen;
	int ms_nTLsn;
	int ms_msRLn;
	int ms_gCTrustn;
} ms_TeeCalSEG_t;

typedef struct ms_ecall_type_char_t {
	char ms_val;
} ms_ecall_type_char_t;

typedef struct ms_ecall_type_int_t {
	int ms_val;
} ms_ecall_type_int_t;

typedef struct ms_ecall_type_float_t {
	float ms_val;
} ms_ecall_type_float_t;

typedef struct ms_ecall_type_double_t {
	double ms_val;
} ms_ecall_type_double_t;

typedef struct ms_ecall_type_size_t_t {
	size_t ms_val;
} ms_ecall_type_size_t_t;

typedef struct ms_ecall_type_wchar_t_t {
	wchar_t ms_val;
} ms_ecall_type_wchar_t_t;

typedef struct ms_ecall_type_struct_t {
	struct struct_foo_t ms_val;
} ms_ecall_type_struct_t;

typedef struct ms_ecall_type_enum_union_t {
	enum enum_foo_t ms_val1;
	union union_foo_t* ms_val2;
} ms_ecall_type_enum_union_t;

typedef struct ms_ecall_pointer_user_check_t {
	size_t ms_retval;
	void* ms_val;
	size_t ms_sz;
} ms_ecall_pointer_user_check_t;

typedef struct ms_ecall_pointer_in_t {
	int* ms_val;
} ms_ecall_pointer_in_t;

typedef struct ms_ecall_pointer_out_t {
	int* ms_val;
} ms_ecall_pointer_out_t;

typedef struct ms_ecall_pointer_in_out_t {
	int* ms_val;
} ms_ecall_pointer_in_out_t;

typedef struct ms_ecall_pointer_string_t {
	char* ms_str;
} ms_ecall_pointer_string_t;

typedef struct ms_ecall_pointer_string_const_t {
	char* ms_str;
} ms_ecall_pointer_string_const_t;

typedef struct ms_ecall_pointer_size_t {
	void* ms_ptr;
	size_t ms_len;
} ms_ecall_pointer_size_t;

typedef struct ms_ecall_pointer_count_t {
	int* ms_arr;
	int ms_cnt;
} ms_ecall_pointer_count_t;

typedef struct ms_ecall_pointer_isptr_readonly_t {
	buffer_t ms_buf;
	size_t ms_len;
} ms_ecall_pointer_isptr_readonly_t;

typedef struct ms_ecall_pointer_sizefunc_t {
	char* ms_buf;
} ms_ecall_pointer_sizefunc_t;

typedef struct ms_ecall_array_user_check_t {
	int* ms_arr;
} ms_ecall_array_user_check_t;

typedef struct ms_ecall_array_in_t {
	int* ms_arr;
} ms_ecall_array_in_t;

typedef struct ms_ecall_array_out_t {
	int* ms_arr;
} ms_ecall_array_out_t;

typedef struct ms_ecall_array_in_out_t {
	int* ms_arr;
} ms_ecall_array_in_out_t;

typedef struct ms_ecall_array_isary_t {
	array_t*  ms_arr;
} ms_ecall_array_isary_t;

typedef struct ms_ecall_function_private_t {
	int ms_retval;
} ms_ecall_function_private_t;

typedef struct ms_ecall_sgx_cpuid_t {
	int* ms_cpuinfo;
	int ms_leaf;
} ms_ecall_sgx_cpuid_t;

typedef struct ms_ecall_increase_counter_t {
	size_t ms_retval;
} ms_ecall_increase_counter_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_pointer_user_check_t {
	int* ms_val;
} ms_ocall_pointer_user_check_t;

typedef struct ms_ocall_pointer_in_t {
	int* ms_val;
} ms_ocall_pointer_in_t;

typedef struct ms_ocall_pointer_out_t {
	int* ms_val;
} ms_ocall_pointer_out_t;

typedef struct ms_ocall_pointer_in_out_t {
	int* ms_val;
} ms_ocall_pointer_in_out_t;

typedef struct ms_memccpy_t {
	void* ms_retval;
	void* ms_dest;
	void* ms_src;
	int ms_val;
	size_t ms_len;
} ms_memccpy_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_MyStrCpy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_MyStrCpy_t));
	ms_MyStrCpy_t* ms = SGX_CAST(ms_MyStrCpy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_DeStr = ms->ms_DeStr;
	size_t _tmp_DeLen = ms->ms_DeLen;
	size_t _len_DeStr = _tmp_DeLen;
	char* _in_DeStr = NULL;
	char* _tmp_SoStr = ms->ms_SoStr;
	size_t _tmp_SoLen = ms->ms_SoLen;
	size_t _len_SoStr = _tmp_SoLen;
	char* _in_SoStr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_DeStr, _len_DeStr);
	CHECK_UNIQUE_POINTER(_tmp_SoStr, _len_SoStr);

	if (_tmp_DeStr != NULL && _len_DeStr != 0) {
		if ((_in_DeStr = (char*)malloc(_len_DeStr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_DeStr, 0, _len_DeStr);
	}
	if (_tmp_SoStr != NULL && _len_SoStr != 0) {
		_in_SoStr = (char*)malloc(_len_SoStr);
		if (_in_SoStr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_SoStr, _tmp_SoStr, _len_SoStr);
	}
	MyStrCpy(_in_DeStr, _in_SoStr, _tmp_DeLen, _tmp_SoLen);
err:
	if (_in_DeStr) {
		memcpy(_tmp_DeStr, _in_DeStr, _len_DeStr);
		free(_in_DeStr);
	}
	if (_in_SoStr) free(_in_SoStr);

	return status;
}

static sgx_status_t SGX_CDECL sgx_MyAccum(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_MyAccum_t));
	ms_MyAccum_t* ms = SGX_CAST(ms_MyAccum_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = MyAccum(ms->ms_start, ms->ms_end);


	return status;
}

static sgx_status_t SGX_CDECL sgx_TeeCalGRAT(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TeeCalGRAT_t));
	ms_TeeCalGRAT_t* ms = SGX_CAST(ms_TeeCalGRAT_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct mTrsLt* _tmp_mTLst = ms->ms_mTLst;
	size_t _tmp_DeLen = ms->ms_DeLen;
	size_t _len_mTLst = _tmp_DeLen;
	struct mTrsLt* _in_mTLst = NULL;
	struct msgRtLt* _tmp_msRf = ms->ms_msRf;
	size_t _tmp_SoLen = ms->ms_SoLen;
	size_t _len_msRf = _tmp_SoLen;
	struct msgRtLt* _in_msRf = NULL;
	struct gCarTrust* _tmp_gCTrust = ms->ms_gCTrust;
	size_t _tmp_gCLen = ms->ms_gCLen;
	size_t _len_gCTrust = _tmp_gCLen;
	struct gCarTrust* _in_gCTrust = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mTLst, _len_mTLst);
	CHECK_UNIQUE_POINTER(_tmp_msRf, _len_msRf);
	CHECK_UNIQUE_POINTER(_tmp_gCTrust, _len_gCTrust);

	if (_tmp_mTLst != NULL && _len_mTLst != 0) {
		_in_mTLst = (struct mTrsLt*)malloc(_len_mTLst);
		if (_in_mTLst == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mTLst, _tmp_mTLst, _len_mTLst);
	}
	if (_tmp_msRf != NULL && _len_msRf != 0) {
		_in_msRf = (struct msgRtLt*)malloc(_len_msRf);
		if (_in_msRf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_msRf, _tmp_msRf, _len_msRf);
	}
	if (_tmp_gCTrust != NULL && _len_gCTrust != 0) {
		_in_gCTrust = (struct gCarTrust*)malloc(_len_gCTrust);
		if (_in_gCTrust == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_gCTrust, _tmp_gCTrust, _len_gCTrust);
	}
	TeeCalGRAT(_in_mTLst, _in_msRf, _in_gCTrust, _tmp_DeLen, _tmp_SoLen, _tmp_gCLen, ms->ms_n);
err:
	if (_in_mTLst) {
		memcpy(_tmp_mTLst, _in_mTLst, _len_mTLst);
		free(_in_mTLst);
	}
	if (_in_msRf) free(_in_msRf);
	if (_in_gCTrust) free(_in_gCTrust);

	return status;
}

static sgx_status_t SGX_CDECL sgx_TeeCalSEG(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TeeCalSEG_t));
	ms_TeeCalSEG_t* ms = SGX_CAST(ms_TeeCalSEG_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct mTrsLt* _tmp_mTLs = ms->ms_mTLs;
	size_t _tmp_DeLen = ms->ms_DeLen;
	size_t _len_mTLs = _tmp_DeLen;
	struct mTrsLt* _in_mTLs = NULL;
	struct msgRtLt* _tmp_msRL = ms->ms_msRL;
	size_t _tmp_SoLen = ms->ms_SoLen;
	size_t _len_msRL = _tmp_SoLen;
	struct msgRtLt* _in_msRL = NULL;
	struct gCarTrust* _tmp_gCTrust = ms->ms_gCTrust;
	size_t _tmp_gCLen = ms->ms_gCLen;
	size_t _len_gCTrust = _tmp_gCLen;
	struct gCarTrust* _in_gCTrust = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mTLs, _len_mTLs);
	CHECK_UNIQUE_POINTER(_tmp_msRL, _len_msRL);
	CHECK_UNIQUE_POINTER(_tmp_gCTrust, _len_gCTrust);

	if (_tmp_mTLs != NULL && _len_mTLs != 0) {
		_in_mTLs = (struct mTrsLt*)malloc(_len_mTLs);
		if (_in_mTLs == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mTLs, _tmp_mTLs, _len_mTLs);
	}
	if (_tmp_msRL != NULL && _len_msRL != 0) {
		_in_msRL = (struct msgRtLt*)malloc(_len_msRL);
		if (_in_msRL == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_msRL, _tmp_msRL, _len_msRL);
	}
	if (_tmp_gCTrust != NULL && _len_gCTrust != 0) {
		_in_gCTrust = (struct gCarTrust*)malloc(_len_gCTrust);
		if (_in_gCTrust == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_gCTrust, _tmp_gCTrust, _len_gCTrust);
	}
	TeeCalSEG(_in_mTLs, _in_msRL, _in_gCTrust, _tmp_DeLen, _tmp_SoLen, _tmp_gCLen, ms->ms_nTLsn, ms->ms_msRLn, ms->ms_gCTrustn);
err:
	if (_in_mTLs) free(_in_mTLs);
	if (_in_msRL) free(_in_msRL);
	if (_in_gCTrust) {
		memcpy(_tmp_gCTrust, _in_gCTrust, _len_gCTrust);
		free(_in_gCTrust);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_char(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_char_t));
	ms_ecall_type_char_t* ms = SGX_CAST(ms_ecall_type_char_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_char(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_int(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_int_t));
	ms_ecall_type_int_t* ms = SGX_CAST(ms_ecall_type_int_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_int(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_float(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_float_t));
	ms_ecall_type_float_t* ms = SGX_CAST(ms_ecall_type_float_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_float(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_double(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_double_t));
	ms_ecall_type_double_t* ms = SGX_CAST(ms_ecall_type_double_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_double(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_size_t(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_size_t_t));
	ms_ecall_type_size_t_t* ms = SGX_CAST(ms_ecall_type_size_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_size_t(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_wchar_t(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_wchar_t_t));
	ms_ecall_type_wchar_t_t* ms = SGX_CAST(ms_ecall_type_wchar_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_wchar_t(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_struct(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_struct_t));
	ms_ecall_type_struct_t* ms = SGX_CAST(ms_ecall_type_struct_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_struct(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_enum_union(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_enum_union_t));
	ms_ecall_type_enum_union_t* ms = SGX_CAST(ms_ecall_type_enum_union_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	union union_foo_t* _tmp_val2 = ms->ms_val2;


	ecall_type_enum_union(ms->ms_val1, _tmp_val2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_user_check_t));
	ms_ecall_pointer_user_check_t* ms = SGX_CAST(ms_ecall_pointer_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_val = ms->ms_val;


	ms->ms_retval = ecall_pointer_user_check(_tmp_val, ms->ms_sz);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_t));
	ms_ecall_pointer_in_t* ms = SGX_CAST(ms_ecall_pointer_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL && _len_val != 0) {
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_val, _tmp_val, _len_val);
	}
	ecall_pointer_in(_in_val);
err:
	if (_in_val) free(_in_val);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_out_t));
	ms_ecall_pointer_out_t* ms = SGX_CAST(ms_ecall_pointer_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL && _len_val != 0) {
		if ((_in_val = (int*)malloc(_len_val)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_val, 0, _len_val);
	}
	ecall_pointer_out(_in_val);
err:
	if (_in_val) {
		memcpy(_tmp_val, _in_val, _len_val);
		free(_in_val);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_out_t));
	ms_ecall_pointer_in_out_t* ms = SGX_CAST(ms_ecall_pointer_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL && _len_val != 0) {
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_val, _tmp_val, _len_val);
	}
	ecall_pointer_in_out(_in_val);
err:
	if (_in_val) {
		memcpy(_tmp_val, _in_val, _len_val);
		free(_in_val);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_t));
	ms_ecall_pointer_string_t* ms = SGX_CAST(ms_ecall_pointer_string_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	ecall_pointer_string(_in_str);
err:
	if (_in_str) {
		memcpy(_tmp_str, _in_str, _len_str);
		free(_in_str);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string_const(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_const_t));
	ms_ecall_pointer_string_const_t* ms = SGX_CAST(ms_ecall_pointer_string_const_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	ecall_pointer_string_const((const char*)_in_str);
err:
	if (_in_str) free((void*)_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_size_t));
	ms_ecall_pointer_size_t* ms = SGX_CAST(ms_ecall_pointer_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_ptr = ms->ms_ptr;
	size_t _tmp_len = ms->ms_len;
	size_t _len_ptr = _tmp_len;
	void* _in_ptr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ptr, _len_ptr);

	if (_tmp_ptr != NULL && _len_ptr != 0) {
		_in_ptr = (void*)malloc(_len_ptr);
		if (_in_ptr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ptr, _tmp_ptr, _len_ptr);
	}
	ecall_pointer_size(_in_ptr, _tmp_len);
err:
	if (_in_ptr) {
		memcpy(_tmp_ptr, _in_ptr, _len_ptr);
		free(_in_ptr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_count(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_count_t));
	ms_ecall_pointer_count_t* ms = SGX_CAST(ms_ecall_pointer_count_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	int _tmp_cnt = ms->ms_cnt;
	size_t _len_arr = _tmp_cnt * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	if (sizeof(*_tmp_arr) != 0 &&
		(size_t)_tmp_cnt > (SIZE_MAX / sizeof(*_tmp_arr))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL && _len_arr != 0) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_pointer_count(_in_arr, _tmp_cnt);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_isptr_readonly(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_isptr_readonly_t));
	ms_ecall_pointer_isptr_readonly_t* ms = SGX_CAST(ms_ecall_pointer_isptr_readonly_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	buffer_t _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	buffer_t _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (buffer_t)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_buf, _tmp_buf, _len_buf);
	}
	ecall_pointer_isptr_readonly(_in_buf, _tmp_len);
err:
	if (_in_buf) free((void*)_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_sizefunc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_sizefunc_t));
	ms_ecall_pointer_sizefunc_t* ms = SGX_CAST(ms_ecall_pointer_sizefunc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _len_buf = ((_tmp_buf) ? get_buffer_len(_tmp_buf) : 0);
	char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);

		/* check whether the pointer is modified. */
		if (get_buffer_len(_in_buf) != _len_buf) {
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
	}
	ecall_pointer_sizefunc(_in_buf);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ocall_pointer_attr(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_pointer_attr();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_user_check_t));
	ms_ecall_array_user_check_t* ms = SGX_CAST(ms_ecall_array_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;


	ecall_array_user_check(_tmp_arr);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_t));
	ms_ecall_array_in_t* ms = SGX_CAST(ms_ecall_array_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL && _len_arr != 0) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_array_in(_in_arr);
err:
	if (_in_arr) free(_in_arr);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_out_t));
	ms_ecall_array_out_t* ms = SGX_CAST(ms_ecall_array_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ((_in_arr = (int*)malloc(_len_arr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_arr, 0, _len_arr);
	}
	ecall_array_out(_in_arr);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_out_t));
	ms_ecall_array_in_out_t* ms = SGX_CAST(ms_ecall_array_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL && _len_arr != 0) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_array_in_out(_in_arr);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_isary(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_isary_t));
	ms_ecall_array_isary_t* ms = SGX_CAST(ms_ecall_array_isary_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ecall_array_isary((ms->ms_arr != NULL) ? (*ms->ms_arr) : NULL);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_calling_convs(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_calling_convs();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_public(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_public();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_private(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_function_private_t));
	ms_ecall_function_private_t* ms = SGX_CAST(ms_ecall_function_private_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_function_private();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_malloc_free(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_malloc_free();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sgx_cpuid(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sgx_cpuid_t));
	ms_ecall_sgx_cpuid_t* ms = SGX_CAST(ms_ecall_sgx_cpuid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_cpuinfo = ms->ms_cpuinfo;
	size_t _len_cpuinfo = 4 * sizeof(*_tmp_cpuinfo);
	int* _in_cpuinfo = NULL;

	CHECK_UNIQUE_POINTER(_tmp_cpuinfo, _len_cpuinfo);

	if (_tmp_cpuinfo != NULL && _len_cpuinfo != 0) {
		if ((_in_cpuinfo = (int*)malloc(_len_cpuinfo)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cpuinfo, 0, _len_cpuinfo);
	}
	ecall_sgx_cpuid(_in_cpuinfo, ms->ms_leaf);
err:
	if (_in_cpuinfo) {
		memcpy(_tmp_cpuinfo, _in_cpuinfo, _len_cpuinfo);
		free(_in_cpuinfo);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_exception(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_exception();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_map(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_map();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_increase_counter(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_increase_counter_t));
	ms_ecall_increase_counter_t* ms = SGX_CAST(ms_ecall_increase_counter_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_increase_counter();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_producer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_producer();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_consumer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_consumer();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[38];
} g_ecall_table = {
	38,
	{
		{(void*)(uintptr_t)sgx_MyStrCpy, 0},
		{(void*)(uintptr_t)sgx_MyAccum, 0},
		{(void*)(uintptr_t)sgx_TeeCalGRAT, 0},
		{(void*)(uintptr_t)sgx_TeeCalSEG, 0},
		{(void*)(uintptr_t)sgx_ecall_type_char, 0},
		{(void*)(uintptr_t)sgx_ecall_type_int, 0},
		{(void*)(uintptr_t)sgx_ecall_type_float, 0},
		{(void*)(uintptr_t)sgx_ecall_type_double, 0},
		{(void*)(uintptr_t)sgx_ecall_type_size_t, 0},
		{(void*)(uintptr_t)sgx_ecall_type_wchar_t, 0},
		{(void*)(uintptr_t)sgx_ecall_type_struct, 0},
		{(void*)(uintptr_t)sgx_ecall_type_enum_union, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_user_check, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_out, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in_out, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string_const, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_size, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_count, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_isptr_readonly, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_sizefunc, 0},
		{(void*)(uintptr_t)sgx_ocall_pointer_attr, 0},
		{(void*)(uintptr_t)sgx_ecall_array_user_check, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in, 0},
		{(void*)(uintptr_t)sgx_ecall_array_out, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in_out, 0},
		{(void*)(uintptr_t)sgx_ecall_array_isary, 0},
		{(void*)(uintptr_t)sgx_ecall_function_calling_convs, 0},
		{(void*)(uintptr_t)sgx_ecall_function_public, 0},
		{(void*)(uintptr_t)sgx_ecall_function_private, 1},
		{(void*)(uintptr_t)sgx_ecall_malloc_free, 0},
		{(void*)(uintptr_t)sgx_ecall_sgx_cpuid, 0},
		{(void*)(uintptr_t)sgx_ecall_exception, 0},
		{(void*)(uintptr_t)sgx_ecall_map, 0},
		{(void*)(uintptr_t)sgx_ecall_increase_counter, 0},
		{(void*)(uintptr_t)sgx_ecall_producer, 0},
		{(void*)(uintptr_t)sgx_ecall_consumer, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[12][38];
} g_dyn_entry_table = {
	12,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL ocall_pointer_user_check(int* val)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pointer_user_check_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_user_check_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_user_check_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_user_check_t));

	ms->ms_val = SGX_CAST(int*, val);
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_in_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memcpy(ms->ms_val, val, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_out_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_out_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memset(ms->ms_val, 0, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(3, ms);

	if (val) memcpy((void*)val, ms->ms_val, _len_val);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_in_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_out_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_out_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memcpy(ms->ms_val, val, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);

	if (val) memcpy((void*)val, ms->ms_val, _len_val);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dest = len;
	size_t _len_src = len;

	ms_memccpy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_memccpy_t);
	void *__tmp = NULL;

	ocalloc_size += (dest != NULL && sgx_is_within_enclave(dest, _len_dest)) ? _len_dest : 0;
	ocalloc_size += (src != NULL && sgx_is_within_enclave(src, _len_src)) ? _len_src : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_memccpy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_memccpy_t));

	if (dest != NULL && sgx_is_within_enclave(dest, _len_dest)) {
		ms->ms_dest = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dest);
		memcpy(ms->ms_dest, dest, _len_dest);
	} else if (dest == NULL) {
		ms->ms_dest = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (src != NULL && sgx_is_within_enclave(src, _len_src)) {
		ms->ms_src = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_src);
		memcpy((void*)ms->ms_src, src, _len_src);
	} else if (src == NULL) {
		ms->ms_src = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = val;
	ms->ms_len = len;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;
	if (dest) memcpy((void*)dest, ms->ms_dest, _len_dest);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_function_allow()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(6, NULL);

	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memset(ms->ms_cpuinfo, 0, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(7, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

