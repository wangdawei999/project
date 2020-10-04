#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "sgx_tcrypto.h"

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);
//void ecall_mymemcpy();

//void TeeCalGRAT(struct mTrsLt *mTLst, struct msgRtLt *msRf,struct gCarTrust *gCTrust,size_t DeLen,size_t SoLen,size_t gCLen,int n);
void save_key(uint8_t *key);
void verify_counter(sgx_ec256_signature_t *sprc_signature,uint8_t *ensecrets,uint8_t *hm,uint8_t *sci,uint8_t *result,uint8_t *hc1);
void verify_c(uint8_t *ensecrets,uint8_t *sicv,size_t bsize);
#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
