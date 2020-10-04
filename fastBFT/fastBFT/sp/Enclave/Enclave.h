
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
//void sac_decrypt(unsigned char *ensecret,unsigned char *desecret,size_t en_size,size_t de_size,int k);
int verify_shares(unsigned char *shares,size_t shares_size,int m);
void Init(sgx_aes_ctr_128bit_key_t *p_key1,sgx_ec256_public_t *pout_public,size_t pk_size,size_t pub_size);

void preprocessing(sgx_ec256_signature_t *p_sg, uint8_t *en_s,size_t p_size,size_t en_size);

void request_counter(uint8_t *hm,sgx_ec256_signature_t *sprc_signature);
void get_secrets(uint8_t *dsecrets,uint8_t *dhcs,size_t mnum);
void save_key(uint8_t *key);
//void verify_counter(sgx_ec256_signature_t *sprc_signature,uint8_t *ensecrets,uint8_t *hm,uint8_t *sci,uint8_t *result,uint8_t *hc1);
//void update_counter(uint8_t *sc,sgx_ec256_signature_t *up_signature,uint8_t *hc1,uint8_t *result);
int get_c();
int get_v();
void go_back();
//void ende();

//void ecall_mymemcpy();

//void TeeCalGRAT(struct mTrsLt *mTLst, struct msgRtLt *msRf,struct gCarTrust *gCTrust,size_t DeLen,size_t SoLen,size_t gCLen,int n);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
