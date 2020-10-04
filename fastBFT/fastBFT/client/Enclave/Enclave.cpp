/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 


#include <stdarg.h>
#include <string.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>  
#include <unistd.h> 

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
static int clatest=0;
static int v=0;
uint8_t ikey[16];
sgx_ec256_public_t  p_public;
sgx_aes_ctr_128bit_key_t i_key;
sgx_ecc_state_handle_t ecc_handle;
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
//按二进制打印字符数组
void printbitsn(unsigned char randSecret[],int n)
{
	for(int i=0;i<n;i++)
	{
	    unsigned char a=randSecret[i];
	    int c[8];
	    for(int j=0;j<8;j++)
	    {
	        c[j]=a%2;
	        a=a/2;
	    }
	    for(int j=7;j>=0;j--)
	    {
	        printf("%d",c[j]);
	    }
	}
	printf("\n");
}
//字符数组复制
void mystrncpy(unsigned char * a,unsigned char * scv,int n)
{
    //unsigned char * p=(unsigned char *)scv;
    for(int i=0;i<n;i++)
    {
        a[i]=scv[i];
    }
}
//保存密钥
void save_key(uint8_t *key)
{
    mystrncpy((unsigned char*)&p_public,key,64);
    mystrncpy((unsigned char*)&i_key,key+64,16);
    printf("sp public key\n");
    printbitsn((unsigned char*)&p_public,64);
    printf("tee key i for decrypto\n");
    printbitsn((unsigned char*)&i_key,16);
}
//verify_counter
void verify_counter(sgx_ec256_signature_t *sprc_signature,uint8_t *ensecrets,uint8_t *hm,uint8_t *sci,uint8_t *result,uint8_t *hc1)
{
    uint8_t p_result;
	bindsicv sicv;
	//printf("hm content\n");
	//printbitsn((uint8_t *)hm,32);
	//printbitsn(ensecrets,128);
	bindhcv hmcv;
	memset(&hmcv,'\0',sizeof(hmcv));
	//hcv赋值
	mystrncpy((uint8_t*)&hmcv.hc,(uint8_t*)hm,32);
	hmcv.c=clatest+1;
	hmcv.v=v;
	//decrypto
	uint8_t de_ctr[16]={'0'};
    uint8_t ensecret[128]={'0'};
	mystrncpy((uint8_t*)ensecret,(uint8_t*)ensecrets,128);
	sgx_status_t st=sgx_aes_ctr_decrypt(&i_key,ensecret,128,
	    de_ctr,128,(uint8_t*)&sicv);
	strncpy((char*)sci,(char*)sicv.si,16);
	printbitsn(sci,16);
    strncpy((char*)hc1,(char*)sicv.hc,32);
    printf("decrypto %d\n",st);
	
	//进行SHA256映射
    uint8_t hmcvh[32]; 
    
    sgx_sha256_msg((uint8_t *)&hmcv,sizeof(hmcv),&hmcvh);
	
	sgx_ecc256_open_context(&ecc_handle);
	sgx_ecdsa_verify((uint8_t *)hmcvh,32,&p_public, sprc_signature,&p_result, ecc_handle);
	sgx_ecc256_close_context(ecc_handle);

	printf("signature verify p_result %d\n",p_result);
	
	if(p_result!=0) strncpy((char*)result,"invalid signature",sizeof("invalid signature"));
	//printf("p_result%d\n",p_result);
	 else if(st!=SGX_SUCCESS)strncpy((char*)result,"invalid encryption",sizeof("invalid encryption"));
    else if(sicv.c!=clatest&&sicv.v!=v)strncpy((char*)result,"invalid counter value",sizeof("invalid encryption"));
    else{
        clatest=clatest+1;
        printf("clatest%d\n",clatest);
        strncpy((char*)result,"ok",sizeof("ok"));
    }
}
void verify_c(uint8_t *ensecrets,uint8_t *sicv,size_t bsize)
{
    
	uint8_t de_ctr[16]={'0'};
	bindsicv sv;
	uint8_t ensecret[128]={'0'};
	mystrncpy((uint8_t*)ensecret,(uint8_t*)ensecrets,128);
	
	sgx_status_t st=sgx_aes_ctr_decrypt(&i_key,ensecret,128,de_ctr,128,(uint8_t*)&sv);
	mystrncpy((unsigned char*)sicv,(unsigned char*)&sv,sizeof(sv));
	printf("decrypto result%d",st);
}
