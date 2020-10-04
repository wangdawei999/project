#include <stdarg.h>
#include <string.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>  
#include <unistd.h> 

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
static uint32_t clatest=0;//latest counter value
static uint32_t v=0;//current view number
sgx_ec256_public_t  sp_public;//sp public key
sgx_aes_ctr_128bit_key_t i_key;//view key
sgx_ecc_state_handle_t ecc_handle;//ECC GF context
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
//按二进制打印长度为key_size字符数组
void printbitsn(uint8_t randSecret[],int n)
{
	for(int i=0;i<n;i++)
	{
	    uint8_t a=randSecret[i];
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
//字符数组复制,将长度为n的字符数组b拷贝给a
void mystrncpy(uint8_t * a,uint8_t * b,int n)
{
    //uint8_t * p=(uint8_t *)scv;
    for(int i=0;i<n;i++)
    {
        a[i]=b[i];
    }
}
//字符数组比较
int mystrncmp(uint8_t a[],uint8_t b[],int n)
{
    int i=0;
    for(;i<n;i++)
    {
        if(a[i]==b[i]&&i!=n)continue;
        else break;
    }
    return i==n?1:0;
}
//保存public key ,密钥ki
void save_key(uint8_t *key)
{
    mystrncpy((uint8_t*)&sp_public,key,64);
    mystrncpy((uint8_t*)&i_key,key+64,16);
    printf("sp public key\n");
    printbitsn((uint8_t*)&sp_public,64);
    printf("tee key i for decrypto\n");
    printbitsn((uint8_t*)&i_key,16);
}
//verify_counter
void verify_counter(sgx_ec256_signature_t *sprc_signature,uint8_t *ensecrets,uint8_t *hm,uint8_t *sci,uint8_t *result,uint8_t *hc1)
{
    uint8_t p_result;//decrypto result
	bindsicv sicv;//save si,c,v
	memset(&sicv,'\0',sizeof(sicv));
	//printf("hm content\n");
	//printbitsn((uint8_t *)hm,32);
	//printbitsn(ensecrets,128);
	bindhcv hmcv;//save hm,c,v
	memset(&hmcv,'\0',sizeof(hmcv));
	//hmcv赋值
	mystrncpy((uint8_t*)&hmcv.hc,(uint8_t*)hm,32);
	hmcv.c=clatest+1;
	hmcv.v=v;
	//decrypto
	uint8_t de_ctr[16]={'0'};
    uint8_t ensecret[128]={'0'};
	mystrncpy((uint8_t*)ensecret,(uint8_t*)ensecrets,128);
	
	sgx_aes_ctr_128bit_key_t i_keyt;
	mystrncpy((uint8_t*)&i_keyt,(uint8_t*)&i_key,sizeof(i_keyt));
	//decryto E<sci,c,v,hc>
	uint32_t ctr_inc_bits=128;
	sgx_status_t st=sgx_aes_ctr_decrypt(&i_keyt,ensecret,sizeof(ensecret),
	    de_ctr,ctr_inc_bits,(uint8_t*)&sicv);
    //printf("sicv.c%d\n",sicv.c);
    //printbitsn((uint8_t*)&sicv.si,sizeof(sicv.si));
	mystrncpy((uint8_t *)sci,(uint8_t *)sicv.si,16);
	//printbitsn(sci,16);
    mystrncpy((uint8_t *)hc1,(uint8_t *)sicv.hc,32);
    printf("decrypto %d\n",st);
	
	//进行SHA256映射
    uint8_t hmcvh[32]; 
    
    sgx_sha256_msg((uint8_t *)&hmcv,sizeof(hmcv),&hmcvh);
	//printbitsn((uint8_t*)&sp_public,64);
	sgx_ecc256_open_context(&ecc_handle);
	//verify signature result
	sgx_ecdsa_verify((uint8_t *)hmcvh,32,&sp_public, sprc_signature,&p_result, ecc_handle);
	sgx_ecc256_close_context(ecc_handle);

	printf("signature verify p_result %d\n",p_result);
	printf("sicv.c%d clatest%d\n",sicv.c,clatest);
	if(p_result!=0) strncpy((char*)result,"invalid signature",sizeof("invalid signature"));
	//printf("p_result%d\n",p_result);
	else if(st!=SGX_SUCCESS)strncpy((char*)result,"invalid encryption",sizeof("invalid encryption"));
    else if((sicv.c!=clatest+1)&&(sicv.v!=v))strncpy((char*)result,"invalid counter value",sizeof("invalid counter value"));
    else{
        clatest=clatest+1;
        printf("clatest%d\n",clatest);
        strncpy((char*)result,"ok",sizeof("ok"));
    }
}
//passive replica update counter in reply2 phase
void update_counter(uint8_t *sc,sgx_ec256_signature_t *up_signature,uint8_t *hc1,uint8_t *result)
{
    bindscv scv;//save s,c,v
    bindhcv hcv;//save hc,c,v
    uint8_t p_result;
    
    mystrncpy(scv.secret,sc,16);
    scv.c=clatest+1;
    scv.v=v;
    uint8_t scvh[32];//save H<sc,c,v> result
	//hc<-H(<sc,(c,v)>)进行SHA256映射
    sgx_sha256_msg((uint8_t *)&scv,sizeof(scv),&scvh);
    
	memset(&hcv,'\0',sizeof(hcv));
	//hcv赋值
	mystrncpy((uint8_t*)&hcv.hc,(uint8_t*)hc1,32);
	hcv.c=clatest+1;
	hcv.v=v;
	//进行SHA256映射
    uint8_t hcvh[32]; 
    
    sgx_sha256_msg((uint8_t *)&hcv,sizeof(hcv),&hcvh);
	sgx_ecc256_open_context(&ecc_handle);
	sgx_ecdsa_verify((uint8_t *)hcvh,32,&sp_public, up_signature,&p_result, ecc_handle);
	sgx_ecc256_close_context(ecc_handle);
	printf("update phase signature verify p_result %d\n",p_result);
	
	if(p_result!=0) strncpy((char*)result,"invalid signature",sizeof("invalid signature"));
	//printf("p_result%d\n",p_result);
    else if(mystrncmp(scvh,hc1,32)==0)strncpy((char*)result,"invalid secret",sizeof("invalid secret"));
    else{
        clatest=clatest+1;
        printf("clatest%d\n",clatest);
        strncpy((char*)result,"ok",sizeof("ok"));
    }
}
//get counter value
int get_c()
{
    return clatest;
}
//get view number
int get_v()
{
    return v;
}
/*
void verify_c(uint8_t *ensecrets,uint8_t *sicv,size_t bsize)
{
    
	uint8_t de_ctr[16]={'0'};
	bindsicv sv;
	uint8_t ensecret[128]={'0'};
	mystrncpy((uint8_t*)ensecret,(uint8_t*)ensecrets,128);
	
	sgx_status_t st=sgx_aes_ctr_decrypt(&i_key,ensecret,128,de_ctr,128,(uint8_t*)&sv);
	mystrncpy((uint8_t*)sicv,(uint8_t*)&sv,sizeof(sv));
	printf("decrypto result%d",st);
}*/
