#include <stdarg.h>
#include <string.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>  
#include <unistd.h> 

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#include <string>
#include <iostream>
#include <vector>
#include <cstdlib>
#include <bitset>

static uint32_t clatest=0;//latest counter value
uint32_t cpre=0;
static uint32_t v=0;//current view number
//定义椭圆曲线公私钥
sgx_ec256_private_t  p_private;//sp private key
sgx_ec256_public_t  p_public;//sp public key
sgx_aes_ctr_128bit_key_t i_key;//view key
sgx_ecc_state_handle_t ecc_handle;//ECC GF context
//存储最大生成MaxNumM组秘密及shares,128bits secret,key_size=16,MaxNumSa is active replica number
static uint8_t msecrets[MaxNumM][key_size];
static uint8_t mshares[MaxNumM][key_size*MaxNumSa];
//最大副本节点，生成MaxNumS对密钥
sgx_aes_ctr_128bit_key_t p_key[MaxNumS];//存储ki密钥
sgx_ec256_signature_t p_signatures[MaxNumM];//存储m轮<hc,c,v>签名
//按照active replica顺序存储m轮<sci,c,v，hc>加密数据
uint8_t ensecrets[MaxNumSa][MaxNumM][128];
uint8_t hcs[MaxNumM][32];//存储m轮H<sc,c,v>结果
//字符数组复制,将长度为key_size的字符数组b拷贝给a
void mystrcpy(uint8_t a[],uint8_t b[])
{
    for(int i=0;i<key_size;i++)
    {
        a[i]=b[i];
    }
}
//字符数组复制,将长度为n的字符数组b拷贝给a
void mystrncpy(uint8_t * a,uint8_t * scv,int n)
{
    //uint8_t * p=(uint8_t *)scv;
    for(int i=0;i<n;i++)
    {
        a[i]=scv[i];
    }
}
//字符数组比较,比较长度为key_size的字符数组a和b的大小
int mystrcmp(uint8_t a[],uint8_t b[])
{
    int i=0;
    for(;i<key_size;i++)
    {
        if(a[i]==b[i]&&i!=key_size)continue;
        else break;
    }
    return i==key_size?1:0;
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
//按二进制打印长度为key_size字符数组
void printbits(uint8_t randSecret[])
{
	for(int i=0;i<key_size;i++)
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
//按二进制打印长度为n字符数组
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
//生成128-bit随机secret函数，使用无符号字符数组存储秘密，数组长度为key_size=128/8=16
void generate_random_secret(uint8_t secret[])
{
    //按每个无符号字符生成随机secret
	for(int i=0;i<key_size;i++)
	{
		sgx_read_rand((uint8_t *)&secret[i],sizeof(uint8_t));//调用sdk函数按字符元素生成随机秘密
	}
	//按二进制位打印随机secret
	/*printf("\nsecret\n");
	printbits(secret);*/
}
//生成n个随机shares秘密，使其异或运算结果为原始的随机secret
void xor_shares_split(uint8_t secret[],uint8_t shares[][key_size],int n)
{
    //首先生成n-1个随机shares,
	for(int i=0;i<n-1;i++)
	{
		for(int j=0;j<key_size;j++)
		{
			sgx_read_rand((uint8_t *)&shares[i][j],sizeof(uint8_t));
		}
	}
	//然后打印n-1个随机shares
	/*for(int i=0;i<n-1;i++)
	{
	    printf("shares%d\n",i);
	    printbits(shares[i]);
	}*/
	//通过secret与n-1个shares异或运算得出最后一个shares
	uint8_t xorShares[key_size];//存储xor秘密
	mystrcpy(xorShares,secret);//将secret拷贝到xor秘密中
	//将secret与生成的n-1个shares进行xor运算得到最后一个shares
	for(int i=0;i<n-1;i++)
	{
		for(int j=0;j<key_size;j++)
		{
			xorShares[j]=xorShares[j]^shares[i][j];
		}
	}
	//存储xor运算得到最后一个shares
	mystrcpy(shares[n-1],xorShares);
	//打印最后一个shares
	//printf("shares%d\n",n-1);
	//printbits(xorShares);
}
//对n个shares进行验证，判断异或运算结果是否为secret
int  verify_shares(uint8_t *shares,size_t shares_size,int m)
{
    uint8_t xor_secret[key_size];//存储xor秘密
    uint8_t aShares[MaxNumSa][key_size];//存储传入的参数shares
    mystrncpy((uint8_t *)aShares,shares,shares_size);//拷贝传入的参数shares
	mystrcpy(xor_secret,aShares[0]);//拷贝第一个share
	//使用异或运算对n个shares进行xor聚合
    for(int i=1;i<shares_size/16;i++)
    {
		for(int j=0;j<key_size;j++)
		{
			xor_secret[j]=(xor_secret[j]^aShares[i][j]);
		}
	}
	//mystrcpy(xor_secret,xorShares);
	//比较聚合后xor_secret与原始的secret是否相等
	if(mystrcmp(msecrets[m],xor_secret)==1)return 1;
	else return 0;
}
//打印函数
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
//获取两组用于reply2的secret和hc
void get_secrets(uint8_t *dsecrets,uint8_t *dhcs,size_t mnum)
{
    mystrncpy(dsecrets,(uint8_t *)&msecrets[mnum],32);
    mystrncpy(dhcs,(uint8_t *)&hcs[mnum],64);
}
/*
//对称解密 test
void sac_decrypt(uint8_t *ensecret,uint8_t *desecret,size_t en_size,size_t de_size,int k)
{
    //uint32_t ctr_inc_bits=128;
    uint8_t de_ctr[16]={'0'};
    bindsicv de;
    //对称解密
    sgx_aes_ctr_decrypt(&p_key[k],ensecret,128,
    de_ctr,128,(uint8_t*)&de);
    printf("preprocessing decrypt\n");
    printbitsn((uint8_t*)&de,de_size);
	printf("\n");
	mystrncpy((uint8_t*)desecret,(uint8_t*)&de,de_size);
}*/
//初始化sp的公私钥，以及ki密钥
void Init(sgx_aes_ctr_128bit_key_t *p_key1,sgx_ec256_public_t *pout_public,size_t pk_size,size_t pub_size)
{
    //初始化sp与s之间的对称密钥
    for(int i=0;i<pk_size/16;i++)
    {
        uint8_t randSecret[key_size];//临时存储生成的密钥
        for(int i=0;i<key_size;i++)
	    {
		    sgx_read_rand((uint8_t *)&randSecret[i],sizeof(uint8_t));
	    }
	    mystrcpy((uint8_t *)&p_key[i],randSecret);//存储生成的第i个密钥
	    //printf("k%d\n",i);
	    //printbitsn(randSecret,key_size);
    }
    //初始化椭圆曲线公私钥
    sgx_status_t ret;
    //open a handle to the ECC GF(p) context;
	ret=sgx_ecc256_open_context(&ecc_handle);
	//create_key_pair
	ret=sgx_ecc256_create_key_pair(&p_private,&p_public,ecc_handle);
	//close a handle to the ECC GF(p) context;
	sgx_ecc256_close_context(ecc_handle);
	if(ret!=SGX_SUCCESS) 
	{
	    printf("create public key and private key error\n");
	    //exit(0);
	}
	printf("Init public key\n");
	printbitsn((uint8_t *)&p_public,sizeof(sgx_ec256_public_t));
    mystrncpy((uint8_t *)p_key1,(uint8_t *)p_key,pk_size);//传到TEE外ki
    mystrncpy((uint8_t *)pout_public,(uint8_t *)&p_public,sizeof(sgx_ec256_public_t));//传到TEE外public key
}
void go_back()
{
    clatest=clatest-1;
}
//预处理过程，生成秘密与shares，将secret与计数器绑定
void preprocessing(sgx_ec256_signature_t *p_sg, uint8_t *en_s,size_t p_size,size_t en_size)
{
    //m次循环操作
    for(uint32_t a=1;a<=MaxNumM;a++)
    {   
        //c=clatest+a;
        uint32_t cpre=clatest+a;//预处理c
        uint8_t secret[key_size];//存储临时secret
        uint8_t xor_secret[key_size]={'0'};
	    uint8_t shares[MaxNumSa][key_size]={'0'};//存储临时shares
	    bindscv scv;//绑定sc，c，v，用于H(<sc,c,v>)参数
	    bindhcv hcv;//绑定hc，c，v，用于Sign(<hc,c,v>)参数
	    //sc<-{0,1}
	    generate_random_secret(secret);//生成secret
	    //printf("generate secret\n");
	    //printbits(secret);
	    //存储生成的秘密
        mystrcpy((uint8_t*)&msecrets[a-1],secret);
	    mystrcpy(scv.secret,secret);
	    scv.c=cpre;
	    hcv.c=cpre;
	    scv.v=v;
	    hcv.v=v;
	    uint8_t hc[32];//存储H(<sc,c,v>)结果
	    //hc<-H(<sc,(c,v)>)进行SHA256映射
        sgx_sha256_msg((uint8_t *)&scv,sizeof(scv),&hc);
        mystrncpy(hcs[a-1],hc,32);
        mystrncpy(hcv.hc,hc,32);
        //sc1+sc2+...+sc(f+1)<-sc
	    xor_shares_split(secret,shares,en_size/(128*MaxNumM));
	    //存储生成的shares
	    mystrncpy((uint8_t*)&mshares[a-1],(uint8_t*)&shares[0],key_size*en_size/(128*MaxNumM));
	    //Eic<-E(ki,<sci,(c,v),hcj,hc)
	    //uint8_t myensecret[MaxNumSa][128]={'0'};
	    //将子秘密sci，c，v与hc聚合进行加密
	    for(int i=0;i<(en_size/(128*MaxNumM));i++)
	    {
	        bindsicv sicv;
	        memset(&sicv,'0',sizeof(sicv));
            mystrncpy(sicv.si,shares[i],16);
            sicv.c=cpre;
            sicv.v=v;
            mystrncpy(sicv.hc,hc,sizeof(hc));
            
            //printf("sicv.c%d\n",sicv.c);
            //printbitsn((uint8_t*)&sicv.si,sizeof(sicv.si));
            //进行对称加密操作
	        uint8_t en_ctr[16]={'0'};
	        uint8_t ensecret[128]={'0'};
	        //uint32_t ctr_inc_bits=128;
	        //为每个<sci,c,v,hc>对称加密
	        sgx_aes_ctr_encrypt(&p_key[i],(uint8_t*)&sicv,sizeof(sicv),en_ctr,128,(uint8_t*)ensecret);
	        //printbitsn(ensecret,128);
	        //存储每个<sci,c,v,hc>对称加密结果
	        mystrncpy((uint8_t*)&ensecrets[i][a-1],(uint8_t*)ensecret,128);
	    }
	    //<hc,(c,v)>ap<-Sign(<hc,(c,v)>)
	    sgx_status_t ret;
        //进行ecsda签名操作
        //TEE中的ecsda签名操作必须是待签名的数据的哈希值为,其中h(x)sha256结果
        uint8_t hcvh[32];
	    //进行SHA256映射
        sgx_sha256_msg((uint8_t *)&hcv,sizeof(hcv),&hcvh);
	    sgx_ec256_signature_t p_signature;
	    sgx_ecc256_open_context(&ecc_handle);
	    sgx_ecdsa_sign((uint8_t *)&hcvh,32,&p_private,&p_signature,ecc_handle);
	    sgx_ecc256_close_context(ecc_handle); 
	    //进行ecsda验证签名操作
	    //uint8_t p_result;
	    //sgx_ecdsa_verify((uint8_t *)&hcvh,sizeof(hcvh),&p_public, &p_signature,&p_result, ecc_handle);
	    //存储m轮的ecsda签名结果
        mystrncpy((uint8_t*)&p_signatures[a-1],(uint8_t*)&p_signature,sizeof(sgx_ec256_signature_t));
        //int i=verify_shares(secret,xor_secret,shares,MaxNumSa);
	    //printf("verify %s\n",i?"same":"not same");   
    }
    mystrncpy((uint8_t*)en_s,(uint8_t*)ensecrets,en_size);
    mystrncpy((uint8_t*)p_sg,(uint8_t*)&p_signatures,p_size);
    //printf("ensecrets size %d\n",sizeof(ensecrets));
}
//clatest=clatest+1,sign(x,clatest,v)
void request_counter(uint8_t *hm,sgx_ec256_signature_t *sprc_signature)
{
    //clatest=clatest+1
    clatest=clatest+1;
	//printbitsn((uint8_t *)hm,32);
    bindhcv hmcv;
    mystrncpy((uint8_t*)&hmcv.hc,(uint8_t*)hm,32);
    hmcv.c=clatest;
    hmcv.v=v;
    //进行SHA256映射
    uint8_t hmcvh[32]; 
    sgx_sha256_msg((uint8_t *)&hmcv,sizeof(hmcv),&hmcvh);
    sgx_ec256_signature_t p_signaturet;
	sgx_ecc256_open_context(&ecc_handle);
	//sign for hmcvh
	sgx_ecdsa_sign((uint8_t *)hmcvh,32,&p_private,&p_signaturet,ecc_handle);
    //verify signature
    uint8_t p_result;
    mystrncpy((uint8_t*)sprc_signature,(uint8_t*)&p_signaturet,64);
	sgx_ecdsa_verify((uint8_t *)&hmcvh,32,&p_public, &p_signaturet,&p_result, ecc_handle);
	sgx_ecc256_close_context(ecc_handle);
	printf("clatest%d\n",clatest);
	printf("request_counter p_result%d\n",p_result);
}
//保存密钥
void save_key(uint8_t *key)
{
    mystrncpy((uint8_t*)&p_public,key,64);
    mystrncpy((uint8_t*)&i_key,key+64,16);
    printf("sp public key\n");
    printbitsn((uint8_t*)&p_public,64);
    printf("tee key i for decrypto\n");
    printbitsn((uint8_t*)&i_key,16);
}
/*
//verify_counter
void verify_counter(sgx_ec256_signature_t *sprc_signature,uint8_t *spensecret,uint8_t *hm,uint8_t *sci,uint8_t *result,uint8_t *hc1)
{
    uint8_t p_result;
	bindsicv sicv;
	//printf("hm content\n");
	//printbitsn((uint8_t *)hm,32);
	//printbitsn(spensecret,128);
	bindhcv hmcv;
	memset(&hmcv,'\0',sizeof(hmcv));
	//hcv赋值
	mystrncpy((uint8_t*)&hmcv.hc,(uint8_t*)hm,32);
	hmcv.c=clatest+1;
	hmcv.v=v;
	//decrypto
	uint8_t de_ctr[16]={'0'};
    //uint8_t ensecret[128]={'0'};
	//mystrncpy((uint8_t*)ensecret,(uint8_t*)spensecret,128);
	sgx_aes_ctr_128bit_key_t i_keyt;
	mystrncpy((uint8_t*)&i_keyt,(uint8_t*)&i_key,sizeof(i_keyt));
	sgx_status_t st=sgx_aes_ctr_decrypt(&i_keyt,ensecret,128,
	    de_ctr,128,(uint8_t*)&sicv);
	mystrncpy((uint8_t *)sci,(uint8_t *)sicv.si,16);
	//printbitsn(sci,16);
    mystrncpy((uint8_t *)hc1,(uint8_t *)sicv.hc,32);
    printf("decrypto %d\n",st);
	
	//进行SHA256映射
    uint8_t hmcvh[32]; 
    
    sgx_sha256_msg((uint8_t *)&hmcv,sizeof(hmcv),&hmcvh);
	//printbitsn((uint8_t*)&p_public,64);
	sgx_ecc256_open_context(&ecc_handle);
	sgx_ecdsa_verify((uint8_t *)hmcvh,32,&p_public, sprc_signature,&p_result, ecc_handle);
	sgx_ecc256_close_context(ecc_handle);

	printf("signature verify p_result %d\n",p_result);
	
	if(p_result!=0) strncpy((char*)result,"invalid signature",sizeof("invalid signature"));
	//printf("p_result%d\n",p_result);
	 else if(st!=SGX_SUCCESS)strncpy((char*)result,"invalid encryption",sizeof("invalid encryption"));
    else if(sicv.c!=clatest&&sicv.v!=v)strncpy((char*)result,"invalid counter value",sizeof("invalid counter value"));
    else{
        clatest=clatest+1;
        printf("clatest%d\n",clatest);
        strncpy((char*)result,"ok",sizeof("ok"));
    }
}
void update_counter(uint8_t *sc,sgx_ec256_signature_t *up_signature,uint8_t *hc1,uint8_t *result)
{
    bindscv scv;
    bindhcv hcv;
    uint8_t p_result;
    
    mystrncpy(scv.secret,sc,16);
    scv.c=clatest+1;
    scv.v=v;
    uint8_t hc2[32];
	//hc<-H(<sc,(c,v)>)进行SHA256映射
    sgx_sha256_msg((uint8_t *)&scv,sizeof(scv),&hc2);
    
	memset(&hcv,'\0',sizeof(hcv));
	//hcv赋值
	mystrncpy((uint8_t*)&hcv.hc,(uint8_t*)hc1,32);
	hcv.c=clatest+1;
	hcv.v=v;
	//进行SHA256映射
    uint8_t hcvh[32]; 
    
    sgx_sha256_msg((uint8_t *)&hcv,sizeof(hcv),&hcvh);
	sgx_ecc256_open_context(&ecc_handle);
	sgx_ecdsa_verify((uint8_t *)hcvh,32,&p_public, up_signature,&p_result, ecc_handle);
	sgx_ecc256_close_context(ecc_handle);
	printf("update phase signature verify p_result %d\n",p_result);
	
	if(p_result!=0) strncpy((char*)result,"invalid signature",sizeof("invalid signature"));
	//printf("p_result%d\n",p_result);
    else if(mystrncmp(hc2,hc1,32)==0)strncpy((char*)result,"invalid secret",sizeof("invalid secret"));
    else{
        clatest=clatest+1;
        printf("clatest%d\n",clatest);
        strncpy((char*)result,"ok",sizeof("ok"));
    }
}*/
int get_c()
{
    return clatest;
}
int get_v()
{
    return v;
}
