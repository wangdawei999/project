//c header file
#include <stdio.h>
#include <string.h> 
#include <strings.h>
#include <assert.h>
#include <sys/time.h>
//system header file
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
//SGX header file,runtime,untrusted
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"

/*socket tcp service*/
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>
/*select*/
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/sha.h>

#define SERVER_PORT 1234
#define BACKLOG 1
#define MaxSize 2000000
int Msize=1;
uint32_t res;//Msize,简单代表执行M，这里实现求字节数操作
int bufLen=MaxSize+400;//发送和接收缓冲区的长度
uint8_t ensecrets[2][128];//用于整个过程的两个secrets
char M[MaxSize]={'\0'};//存储消息M
uint8_t hcpre[32];//获取prepare阶段的验证计数器返回的哈希
uint8_t hccom[32];//获取commit2阶段的验证计数器返回的哈希
sgx_ec256_signature_t sppre_signature;//存储prepare阶段的sp发送的关于<h(M),c,v>签名
sgx_ec256_signature_t spcom_signature;//存储commit2阶段的sp发送的关于<h(M||res),c,v>签名
sgx_ec256_signature_t p_signature[2];//preprocessing阶段准备的签名集合sign<hc,c,v>
uint8_t msecrets[2][16];//用于整个过程的两个secrets
uint8_t hcs[2][32];//用于整个过程的两个哈希值H<sc,c,v>
//定义存储公钥和对称密钥的结构体
struct ipkey{
    sgx_ec256_public_t  sp_public;
    sgx_aes_ctr_128bit_key_t i_key;
};
//定义存储res，M的结构体
typedef struct resM{
    uint32_t res;
    char M[MaxSize];
} resM;
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
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* OCall functions *//* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
  */
void ocall_print_string(const char *str)
{
    
    printf("%s", str);
} 
//按二进制打印字符数组
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
//字符数组复制
void mystrncpy(uint8_t * a,uint8_t * scv,int n)
{
    //uint8_t * p=(uint8_t *)scv;
    for(int i=0;i<n;i++)
    {
        a[i]=scv[i];
    }
}
bool RecvAll(int  sock, char * buffer, int size)
{
    while (size>0)//剩余部分大于0
    {
        int RecvSize= recv(sock, buffer, size, 0);
        if(RecvSize<=0)
            return false;
        size = size - RecvSize;
        buffer+=RecvSize;
    }
    return true;
}
/* Application entry */  
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    if(argc<2){
		printf("please input two parament ./si Msize\n");
		exit(0);
	}
    Msize=atoi(argv[1]);
    //Msize=1;
    //Initialize the enclave 
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        exit(0); 
    }
    
    //创建套接字
    int clt_sock = socket(AF_INET, SOCK_STREAM, 0);

    int recvbuff = 2*1024*1024;
    if(setsockopt(clt_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&recvbuff, sizeof(int)) == -1)
	printf("setsocket error\n");
else
	printf("setsocket success\n");

    //向服务器（特定的IP和端口）发起请求
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));  //每个字节都用0填充
    serv_addr.sin_family = AF_INET;  //使用IPv4地址
    serv_addr.sin_addr.s_addr = inet_addr("192.168.199.240");  //具体的IP地址
    serv_addr.sin_port = htons(1234);  //端口
    if(connect(clt_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))<0)
    {
        perror("connect error");
        return 1;
    }
    char sendBuf[bufLen];
    char recvBuf[bufLen];
    int numbytes;
    struct ipkey ipk;
    while(1)
    {
        memset(recvBuf,'\0',bufLen);
        if ((numbytes=recv(clt_sock,recvBuf,15,0)) == -1)
        { 
            printf("recv"); 
            break;
        }
         if(numbytes <= 0)
        {
            printf("recv error\n");
            exit(0);
        }
        char type[15];
		memcpy(type,recvBuf,15);
		printf("recv msg %s\n",type);
		if(strcmp(type,"key")==0)
		{   
		    /*if ((numbytes=recv(clt_sock,recvBuf,bufLen,0)) == -1)
            { 
                printf("recv"); 
                break;
            }
            if(numbytes <= 0)
            {
                printf("recv000\n");
                exit(0);
            } */ 
            //uint8_t key[16];
            memset(recvBuf,'\0',bufLen);
            int size=sizeof(ipk);
            if(RecvAll(clt_sock,recvBuf,size)==false)exit(0);
	        mystrncpy((uint8_t* )&ipk,(uint8_t*)recvBuf,sizeof(ipk));
	        //printbitsn(key,16);
	        save_key(global_eid,(uint8_t*)&ipk);
	        
        }
		else if(strcmp(type,"preprocessing")==0)
		{
		    /*if ((numbytes=recv(clt_sock,recvBuf,bufLen,0)) == -1)
            { 
                printf("recv"); 
                break;
            }
            if(numbytes <= 0)
            {
                printf("recv000\n");
                exit(0);
            } */ 
            memset(recvBuf,'\0',bufLen);
            int size=sizeof(ensecrets);
            if(RecvAll(clt_sock,recvBuf,size)==false)exit(0);
		    memset(ensecrets,'\0',sizeof(ensecrets));
	        mystrncpy((uint8_t* )&ensecrets,(uint8_t*)recvBuf,sizeof(ensecrets));
	        printf("preprocessing ok\n");
        }
		else if(strcmp(type,"prepare")==0)
		{
		    /*char svBuf[bufLen];
		    memset(svBuf,'\0',bufLen);
		    int total=0;
		    while(1)
            { 
                memset(recvBuf,'\0',bufLen);
                if ((numbytes=recv(clt_sock,recvBuf,bufLen,0)) == -1)
                { 
                    printf("recv"); 
                    break;
                }
                if(numbytes>0)
                {
                    memcpy(svBuf+total,recvBuf,numbytes);
                    total+=numbytes;
                }
                else if(numbytes <= 0)
                {
                    printf("recv000\n");
                    exit(0);
                }  
                if(total>=Msize+64)break;
            }*/
            memset(recvBuf,'\0',bufLen);
            int size=Msize+64;
            if(RecvAll(clt_sock,recvBuf,size)==false)exit(0);
		    memset(&sppre_signature,'\0',sizeof(sppre_signature));
            memcpy(M,recvBuf,Msize);
            memcpy(&sppre_signature,recvBuf+Msize,64);
            printf("M%c\n",M[Msize-1]);
            uint8_t sci[16];
            uint8_t result[30];
            uint8_t hm[32];
            SHA256( (uint8_t *)M, Msize, hm);
            //活跃的副本节点si调用verify counter，验证签名，加密计数器，解密出commit1阶段用的si
            verify_counter(global_eid,&sppre_signature,ensecrets[0],hm,sci,result,hcpre);
            printf("prepare result %s\n",result);
            //printbitsn((uint8_t*)&sppre_signature,64);
            memset(sendBuf,'\0',bufLen);
	        memcpy(sendBuf,sci,sizeof(sci));
            send(clt_sock,sendBuf,sizeof(sci),0);
            //printf("prepare send sci\n");
            //printbitsn(sci,16);
        }
		else if(strcmp(type,"commit2")==0)
		{
		    //memset(&ms,'\0',bufLen);
            //memcpy(ms.type,"reply1",sizeof("reply1"));
            //memcpy(ms.content,"reply1",sizeof("reply1"));
            /*char svBuf[bufLen];
		    memset(svBuf,'\0',bufLen);
		    int total=0;
		    while(1)
            { 
                memset(recvBuf,'\0',bufLen);
                if ((numbytes=recv(clt_sock,recvBuf,bufLen,0)) == -1)
                { 
                    printf("recv"); 
                    break;
                }
                if(numbytes>0)
                {
                    memcpy(svBuf+total,recvBuf,numbytes);
                    total+=numbytes;
                }
                else if(numbytes <= 0)
                {
                    printf("recv000\n");
                    exit(0);
                }  
                if(total>=sizeof(res)+64)break;
            }*/
            memset(recvBuf,'\0',bufLen);
            int size=sizeof(res)+64;
            if(RecvAll(clt_sock,recvBuf,size)==false)exit(0);
            memset(&spcom_signature,'\0',sizeof(spcom_signature));
            res=Msize;
            uint32_t rest;
            struct resM resM1;
			memset(&resM1,'\0',sizeof(resM1));
            memcpy(&rest,recvBuf,sizeof(res));
            memcpy(&spcom_signature,recvBuf+sizeof(res),64);
            if(res==rest)printf("res right\n");
            //printf("\n\nresM1%s\n",resM1);
            uint8_t hresM[32];
            uint8_t sci[16];
            uint8_t result[30];
            resM1.res=res;
            memcpy(&resM1.M,M,Msize);
            SHA256( (uint8_t *)&resM1, sizeof(res)+Msize, hresM);
            //活跃的副本节点si调用verify counter，验证签名，加密计数器，解密出commit1阶段用的si
            //printf("resM1 bit\n");
            //printbitsn((uint8_t *)&hresM,32);
            verify_counter(global_eid,&spcom_signature,ensecrets[1],hresM,sci,result,hccom);
            printf("commit2 result %s\n\n",result);
            //printbitsn((uint8_t*)&spcom_signature,64);
            memset(sendBuf,'\0',bufLen);
	        memcpy(sendBuf,sci,sizeof(sci));
            send(clt_sock,sendBuf,sizeof(sci),0);
            //printf("commit2 send sci\n\n\n");
            //printbitsn(sci,16);
        }
		else if(strcmp(type,"reply2")==0)
        {
            /*char svBuf[bufLen];
		    memset(svBuf,'\0',bufLen);
		    int total=0;
		    while(1)
            { 
                memset(recvBuf,'\0',bufLen);
                if ((numbytes=recv(clt_sock,recvBuf,bufLen,0)) == -1)
                { 
                    printf("recv"); 
                    break;
                }
                if(numbytes>0)
                {
                    memcpy(svBuf+total,recvBuf,numbytes);
                    total+=numbytes;
                }
                else if(numbytes <= 0)
                {
                    printf("recv000\n");
                    exit(0);
                }  
                if(total>=Msize+sizeof(res)+288)break;
            }*/
            memset(recvBuf,'\0',bufLen);
            int size=Msize+sizeof(res)+352;
            if(RecvAll(clt_sock,recvBuf,size)==false)exit(0);
            memcpy(M,recvBuf,Msize);
            memcpy(&res,recvBuf+Msize,sizeof(res));
            memcpy(msecrets,recvBuf+Msize+sizeof(res),32);
            memcpy(hcs,recvBuf+Msize+sizeof(res)+32,64);
            memcpy(p_signature,recvBuf+Msize+sizeof(res)+96,128);
            memcpy(&sppre_signature,recvBuf+Msize+sizeof(res)+224,32);
            memcpy(&spcom_signature,recvBuf+Msize+sizeof(res)+256,32);
            printf("res %d\n",res);
            bindscv scv1;
            bindscv scv2;
            int clatest;
            int v;
            uint8_t result[35];
            get_c(global_eid,&clatest);
            get_v(global_eid,&v);
            scv1.c=clatest+1;
            scv2.c=clatest+2;
            scv1.v=v;
            scv2.v=v;
            mystrncpy(scv1.secret,msecrets[0],16);
            mystrncpy(scv2.secret,msecrets[1],16);
            uint8_t hscvpre[32];
            uint8_t hscvcom[32];
            SHA256( (uint8_t *)&scv1,sizeof(bindscv), hscvpre);
            SHA256( (uint8_t *)&scv2, sizeof(bindscv), hscvcom);
            if(mystrncmp(hscvpre,hcs[0],32)==1&&mystrncmp(hscvcom,hcs[1],32)==1)
            {
                printf("update counter\n");
                update_counter(global_eid,msecrets[0],&p_signature[0],(uint8_t*)&hcs[0],result);
                printf("reply2 result %s\n",result);
                update_counter(global_eid,msecrets[1],&p_signature[1],(uint8_t*)&hcs[1],result);
                printf("reply2 result %s\n\n",result);
            }
        }
        //numbytes=0;
    }
	//Destroy the enclave 
    sgx_destroy_enclave(global_eid);
   
    return 0;
}


