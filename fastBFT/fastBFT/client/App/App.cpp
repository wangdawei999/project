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
uint32_t res;
int bufLen=MaxSize+400;
typedef struct message{
    char type[15];
    char content[20];
}MS;
char M[MaxSize]={'\0'};
  
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
void *global_Cmsg(void* arg)
{
    int sp_sock=*(int *)arg;
    
    MS ms;
    char sendBuf[bufLen];
    char recvBuf[bufLen];
    int numbytes;
    memset(M,'x',Msize);
    //memcpy(&M[Msize-1],".",1);
    while(1)
    {   
        memset(recvBuf,'\0',bufLen);
        if ((numbytes=recv(sp_sock,recvBuf,15,0)) == -1)
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
		
        if(strcmp(type,"prep ok")==0)
        {
            printf("recv msg %s \n",type); 
            memset(sendBuf,'\0',bufLen);
            memcpy(sendBuf,"request",sizeof("request"));
            memcpy(sendBuf+15,M,Msize);
            int n=send(sp_sock,sendBuf,15+Msize,0);
            printf("send %d\n",n);
            printf("send msg %s\t%c\n","request",M[Msize-1]);
         }
         else if(strcmp(type,"reply2")==0)
         {
            printf("recv msg %s \n",type); 
            memset(recvBuf,'\0',bufLen);
            int size=Msize+sizeof(res)+352;
            if(RecvAll(sp_sock,recvBuf,size)==false)exit(0);
            memcpy(&res,recvBuf+Msize,sizeof(res));
            printf("res %d\n\n",res);
         }
         numbytes=0;
     }
}  
/* Application entry */  
int main(int argc,char*argv[]){
    //创建套接字
    int clt_sock;
    int sp_sock;
	if(argc<2){
		printf("please input three ./client Msize\n");
		exit(0);
	}
	Msize=atoi(argv[1]);
    //printf("please input Msize\n");
   // scanf("%d",&Msize);
    //向服务器（特定的IP和端口）发起请求
    struct sockaddr_in clt_addr;
    struct sockaddr_in sp_addr;
    int addr_len=sizeof(sp_addr);
    
    pthread_t threadCmsg;
    //创建套接字
    clt_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
     //创建sock套接字失败处理
    if(clt_sock<0)
    {
        perror("socket create error.");
        return 1;
    }
/*
    int recvbuff = 2*1024*1024;
    if(setsockopt(clt_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&recvbuff, sizeof(int)) == -1)
	printf("setsocket error\n");
else
	printf("setsocket success\n");
*/
    memset(&clt_addr, 0, sizeof(clt_addr));  //每个字节都用0填充
    clt_addr.sin_family = AF_INET;  //使用IPv4地址
    clt_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    clt_addr.sin_port = htons(1111);  //端口
    if(bind(clt_sock, (struct sockaddr*)&clt_addr, sizeof(clt_addr))<0)
    {
        perror("socket bind error.");
        return 1;
    }
    //进入监听状态，等待用户发起connect请求
    if(listen(clt_sock, 20)<0)
    {
        perror("listen error");
        return 1;
    }
    while(1)
    {
        printf("Listening on port:%d\n",1111);
        sp_sock = accept(clt_sock, (struct sockaddr*)&sp_addr,(socklen_t*)&addr_len);
        if(sp_sock < 0)
        {
             perror("accept client sock connect error");
             return 1;
        }
        pthread_create(&threadCmsg,NULL,global_Cmsg,(void *)&sp_sock);
        
    }
    return 0;
}
