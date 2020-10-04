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
#include <iostream>
#include <string>

#define SERVER_PORT 1234
#define BACKLOG 1
#define DeLen 200
#define SoLen 200
#define MaxSize 2000000
int Msize=1;
int SocketFdnMax=3;//初始化连接到sp的si个数
int SocketFd[200];//存储连接客户端si的socket fd 
int SocketFdn=0;//当前连接到sp的si socket个数
int bufLen=MaxSize+400;//发送和接收缓冲区的长度
int reqFlag=0;//客户端请求标志位，为0时代表没请求，为1时开始运行后续操作
int prepFlag=0;//sp端preprocessing标志位，为0时代表未准备好，为1时开始接受request请求
int prepN=0;//prepN代表给各个sa发送加密秘密情况，当给各个sa均发送秘密后，开始request阶段
int replyFlag=0;//replyFlag是reply2阶段开始的标志为，为1时开始reply2阶段
int InitFlag=0;//用于系统初始化标志位，为0时代表未初始化，需要开始初始化
uint32_t res;//sizeof(M),简单代表执行M，这里实现求字节数操作
sgx_ec256_signature_t pre_signature;//为prepare阶段准备的签名sign<h(M),c,v>
sgx_ec256_signature_t com_signature;//为commit2阶段准备的签名sign<h(M||res),c,v>
sgx_ec256_signature_t p_signature[MaxNumM];//preprocessing阶段准备的签名集合sign<hc,c,v>
//save ki encrypto si,c,v,hc --> e
uint8_t ensicvhc[MaxNumSa][MaxNumM][128];//preprocessing阶段准备的由ki加密的集合E<sci,clatest,v，hc>
uint8_t msecrets[2][key_size];//用于整个过程的两个secrets
uint8_t hcs[2][32];//用于整个过程的两个哈希值H<sc,c,v>
uint8_t scisc[MaxNumSa][16];//存储commit1阶段si回复的shares
uint8_t scisr[MaxNumSa][16];//存储reply1阶段si回复的shares
uint8_t hresM[32];//存储哈希结果H<M||res>
sgx_aes_ctr_128bit_key_t p_key[MaxNumS];//存储Init阶段生成的各个si的对称密钥
sgx_ec256_public_t  p_public;//存储sp的公钥
char M[MaxSize]={'\0'};//存储消息M
struct timeval time_start,time_end;//开始结束时间戳
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;//TEE的id
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


/* OCall functions *//* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
  */
void ocall_print_string(const char *str)
{
    
    printf("%s", str);
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
//定义处理client端和被动的副本节点的线程
void *global_Cmsg(void* arg)
{
    int csp_sock=*(int *)arg;//client sock fd
    int numbytes;//recv number of bytes
    char sendBuf[bufLen];
    char recvBuf[bufLen];
    char svBuf[bufLen];
    int times=1000;//循环次数
    while(1)
    {
        //preprocessing已经完成，开始接受client的request请求
        if(prepFlag==1)
        {
            //通知client端preprocessing已好
            memset(sendBuf,'\0',bufLen);
            //memcpy(sendBuf,&ms,sizeof(ms));
            memcpy(sendBuf,"prep ok",sizeof("prep ok"));
            send(csp_sock,sendBuf,15,0);
            //接收客户端request请求
            int i=0;
            //memset(svBuf,'\0',bufLen); 
            //memset(recvBuf,'\0',bufLen); 
            //printf("recv request bufsize%d\n",bufLen);
            //int total=0;
            //char sv[80000];
            memset(recvBuf,'\0',bufLen); 
            int size=15+Msize;
            if(RecvAll(csp_sock,recvBuf,size)==false)exit(0);
            printf("recv request\n");
            
            //for(int j=0;j<Msize;j++)
                //printf("%c",svBuf[j]);
            memcpy(M,recvBuf+15,Msize);
            //printf("M%c",M[Msize-1]);
            //sleep(3);
            uint8_t hm[32];
            //对从客户端接收的request请求进行SHA256哈希运算
            SHA256( (uint8_t *)M, Msize, hm);
            printf("M%c\n",M[Msize-1]);
            //printf("hm\n");
            //printbitsn((uint8_t *)hm,32);
            //sleep(3);
            //sp调用request counter，更新tee中clatest，并对<hm，clatest，v>进行签名
            request_counter(global_eid,hm,&pre_signature);
            //printf("pre_signature\n");
            //printbitsn(&pre_signature,64);
            //reqFlag是prepare阶段的标志位，代表接收到client端的request请求，准备执行后续prepare等操作
            //prepFlag为preprocessing阶段标志位，为0时代表完成preprocessing
            prepFlag=0;
            reqFlag=1;
        }
        //reply2阶段，回复客户端和被动的副本节点
        if(replyFlag==1)
        {
             //验证shares进行xor操作是否匹配secret，返回结果为1则匹配
             int vrf_result;
             verify_shares(global_eid,&vrf_result,(uint8_t*)scisr,sizeof(scisr),1);
            if(vrf_result==1) printf("reply verify all ok\n"); 
            get_secrets(global_eid,(uint8_t *)msecrets,(uint8_t *)hcs,0);//获得两组返回的secrets和H<sc,c,v>
            //printf("2 secrets\n"); 
            //for(int i=0;i<2;i++)
                //printbitsn((uint8_t *)msecrets[i],16);
            //reply2阶段，回复被动的副本节点
            //拷贝发送消息
            memset(sendBuf,'\0',bufLen);
            memcpy(sendBuf,"reply2",sizeof("reply2"));
            
            memcpy(sendBuf+15,M,Msize);
            memcpy(sendBuf+15+Msize,&res,sizeof(res));
            memcpy(sendBuf+15+Msize+sizeof(res),msecrets,32);
            memcpy(sendBuf+15+Msize+sizeof(res)+32,hcs,64);
            memcpy(sendBuf+15+Msize+sizeof(res)+96,p_signature,128);
            memcpy(sendBuf+15+Msize+sizeof(res)+224,&pre_signature,64);
            memcpy(sendBuf+15+Msize+sizeof(res)+288,&com_signature,64);
            printf("send msg %s\n\n","reply2");
            for(int i=SocketFdnMax/2+1;i<SocketFdnMax;i++)
            {
                send(SocketFd[i],sendBuf,15+Msize+sizeof(res)+352,0);    
            }
            //printf("sizeof signature%ld\n",sizeof(pre_signature));
            //reply2阶段，回复客户端
            send(csp_sock,sendBuf,15+Msize+sizeof(res)+352,0);
            times--;//完成一次整体循环操作，times减1
            //sleep(4);
            //prepN是preprocessing阶段的标志位，当为零时开始preprocessing阶段
            //replyFlag为reply2阶段标志位，为0时代表完成reply2
            prepN=0;replyFlag=0;
            
        }
        
        if(times==0)
        {
            gettimeofday(&time_end,NULL);//获得结束时间戳
            printf("millisecond:%ld\n",time_end.tv_sec*1000-time_start.tv_sec*1000+ (time_end.tv_usec-time_start.tv_usec)/1000);  //毫秒
            exit(0);
        }
    }
} 
void *global_Amsg(void* arg)
{
    int sp_sock=*(int *)arg;
    int numbytes;
    char sendBuf[bufLen];
    char recvBuf[bufLen];
    while(1)
    {
        //Init sp public key and ki
        if((SocketFdn==SocketFdnMax)&&(InitFlag==0))
        {
            Init(global_eid,(sgx_aes_ctr_128bit_key_t *)p_key,&p_public,sizeof(sgx_aes_ctr_128bit_key_t)*SocketFdnMax,sizeof(sgx_ec256_public_t));//初始化公钥和ki
            //printf("public key\n");
	        //printbitsn((uint8_t *)&p_public,sizeof(sgx_ec256_public_t));
	        struct ipkey ipk;
            mystrncpy((uint8_t *)&ipk.sp_public,(uint8_t *)&p_public,sizeof(sgx_ec256_public_t));
            //printf("Init app p_key\n");
            for(int i=0;i<SocketFdnMax;i++)
            {
                mystrncpy((uint8_t *)&ipk.i_key,(uint8_t *)&p_key[i],sizeof(sgx_aes_ctr_128bit_key_t));
                //拷贝发送消息
                memset(sendBuf,'\0',bufLen);
                memcpy(sendBuf,"key",sizeof("key"));
                memcpy(sendBuf+15,&ipk,sizeof(ipk));
                send(SocketFd[i],sendBuf,15+sizeof(ipk),0);
            }
            gettimeofday(&time_start,NULL);
            InitFlag=1;
            
        }
        //preprocessing create m secret and signature bind s,c,v
        else if((SocketFdn==SocketFdnMax)&&(prepN<(SocketFdnMax/2+1)))
        {
             preprocessing(global_eid,(sgx_ec256_signature_t *)p_signature,(uint8_t *)ensicvhc,128,sizeof(uint8_t)*128*MaxNumM*(SocketFdnMax/2+1));
            //printf("\n");  
            printf("preprocessing send message\n");
             for(int i=0;i<(SocketFdnMax/2+1);i++)
            {
              
                //拷贝发送消息
                memset(sendBuf,'\0',bufLen);
                memcpy(sendBuf,"preprocessing",sizeof("preprocessing"));
                memcpy(sendBuf+15,&ensicvhc[i],MaxNumM*128);
                send(SocketFd[i],sendBuf,15+MaxNumM*128,0);
                prepN++;
            }
            if(prepN==(SocketFdnMax/2+1))prepFlag=1;
        }
        //prepare--reply1 phase
        if(reqFlag==1)
        {
            
            //printbitsn((uint8_t*)&pre_signature,64);
            //send prepare 
            printf("send prepare\n");
            for(int i=0;i<(SocketFdnMax/2+1);i++)
            {
                    //拷贝发送消息
                memset(sendBuf,'\0',bufLen);
                memcpy(sendBuf,"prepare",sizeof("prepare"));
                memcpy(sendBuf+15,M,Msize);
                memcpy(sendBuf+15+Msize,&pre_signature,64);
                send(SocketFd[i],sendBuf,15+Msize+64,0);
                //usleep(10);
            }  
            printf("recv commit1\n");
            //recv commit1
            for(int i=0;i<(SocketFdnMax/2+1);i++)
            {
                memset(recvBuf,'\0',bufLen);
                if ((numbytes=recv(SocketFd[i],recvBuf,bufLen,0)) == -1)
                { 
                    printf("recv"); 
                    break;
                }
                if(numbytes <= 0)
                {
                    printf("recv000\n");
                    exit(0);
                }
                memcpy(&scisc[i],recvBuf,16);
                //printbitsn((uint8_t*)&scisc[i],16);
            }
            int vrf_result;
            verify_shares(global_eid,&vrf_result,(uint8_t*)scisc,sizeof(scisc),0);
			//commit2
            if(vrf_result==1) 
            {
                printf("commit verify all ok\n");
                res=Msize;
                printf("res %d\n",res);
                struct resM resM1;
                memset(&resM1,'\0',sizeof(resM1));
                resM1.res=res;
                memcpy(&resM1.M,M,Msize);
                //对从客户端接收的request请求进行SHA256哈希运算
                SHA256( (uint8_t *)&resM1, sizeof(res)+Msize, hresM);
                //printf("resM1 bit\n");
                //printbitsn((uint8_t *)&hresM,32);
                //printf("M%s\n",M);
                //sp调用request counter，更新tee中clatest，并对<hm，clatest，v>进行签名
                request_counter(global_eid,hresM,&com_signature);
                //printf("com_signature bit\n");
                //printbitsn((uint8_t *)&com_signature,64);
                //send commit2
                //拷贝发送消息
                memset(sendBuf,'\0',bufLen);
                memcpy(sendBuf,"commit2",sizeof("commit2"));
                memcpy(sendBuf+15,&res,sizeof(res));
                memcpy(sendBuf+15+sizeof(res),&com_signature,64);
                printf("send commit2\n");
            }
            else
            {
                printf("commit verify fault\n");
                go_back(global_eid);
                reqFlag=0;
                prepN=0;
                continue;
            }
            for(int i=0;i<(SocketFdnMax/2+1);i++)
            {
                send(SocketFd[i],sendBuf,15+sizeof(res)+64,0);
            } 
            printf("recv reply1\n");
            //recv reply1
            for(int i=0;i<(SocketFdnMax/2+1);i++)
            {
                memset(recvBuf,'\0',bufLen);
                if ((numbytes=recv(SocketFd[i],recvBuf,bufLen,0)) == -1)
                { 
                    printf("recv"); 
                    break;
                }
                if(numbytes <= 0)
                {
                    printf("recv000\n");
                    exit(0);
                }  
                memcpy(&scisr[i],recvBuf,16);  
            }
            replyFlag=1; 
            reqFlag=0;     
        }
    }
}

/* Application entry */  
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
	if(argc<3){
		printf("please input two ./sp SOcketFdnMax Msize\n");
		exit(0);
	}
	SocketFdnMax=atoi(argv[1]);
	Msize=atoi(argv[2]);
/*
    printf("本次实验Msize\n");
    scanf("%d",&Msize);
    printf("本次实验si个数\n");
    scanf("%d",&SocketFdnMax);
*/
    int sp_sock;
    int clt_sock;
    int si_sock;
    int csp_sock;
    
    struct sockaddr_in sp_addr;
    struct sockaddr_in si_addr;
    pthread_t threadCmsg;
    
    //Initialize the enclave 
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        exit(0); 
    }
    //创建套接字
    csp_sock = socket(AF_INET, SOCK_STREAM, 0);
/*
    int recvbuff = 2*1024*1024;
    if(setsockopt(csp_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&recvbuff, sizeof(int)) == -1)
	printf("setsocket error\n");
else
	printf("setsocket success\n");
	
	int sendbuff = 2*1024*1024;
	if(setsockopt(csp_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sendbuff, sizeof(int)) == -1)
	printf("setsocket error\n");
else
	printf("setsocket success\n");
*/
    //向服务器（特定的IP和端口）发起请求
    struct sockaddr_in clt_addr;
    memset(&clt_addr, 0, sizeof(clt_addr));  //每个字节都用0填充
    clt_addr.sin_family = AF_INET;  //使用IPv4地址
    clt_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    clt_addr.sin_port = htons(1111);  //端口
    if(connect(csp_sock, (struct sockaddr*)&clt_addr, sizeof(clt_addr))<0)
    {
        perror("connect error");
        return 1;
    }
    pthread_create(&threadCmsg,NULL,global_Cmsg,(void *)&csp_sock);
    int addr_len=sizeof(si_addr);
    pthread_t threadAmsg,threadPmsg;
    //创建套接字
    sp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    //创建sock套接字失败处理
    if(sp_sock<0)
    {
        perror("socket create error.");
        return 1;
    }
    //将套接字和IP、端口绑定
    memset(&sp_addr, 0, sizeof(sp_addr));  //每个字节都用0填充
    //bzero(&server_addr,sizeof(serv_addr));
    sp_addr.sin_family = AF_INET;  //使用IPv4地址
    sp_addr.sin_addr.s_addr = htonl(INADDR_ANY);  //inet_addr("192.168.199.207");具体的IP地址
    //serv_addr.sin_addr.s_addr =htonl(INADDR_ANY);
    sp_addr.sin_port = htons(1234);  //端口
    if(bind(sp_sock, (struct sockaddr*)&sp_addr, sizeof(sp_addr))<0)
    {
        perror("socket bind error.");
        return 1;
    }
    //进入监听状态，等待用户发起请求
    if(listen(sp_sock, 200)<0)
    {
        perror("listen error");
        return 1;
    }
    pthread_create(&threadAmsg,NULL,global_Amsg,(void *)&sp_sock);
    
     while(1)
	{
        printf("Listening on port:%d\n",1234);
        si_sock = accept(sp_sock, (struct sockaddr*)&si_addr,(socklen_t*)&addr_len);
        if(si_sock < 0)
        {
         perror("accept client sock connect error");
         continue;
        }
        //int para=clt_sock;
        printf("You got a connection from %s\n",inet_ntoa(si_addr.sin_addr));
        
		SocketFd[SocketFdn]=si_sock;
		SocketFdn++;
	} 
	
	//Destroy the enclave 
    sgx_destroy_enclave(global_eid);
	return 0;

}

