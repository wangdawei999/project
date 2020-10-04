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

#define SERVER_PORT 1234
#define SSERVER_PORT 2222
#define BACKLOG 1
#define DeLen 200
#define SoLen 200

long t=0;
int pms=0;
int msRn=0;
int mTLsn=0;
int gCTrustn=0;
int msRLn=0;
int srflag=0;
 //接收发送数组的大小  
int tmsgLen=13000;
int sclient,sclientSocket;
struct msgRtLt scmsR[90];
int numsclient;
struct gCarTrust sgCTrust[20];
int sgCTrustn;
int scflag=0;
int paixuchoice=0;
pthread_mutex_t mutms,mutmsR,mutmsRf,mutSFF,mutSFFR,mutSC,mutSFn,mutfp;
pthread_cond_t cond;
pthread_cond_t condsc;
pthread_cond_t condms;
int SocketFd[150],SocketFdnF=0,SocketFdnFR=0,SocketFdn=0;
struct timeval time_RSU1,time_RSU2;


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions *//* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
  */
void ocall_print_string(const char *str)
{
    
    printf("%s", str);
} 
 //处理客户端   
void *start_routine( void *ptr) 
{
    struct ptdParm *para=(struct ptdParm*)ptr;
    //int fd = *(int *)ptr;
    struct msgRtLt *msR=para->msR;
    struct msgRtLt *msRf=para->msRf;
    struct messageS *ms=para->ms;
    int fd = para->client;
    char buf[tmsgLen];
    char sendbuf[tmsgLen];
    struct message m;
    struct messageS mst;
    struct msgRtLt msRC[para->mSSize];
    struct timeval time_startst,time_endst,time_TPS ;
    char name[30];
    memset(name,'\0',sizeof(name)); 
    FILE *fp;
    printf("this is a new thread,you got connected\n");
     gettimeofday(&time_TPS,NULL);
     sprintf(name,"TPS%dm%dC%dmT.txt",para->mSSize,para->maxClient,para->maxTrust); 
    fp=fopen(name,"a+");
    if(fp==NULL)
    {
    printf("File cannot open! ");
    exit(0);
    }
    fprintf(fp,"start%ld\t",time_TPS.tv_sec);
    fclose(fp);
    while(1)
    {
         //获取开始接收消息时间戳
        gettimeofday(&time_startst,NULL);
        memset(buf,'\0',tmsgLen);
        memset(sendbuf,'\0',tmsgLen);
        memset(&m,'\0',sizeof(m));
        memset(&mst,'\0',sizeof(mst));
        int cflag=0;
        int numbytes;
        //gettimeofday(&time_RSU2,NULL);
        if ((numbytes=recv(fd,buf,tmsgLen,0)) == -1){ 
        printf("recv"); 
         break;
        }  
        //printf("bianhua%d",a);
        if(numbytes < 0)
        {
        perror("recv");
        break;
        }

       if(strcmp(buf,"quit")==0){        
            SocketFdn=SocketFdn-1;
            if(SocketFdnF>SocketFdn&&msRn==para->mSSize*SocketFdn&&SocketFdn!=0)srflag=1; 
            break;
        }
        printf("fd=%d\n",fd);
        /*time */
        
        //printf("%s,",DeStr);
        //printf("%s",buf);
        memcpy(&m,buf,sizeof(m));
        mst.m=m;
        mst.ti=t;
        //printf("receive:%ld\t%s\n\n",m.No,m.content);
         //公有数组，存储原始消息
        pthread_mutex_lock(&mutms);
        if(pms>=para->mSSize)cflag=0;
        else if(pms<=(para->mSSize-1)){
            
            //if(pms>=para->mSSize)
               // pthread_cond_wait(&condms,&mutms);
            ms[pms++]=mst;
            //printf("message%s",ms[pms-1].m.content);
            cflag=1;
        }
        pthread_mutex_unlock(&mutms);
        //开始发送客户端评估消息
         if(pms>=para->mSSize)
        {
           //将待评价messages发给客户端 
            memset(sendbuf,'\0',tmsgLen);
            memcpy(sendbuf,ms,sizeof(struct messageS)*para->mSSize);
            //printf("size%s",sendbuf);
            send(fd,sendbuf,sizeof(struct messageS)*para->mSSize,0);
           
            //将评价消息先放到客户端数组中，然后将每个客户端收到的评价放到一个集合中
             //printf("size%ld",sizeof(struct messageS)*para->mSSize);
            memset(buf,'\0',tmsgLen);
            //接收每个客户端返回的评价集合
            recv(fd,buf,sizeof(msRC),0);
            //printf("sizeof(msRC)%ld",sizeof(msRC));
            
            memset(msRC,'\0',sizeof(msRC));
            memcpy(msRC,buf,sizeof(msRC));
           
            pthread_mutex_lock(&mutmsR);
            for(int i=0;i<para->mSSize;i++){
                msR[msRn++]=msRC[i]; 
            }
            SocketFdnF=SocketFdn;
            if(msRn==para->mSSize*SocketFdn){
                srflag=1;
                pthread_cond_wait(&cond,&mutmsR);
                
             }
             else pthread_cond_wait(&cond,&mutmsR);
        
            pthread_mutex_unlock(&mutmsR);
            
            pthread_mutex_lock(&mutms);  
            if(cflag==0){                            
                ms[pms++]=mst;                           
            }
            pthread_mutex_unlock(&mutms);  
            //printf("zaime%d",msRn);
        }
        
        memset(sendbuf,'\0',tmsgLen);
        memcpy(sendbuf,&m,sizeof(m));
        send(fd,sendbuf,sizeof(m),0);
        printf("send:%ld\t%s\n\n",m.No,m.content);
        //获取返回消息时间戳
        gettimeofday(&time_endst,NULL);
        int timeuse=1000000*(time_endst.tv_sec-time_startst.tv_sec)+time_endst.tv_usec-time_startst.tv_usec;
        memset(name,'\0',sizeof(name));   
        sprintf(name,"Teest%dm%dC%dmT.txt",para->mSSize,para->maxClient,para->maxTrust); 
        pthread_mutex_lock(&mutfp);
        fp=fopen(name,"a+");
        if(fp==NULL)
        {
        printf("File cannot open! ");
        exit(0);
        }
        fprintf(fp,"%d\t",timeuse);
        fclose(fp); 
        pthread_mutex_unlock(&mutfp);
        printf("MGRCtime:%d us.\n",timeuse);
        
       // memset(DeStr,'\0',sizeof(DeStr));
    }
    gettimeofday(&time_TPS,NULL);
    memset(name,'\0',sizeof(name));  
    sprintf(name,"TPS%dm%dC%dmT.txt",para->mSSize,para->maxClient,para->maxTrust); 
    fp=fopen(name,"a+");
    if(fp==NULL)
    {
    printf("File cannot open! ");
    exit(0);
    }
    fprintf(fp,"end%ld\t",time_TPS.tv_sec);
    fclose(fp);
    pthread_mutex_lock(&mutSFn);
    for(int i=0;i<SocketFdn+1;i++)
    {   
        if(SocketFd[i]==fd)
        {
            int k=i;
            if(k<SocketFdn+1)
            for(k;k<SocketFdn+1;k++)
                SocketFd[k]=SocketFd[k+1];
            
        }
    }
    pthread_mutex_unlock(&mutSFn);
    close(fd);
}
//rating排序
void paixu(void* arg)
{
    struct ptdParm *para=(struct ptdParm*)arg;
    struct msgRtLt *msR=para->msR;
    struct msgRtLt *msRf=para->msRf;
    char sendbuf[13000];
    struct gCarTrust *gCTrust=para->gCTrust;//全局信任值
    //pthread_mutex_lock(&mutSFFR);
    if(paixuchoice==1){
        memset(msRf,'\0',sizeof(struct msgRtLt)*para->mSSize*para->maxClient);
        /*Sort every messge rating list and group rating values by
    each message.*/
        int n=0;
        printf("kaishipaixule!");
         //pthread_mutex_lock(&mutmsR);
         
        for(int i=0;i<para->mSSize;i++)
        {
            for(int k=0;k<SocketFdn;k++)
            {msRf[n++]=msR[i+k*para->mSSize];}
        }
        memset(sendbuf,'\0',13000);
        memcpy(sendbuf,gCTrust,sizeof(struct gCarTrust)*para->maxClient*2);
        memcpy(sendbuf+sizeof(struct gCarTrust)*para->maxClient*2,msR,sizeof(struct msgRtLt)*para->mSSize*para->maxClient);
        send(sclientSocket,sendbuf,sizeof(struct gCarTrust)*para->maxClient*2+sizeof(struct msgRtLt)*para->mSSize*para->maxClient,0);
        
    }
    else if(paixuchoice==2){
        memset(msRf,'\0',sizeof(struct msgRtLt)*para->mSSize*para->maxClient);
        /*Sort every messge rating list and group rating values by
    each message.*/
        int n=0;
        printf("kaishi server rating paixule!");
        for(int i=0;i<para->mSSize;i++)
        {
            for(int k=0;k<numsclient;k++)
            {msRf[n++]=scmsR[i+k*para->mSSize];
            //printf("msRf[n++].rating%f\n",msRf[n++].rating);
            }
        }
    }
}
//处理服务器发来的消息
void *server_Rmsg(void* arg)
{
    struct ptdParm *para=(struct ptdParm*)arg;
    struct gCarTrust *gCTrust=para->gCTrust;//全局信任值
    char buf[13000];
    while(1)
    {
        pthread_mutex_lock(&mutSC);
        
        
        memset(buf,'\0',13000);
        //gettimeofday(&time_RSU2,NULL);
        
        int numbytes;
        if ((numbytes=recv(sclient,buf,13000,0)) == -1){ 
        printf("recv"); 
         break;
        } 
        
        if(numbytes <=0)
        {
        perror("recv");
        break;
        }
        //printf("sgCTrust numbytes%d\n",numbytes);
        memset(sgCTrust,'\0',sizeof(sgCTrust));
        memcpy(sgCTrust,buf,sizeof(struct gCarTrust)*para->maxClient*2);
        
        int k=0;
        char CarID[20];
        memset(CarID,'\0',sizeof(CarID));
        for(k=0;k<para->maxClient*2;k++){
            int i=0;
            for(;i<gCTrustn;i++){
               if(strcmp(gCTrust[i].CarID,sgCTrust[k].CarID)==0) break;
            }
            if((i>=gCTrustn)&&sgCTrust[k].Trust!=0&&strcmp(sgCTrust[k].CarID,CarID)!=0){
               strcpy(gCTrust[gCTrustn].CarID,sgCTrust[k].CarID);
               gCTrust[gCTrustn++].Trust=(float)0.500000;
            }
        }
       
        numsclient=0;
        memset(scmsR,'\0',sizeof(scmsR));
        memcpy(scmsR,buf+sizeof(struct gCarTrust)*para->maxClient*2,sizeof(struct msgRtLt)*para->mSSize*para->maxClient);
        
        
        for( k=0;k<para->mSSize*para->maxClient;k++)
            {
                if(scmsR[k].rating!=0.000000){
                    numsclient=numsclient+1;
                }
                //printf("numsclient%dsgCTrustn%f\n",numsclient,scmsR[k].rating);
            }
        numsclient=numsclient/para->mSSize;
        //printf("numsclient%d\n",numsclient);
        //printf("gCTrustn%d\n",gCTrustn);
        scflag=1;
        pthread_cond_wait(&condsc,&mutSC);
        pthread_mutex_unlock(&mutSC);
        
    }
       
}
void *global_Rmsg(void* arg)
{
    struct timeval time_startr,time_endr,time_startt,time_endt;//时间戳
    struct ptdParm *para=(struct ptdParm*)arg;//指向主函数中传递的结构体
    struct mTrsLt mTLst[para->mSSize];//单组消息的ratings trust
    memset(mTLst,'\0',sizeof(mTLst));
    struct mTrsLt mTLs[para->maxTrust],mTLsp[para->maxTrust];//多组消息的ratings trust,排序结果列表
    memset(mTLs,'\0',sizeof(mTLs));
    memset(mTLs,'\0',sizeof(mTLsp));
    //存储多组最初的评价消息集合
    struct msgRtLt msRL[para->maxTrust*para->maxClient];
    memset(msRL,'\0',sizeof(msRL));
    struct mTrsLt *p=mTLst;
    struct msgRtLt *msR=para->msR;//排序前单组消息的ratings
    struct msgRtLt *msRf=para->msRf;//排序后单组消息的ratings
    struct msgRtLt *q=para->msRf;
    struct messageS *ms=para->ms;
    struct gCarTrust *gCTrust=para->gCTrust;//全局信任值
    char name[30];
    char CarID[20];
    memset(CarID,'\0',sizeof(CarID));
    FILE *fp;
    while(1)
    {
        //pthread_mutex_lock(&mutmsR);
        //if((msRn>=para->mSSize*SocketFdn)&&(SocketFdn!=0))
        if(srflag==1)
        {
            //排序
            memset(mTLst,'\0',sizeof(mTLst));
           //msgRtLtvi;k;t存储在msR中,Ej;i;k;ts存储在msRf中
            printf("jinrupaixu\n");
            paixuchoice=1;
            paixu((void *)para);
            printf("paixuwanbi\n");
            printf("gCTrustn%d\n",gCTrustn);
            for(int i=0;i<para->mSSize*para->maxClient;i++){
                if(strcmp(msRf[i].RCarID,CarID)!=0){
                msRL[msRLn++]=q[i];
                } 
            }
            //TeeCalGRA(global_eid,ratingsT,ratings,SocketFdn);
            //puts("jinruTEE");
            
            /*Calculate the global rating value of each message based on as set of associated rating values.*/
            //在TEE中进行贝叶斯推断算出ratings trust
            gettimeofday(&time_startr,NULL);
            TeeCalGRAT(global_eid,mTLst, msRf,gCTrust,sizeof(struct mTrsLt)*para->mSSize,sizeof(struct msgRtLt)*para->mSSize*para->maxClient,sizeof(struct gCarTrust)*gCTrustn,SocketFdn);
            gettimeofday(&time_endr,NULL); 
             //计算delay,存储delay到对应文件中 
            int timeuse=1000000*(time_endr.tv_sec-time_startr.tv_sec)+time_endr.tv_usec-time_startr.tv_usec;
            memset(name,'\0',sizeof(name));
            sprintf(name,"TeeMGRC%dm%dC%dmT.txt",para->mSSize,para->maxClient,para->maxTrust); 
            fp=fopen(name,"a+");
            if(fp==NULL)
            {
            printf("File cannot open! ");
            exit(0);
            }
            fprintf(fp,"%d\t",timeuse);
            fclose(fp); 
            printf("time:%d 微秒.\n",timeuse);
            
            
            for(int i=0;i<para->mSSize;i++){
            mTLs[mTLsn++]=mTLst[i];
            //printf("trust%f\n",p[i].ratingT);
            }
            printf("mTLsn++%d\n",mTLsn);
            if(mTLsn>=para->maxTrust)
            {
                //gongshi
                //qingchu 
                for(int i=0;i<gCTrustn;i++)
                    printf("trust %f\n",gCTrust[i].Trust);
                printf("jinru TEE ,jisuan global trust.\n");
                gettimeofday(&time_startt,NULL);
                TeeCalSEG(global_eid,mTLs,msRL,gCTrust,sizeof(struct mTrsLt)*para->maxTrust,sizeof(struct msgRtLt)*para->maxTrust*para->maxClient,sizeof(struct gCarTrust)*gCTrustn,mTLsn,msRLn,gCTrustn);
                gettimeofday(&time_endt,NULL);
                
                int timeuse=1000000*(time_endt.tv_sec-time_startt.tv_sec)+time_endt.tv_usec-time_startt.tv_usec;
                memset(name,'\0',sizeof(name));
                sprintf(name,"TeeNTE%dm%dC%dmT.txt",para->mSSize,para->maxClient,para->maxTrust); 
                fp=fopen(name,"a+");
                if(fp==NULL)
                {
                printf("File cannot open! ");
                exit(0);
                }
                fprintf(fp,"%d\t",timeuse);
                fclose(fp); 
                printf("time:%d 微秒.\n",timeuse);
                
                memset(mTLs,'\0',sizeof(struct mTrsLt)*para->maxTrust);
                memset(msRL,'\0',sizeof(struct msgRtLt)*para->maxTrust*para->maxClient);
				t++;
                mTLsn=0;
                
                msRLn=0;

            }
            pthread_mutex_lock(&mutmsR);
            srflag=0;
            pms=0;
            memset(ms,'\0',sizeof(struct messageS)*para->mSSize);
            msRn=0;
            memset(msR,'\0',sizeof(struct msgRtLt)*para->mSSize*para->maxClient);
            //SocketFdnFR=SocketFdn;
            pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mutmsR);
         }
         //pthread_mutex_unlock(&mutmsR);
         if(scflag==1)
        {
            //排序
            memset(mTLst,'\0',sizeof(mTLst));
           //msgRtLtvi;k;t存储在msR中,Ej;i;k;ts存储在msRf中
            printf("jinrupaixu\n");
            paixuchoice=2;
            paixu((void *)para);
            printf("paixuwanbi\n");
            printf("gCTrustn%d\n",gCTrustn);
            for(int i=0;i<para->mSSize*para->maxClient;i++){
                if(strcmp(msRf[i].RCarID,CarID)!=0){
                msRL[msRLn++]=q[i];
                } 
            }
            //TeeCalGRA(global_eid,ratingsT,ratings,SocketFdn);
            /*Calculate the global rating value of each message based on as set of associated rating values.*/
            //在TEE中进行贝叶斯推断算出ratings trust
            
            gettimeofday(&time_startr,NULL);
            TeeCalGRAT(global_eid,mTLst, msRf,gCTrust,sizeof(struct mTrsLt)*para->mSSize,sizeof(struct msgRtLt)*para->mSSize*para->maxClient,sizeof(struct gCarTrust)*gCTrustn,numsclient);
            gettimeofday(&time_endr,NULL); 
             //计算delay,存储delay到对应文件中 
            int timeuse=1000000*(time_endr.tv_sec-time_startr.tv_sec)+time_endr.tv_usec-time_startr.tv_usec;
            memset(name,'\0',sizeof(name));
            sprintf(name,"TeeMGRC%dm%dC%dmT.txt",para->mSSize,para->maxClient,para->maxTrust); 
            fp=fopen(name,"a+");
            if(fp==NULL)
            {
            printf("File cannot open! ");
            exit(0);
            }
            fprintf(fp,"%d\t",timeuse);
            fclose(fp); 
            printf("time:%d 微秒.\n",timeuse);
            
            
            for(int i=0;i<para->mSSize;i++){
            mTLs[mTLsn++]=mTLst[i];
            //printf("trust%f\n",p[i].ratingT);
            }
            printf("mTLsn++%d\n",mTLsn);
            if(mTLsn>=para->maxTrust)
            {
                //gongshi
                //qingchu 
                for(int i=0;i<gCTrustn;i++)
                    printf("trust %f\n",gCTrust[i].Trust);
                printf("jinru TEE ,jisuan global trust.\n");
                gettimeofday(&time_startt,NULL);
                TeeCalSEG(global_eid,mTLs,msRL,gCTrust,sizeof(struct mTrsLt)*para->maxTrust,sizeof(struct msgRtLt)*msRLn,sizeof(struct gCarTrust)*gCTrustn,mTLsn,msRLn,gCTrustn);
                gettimeofday(&time_endt,NULL);
                
                int timeuse=1000000*(time_endt.tv_sec-time_startt.tv_sec)+time_endt.tv_usec-time_startt.tv_usec;
                memset(name,'\0',sizeof(name));
                sprintf(name,"TeeNTE%dm%dC%dmT.txt",para->mSSize,para->maxClient,para->maxTrust); 
                fp=fopen(name,"a+");
                if(fp==NULL)
                {
                printf("File cannot open! ");
                exit(0);
                }
                fprintf(fp,"%d\t",timeuse);
                fclose(fp); 
                printf("time:%d 微秒.\n",timeuse);
                
                memset(mTLs,'\0',sizeof(struct mTrsLt)*para->maxTrust);
                memset(msRL,'\0',sizeof(struct msgRtLt)*para->maxTrust*para->maxClient);
				t++;
                mTLsn=0;
                
                msRLn=0;

            }
            pthread_mutex_lock(&mutSC);
            scflag=0;
            memset(scmsR,'\0',sizeof(scmsR));
            // pthread_mutex_unlock(&mutSFFR);
            //msRn=0;SocketFdnFR=SocketFdn;
            pthread_cond_signal(&condsc);
            pthread_mutex_unlock(&mutSC);
         }
    }
} 
/* Application entry */  
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    
    int mSSize=10;
    //puts("请输入一次要评估的最大消息数量:");
    //scanf("%d",&mSSize);
    int maxClient;
    puts("请输入最大处理客户端的数量:");
    scanf("%d",&maxClient);
    int maxTrust;
    //puts("请输入最大收集多少个rating trusts，然后计算global trust值:");
    //scanf("%d",&maxTrust);
    maxTrust=mSSize;
    printf("mTrsLtsize%ld\n",sizeof(struct mTrsLt)*maxTrust*maxClient);
    printf("msgRtLtsize%ld\n",sizeof(struct msgRtLt)*mSSize);
    //收集固定数量的消息，然后发给client评估
	struct messageS ms[mSSize];
	memset(ms,'\0',sizeof(ms));
	//收集接收client返回的评估消息，存储排序完毕后的评估消息
	struct msgRtLt msR[mSSize*maxClient],msRf[mSSize*maxClient];
	memset(msR,'\0',sizeof(msR));
	memset(msRf,'\0',sizeof(msRf));
	//全局车辆信任值
	struct gCarTrust gCTrust[maxClient*2];
	memset(gCTrust,'\0',sizeof(gCTrust));
	struct ptdParm para;
	memset(&para,'\0',sizeof(para));
	para.mSSize=mSSize;
	para.maxClient=maxClient;
	para.maxTrust=maxTrust;
	para.ms=ms;
	para.msR=msR;
	para.msRf=msRf;
	para.gCTrust=gCTrust;
	
    int serverSocket,sserverSocket;
    struct sockaddr_in server_addr;
    struct sockaddr_in clientAddr;
    struct sockaddr_in sserver_addr;
    struct sockaddr_in sclientAddr;
    int addr_len=sizeof(clientAddr);
    int saddr_len=sizeof(sclientAddr);
    int client;
    char CarID[20];//保存点分十进制的ip地址
    memset(&ms,'\0',sizeof(ms));
    
	struct sockaddr_in scserverAddr,scclientAddr;//服务器端地址,客户端地址
	int scclientAddrLen=sizeof(scclientAddr);
    pthread_t threadC,threadGRmsg,threadSmsg;
    //线程互斥锁线程锁初始化
    pthread_mutex_init(&mutms,NULL);//公有数组，保证存储原始消息的同步
    pthread_mutex_init(&mutmsR,NULL);//保证存储ratings消息的数组同步
    pthread_mutex_init(&mutmsRf,NULL);//保证存储ratings排序消息的数组同步
    //pthread_mutex_init(&mutSF,NULL);
    pthread_mutex_init(&mutSFF,NULL);//记录是否已发送给每个客户端待评价消息
    pthread_mutex_init(&mutSFFR,NULL);//记录是否已接收每个客户端返回的评价消息
    pthread_mutex_init(&mutSFn,NULL);//记录连接客户端个数同步
    pthread_mutex_init(&mutSC,NULL);//记录连接客户端个数同步
    pthread_mutex_init(&mutfp,NULL);//文件同步
    pthread_cond_init(&cond,NULL);
    pthread_cond_init(&condsc,NULL);
    pthread_cond_init(&condms,NULL);
    gettimeofday(&time_RSU1,NULL);
    gettimeofday(&time_RSU2,NULL);
    //Initialize the enclave 
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        exit(0); 
    }
    //创建用于global message rating处理的线程
    pthread_create(&threadGRmsg,NULL,global_Rmsg,(void *)&para);
    
    //建立监听server连接套接字
    if((sserverSocket = socket(AF_INET, SOCK_STREAM, 0)) <0)
	{
		perror("socket");
		return 1;
	}
	
	bzero(&sserver_addr,sizeof(sserver_addr));
	sserver_addr.sin_family = AF_INET;
	sserver_addr.sin_port = htons(SSERVER_PORT);
	sserver_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	if(bind(sserverSocket,(struct sockaddr *)&sserver_addr,sizeof(sserver_addr)) < 0)
	{
		perror("connect");
		return 1;
	}

	if(listen(sserverSocket,5) < 0)
	{
		perror("listen");
		return 1;
	}
	sclient = accept(sserverSocket, (struct sockaddr*)&sclientAddr,(socklen_t*)&saddr_len);
	char servIP[20]="192.168.1.101";
    //puts("请输入要连接RSU的IP地址:");
    //scanf("%s",servIP);
	 //建立用于连接server套接字
    if((sclientSocket = socket(AF_INET,SOCK_STREAM,0)) < 0)
	{
		perror("socket");
		return 1;
	}
    bzero(&scserverAddr,sizeof(scserverAddr));
	scserverAddr.sin_family = AF_INET;
	scserverAddr.sin_port = htons(SSERVER_PORT);
	scserverAddr.sin_addr.s_addr = inet_addr(servIP);
	if(connect(sclientSocket,(struct sockaddr*)&scserverAddr,sizeof(scserverAddr)) < 0)
	{
		perror("connect");
		return 1;
	}
	pthread_create(&threadSmsg,NULL,server_Rmsg,(void *)&para);
	//用于连接client套接字
	if((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) <0)
	{
		perror("socket");
		return 1;
	}
	
	bzero(&server_addr,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	if(bind(serverSocket,(struct sockaddr *)&server_addr,sizeof(server_addr)) < 0)
	{
		perror("connect");
		return 1;
	}

	if(listen(serverSocket,5) < 0)
	{
		perror("listen");
		return 1;
	}
        while(1)
	{
        printf("Listening on port:%d\n",SERVER_PORT);
        client = accept(serverSocket, (struct sockaddr*)&clientAddr,(socklen_t*)&addr_len);
        if(client < 0)
        {
         perror("accept");
         continue;
        }
        para.client=client;
        printf("You got a connection from %s\n",inet_ntoa(clientAddr.sin_addr));
        //创建线程处理客户端
        pthread_create(&threadC,NULL,start_routine,(void *)&para);
        memset(CarID,'\0',sizeof(CarID));
        inet_ntop(AF_INET,&clientAddr.sin_addr.s_addr,CarID,sizeof(CarID));		
		pthread_mutex_lock(&mutSFn);
		SocketFd[SocketFdn++]=client;
		
        pthread_mutex_unlock(&mutSFn);
        pthread_mutex_lock(&mutSFF);
        SocketFdnF=SocketFdn;
        SocketFdnFR=SocketFdn;
        pthread_mutex_unlock(&mutSFF);
        //初始化加入车辆的全局信任值
        int i=0;
        for(;i<gCTrustn;i++){
           if(strcmp(gCTrust[i].CarID,CarID)==0) break;
        }
        if(i>=gCTrustn){
           strcpy(gCTrust[gCTrustn].CarID,CarID);
           gCTrust[gCTrustn++].Trust=(float)0.500000;
        }
	}
	
    //销毁互斥锁
    pthread_mutex_destroy(&mutms);
    pthread_mutex_destroy(&mutmsR);
    pthread_mutex_destroy(&mutmsRf);
    pthread_mutex_destroy(&mutSFF);
    pthread_mutex_destroy(&mutSFFR);
    pthread_mutex_destroy(&mutSFn);
    pthread_mutex_destroy(&mutfp);
    pthread_mutex_destroy(&mutSC);
    pthread_cond_destroy(&cond);  
    pthread_cond_destroy(&condsc);  
    pthread_cond_destroy(&condms);   
    getchar();
    return 0;
}

