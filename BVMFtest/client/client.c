#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>


#define SERVER_PORT 1234
long No=1;
int tmsgLen=4096;
//定义消息为五元组
struct message{
	char CarID[20];
	long No;
	char attri;
	char RSUID[20];
	//int length;
	char content[30];
};
struct messages{
	struct message m;
	long ti;
};
struct msgRtLt{
    struct messages ms;
    char RCarID[20];
    float rating; 
};
int main()
{
    char servIP[20]="192.168.1.109";
    //puts("请输入要连接RSU的IP地址:");
    //scanf("%s",servIP);
    int mSSize;
    puts("请输入一次要评估的最大消息数量:");
    scanf("%d",&mSSize);
    int mCNum=10000;
    //puts("请输入循环发送消息的次数:");
    //scanf("%d",&mCNum);
    struct messages ms[mSSize];
    struct msgRtLt msR[mSSize];
	int clientSocket;
	struct sockaddr_in serverAddr,clientAddr;//服务器端地址,客户端地址
	int clientAddrLen=sizeof(clientAddr);
	char sendbuf[tmsgLen];
	char recvbuf[tmsgLen];
	struct message sendbufm;
	char attri[]={'a','b','c','d','e','f'};
	char attriC[]={'a','b','c'};
	int iDataNum;
	struct timeval time_start,time_end;
	struct timeval time_startst,time_endst ;
	int times=1;
	//srand((int)time(0));
	char CarID[20];//保存点分十进制的ip地址
	char RSUID[20];//保存点分十进制的ip地址
	char RCarID[20];//保存点分十进制的ip地址
	 FILE *fp;
	if((clientSocket = socket(AF_INET,SOCK_STREAM,0)) < 0)
	{
		perror("socket");
		return 1;
	}

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(SERVER_PORT);
	serverAddr.sin_addr.s_addr = inet_addr(servIP);
	if(connect(clientSocket,(struct sockaddr*)&serverAddr,sizeof(serverAddr)) < 0)
	{
		perror("connect");
		return 1;
	}

	printf("connect with destination host...%s\t%d\n",inet_ntop(AF_INET,&serverAddr.sin_addr.s_addr,RSUID,sizeof(RSUID)),ntohs(serverAddr.sin_port));
    getsockname(clientSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);//获取sockfd表示的连接上的本地地址
	while(times<=mCNum+2)
	{
	     srand((unsigned)time(NULL)+rand());
		//printf("Input your word:>");
		//scanf("%s",sendbuf);
		//printf("\n");
		//为消息赋值
		struct message m,mr;
		memset(sendbuf,'\0',tmsgLen);
		memset(&m,'\0',sizeof(m));
		strcpy(m.CarID,inet_ntop(AF_INET,&clientAddr.sin_addr.s_addr,CarID,sizeof(CarID)));
		m.No=No++;
		int index=rand()%sizeof(attri);
		m.attri=attri[index];
		//printf("%d\n",index);
		strcpy(m.RSUID,inet_ntop(AF_INET,&serverAddr.sin_addr.s_addr,RSUID,sizeof(RSUID)));
		if(strncmp(recvbuf,"wait for rating",15)==0)
		    strcpy(m.content,"wait for rating");
		else strcpy(m.content,"hello");
		memset(recvbuf,'\0',tmsgLen);
		//m.length=sizeof("hello")-1;
		
		//消息赋值结束
		memcpy(sendbuf,&m,sizeof(m));
		//printf("%160s",sendbuf);
		if(times==mCNum+1)
	        strcpy(sendbuf,"quit");
	     gettimeofday(&time_start,NULL); 
	    //发送消息 
		send(clientSocket,sendbuf,sizeof(m),0);
		if(strcmp(sendbuf,"quit") == 0)
			break;
		//接收消息
		iDataNum =recv(clientSocket,recvbuf,sizeof(struct messages)*mSSize,0);
		//printf("%s  %ld\n",recvbuf,sizeof(recvbuf));
		//printf("%s  %ld\n",recvbuf,sizeof("wait for rating"));
		//printf("%s  %ld\n",recvbuf,sizeof(ms));
		//int i=strncmp(recvbuf,"wait for rating",15);
		//printf("%d\n",i);
		//开始评估消息
		//if(strncmp(recvbuf,"wait for rating",15)==0)
		//printf("iDataNum%d",iDataNum);
		//printf("iDataNum%d",iDataNum);
		if(iDataNum>sizeof(struct message))
		{ 
		    
		    //memset(recvbuf,'\0',tmsgLen);
		    memset(ms,'\0',sizeof(ms));
		    memset(msR,'\0',sizeof(msR));
		   // gettimeofday(&time_startst,NULL); 
		    //iDataNum =recv(clientSocket,recvbuf,sizeof(ms),0);
		    //gettimeofday(&time_endst,NULL);
		    memcpy(&ms,recvbuf,sizeof(ms));
		    
       // int timeuses=1000000*(time_endst.tv_sec-time_startst.tv_sec)+time_endst.tv_usec-time_startst.tv_usec;
       // printf("MGRCtime:%d us.\n",timeuses);
		   // printf("%c\n",ms[4].m.attri);
		    int i=0;
		     //puts("receive ok");
		    
		    while(i<mSSize)
		    {
		        int k=0;
                for(;ms[i].m.attri!=attriC[k]&&k<sizeof(attriC);k++);
                
		        //printf("%d\n",k);
		        if(k<sizeof(attriC)){
	                msR[i].ms=ms[i];
	                msR[i].rating=(rand()%1000)*0.001;
	                strcpy(msR[i].RCarID,inet_ntop(AF_INET,&clientAddr.sin_addr.s_addr,RCarID,sizeof(RCarID)));
	            }
	            else{
	                msR[i].ms=ms[i];
	                msR[i].rating=0.5;
	                strcpy(msR[i].RCarID,inet_ntop(AF_INET,&clientAddr.sin_addr.s_addr,RCarID,sizeof(RCarID)));
	            }
	            i++;
	 
		    }
		    
		   // puts("receive ok");
		   for(i=0;i<mSSize;i++)
		       printf("%f\n",msR[i].rating);
		   // puts("receive ok");
		    memset(sendbuf,'\0',tmsgLen);
		    memcpy(sendbuf,&msR,sizeof(msR));
		    
            send(clientSocket,sendbuf,sizeof(msR),0);
            printf("msR%ld,%ld",sizeof(msR),sizeof(struct msgRtLt)*mSSize);
            iDataNum =recv(clientSocket,recvbuf,sizeof(m),0);
		    memset(&mr,'\0',sizeof(mr));
		    memcpy(&mr,recvbuf,sizeof(mr));
		    gettimeofday(&time_end,NULL);
		    int timeuse=1000000*(time_end.tv_sec-time_start.tv_sec)+time_end.tv_usec-time_start.tv_usec; 
            fp=fopen("data.txt","a+");
            if(fp==NULL)
            {
            printf("File cannot open! ");
            exit(0);
            }
            fprintf(fp,"%d\t",timeuse);
            fclose(fp);
            printf("Ratingtime:%d us.\n",timeuse);
		    //recvbuf[iDataNum] ='\0';
		    printf("recv data of my word is: %s\n",mr.content);
		    //sleep(1);
		    times++;
		    usleep(200000);
            //puts("receive ok");
		}
		else{
		memset(&mr,'\0',sizeof(mr));
		memcpy(&mr,recvbuf,sizeof(mr));
		gettimeofday(&time_end,NULL);
		int timeuse=1000000*(time_end.tv_sec-time_start.tv_sec)+time_end.tv_usec-time_start.tv_usec; 
        fp=fopen("data.txt","a+");
        if(fp==NULL)
        {
        printf("File cannot open! ");
        exit(0);
        }
        fprintf(fp,"%d\t",timeuse);
        fclose(fp);
		//recvbuf[iDataNum] ='\0';
		printf("recv data of my word is: %s\n",mr.content);
		//sleep(1);
		printf("time:%d us.\n",timeuse);
		times++;
		usleep(200000);
		}
		
	}
	close(clientSocket);
	return 0;
}
