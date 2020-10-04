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
/*
void ecall_mymemcpy()
{
    char DeStr[DeLen]="";
    char SoStr[SoLen]="SGX";
    ocall_strcpy(DeStr,SoStr,DeLen,SoLen);
    printf("%s\n",DeStr);
 }*/
 void MyStrCpy(char *DeStr,char *SoStr,size_t DeLen,size_t SoLen)
 {
    if(DeLen>SoLen)
       DeLen=SoLen;
    if(DeLen>=0)
      memcpy(DeStr,SoStr,SoLen);
 }
 size_t MyAccum(size_t start,size_t end)
 {
     size_t sum=0;
     for(;start<=end;start++)
         sum+=start;
     return sum;
 }
void TeeCalGR(struct mTrsLt DeStr[5],struct msgRtLt  SoStr[15])
{
    int t=0;
    printf("jinrutee%d",t);
    for(int i=0;i<=5;i++)
    {   
        float sum=0;int n=0;
        for(int k=0;k<3;k++)
            if(SoStr[i+k].rating!=0)
                {sum=sum+SoStr[i+k].rating;n++;}
        DeStr[i].ratingT=sum/n;
        DeStr[i].ms=SoStr[i].ms;
    }   
        
}
void TeeCalGRA(float DeStr[5],float SoStr[15],int n)
{
    int t=0,m=0;
    printf("jinrutee%d",t);
    for(int i=0;i<=5;i++)
    {   
        float sum=0;
        for(int k=0;k<n;k++)
            {sum=sum+SoStr[i*n+k];}
        DeStr[m++]=sum/n;
        //DeStr[i]=SoStr[i];
    }   
        
}
//根据贝叶斯推断计算当前组ratings的trust

void TeeCalGRAT(struct mTrsLt *mTLst, struct msgRtLt *msRf,struct gCarTrust *gCTrust,size_t DeLen,size_t SoLen,size_t gCLen,int n)
{
     int t=0,m=0;int i;
    //printf("jinrutee%d\n",t);
    //printf("DeLen%d\n",DeLen);
    //printf("SoLen%d\n",SoLen);
    //printf("n%d\n",n);
    for(int i=0;i<(DeLen/sizeof(struct mTrsLt));i++)
    {   
        float sum=0;
        for(int k=0;k<n;k++)
        {
            for(int j=0;j<gCLen/sizeof(struct gCarTrust);j++)
            if(strcmp(msRf[i*n+k].RCarID,gCTrust[j].CarID)==0){
                if(msRf[i*n+k].rating==0.500000)sum=sum+0.500000;
				else{
				sum=sum+gCTrust[j].Trust*msRf[i*n+k].rating/(msRf[i*n+k].rating*gCTrust[j].Trust+0.5*(1-gCTrust[j].Trust));}
			}
        }
		mTLst[m].ms=msRf[m].ms;	
        mTLst[m++].ratingT=sum/n;
        //printf("zhi%f",mTLst[m-1].ratingT);
        //DeStr[i]=SoStr[i];
    }
     
}

//全局信任值计算
void TeeCalSEG(struct mTrsLt *mTLs, struct msgRtLt *msRL,struct gCarTrust *gCTrust,size_t DeLen,size_t SoLen,size_t gCLen,int nTLsn,int msRLn,int gCTrustn){
    //printf("jixing Global jisuan\n");
    //for(int i=0;i<gCTrustn;i++)
        //printf("id %d,%s trust,%f msRLn%d,nTLsn%d\n",i,gCTrust[i].CarID,gCTrust[i].Trust,msRLn,nTLsn);
        
    //计算作为send trust
    struct gSum Sum[gCTrustn];
    for(int i=0;i<gCTrustn;i++)
        {Sum[i].sum=0;Sum[i].num=0;}
    for(int k=0;k<nTLsn;k++)
    { 
    
        for(int i=0;i<gCTrustn;i++)
        if(strcmp(mTLs[k].ms.m.CarID,gCTrust[i].CarID)==0) {Sum[i].sum=Sum[i].sum+mTLs[k].ratingT;Sum[i].num++;}
    }
    for(int i=0;i<gCTrustn;i++)
        {//printf("sendsum%f,num%d\n",Sum[i].sum,Sum[i].num);
        if(Sum[i].sum!=0) gCTrust[i].sendTrust=Sum[i].sum/Sum[i].num;
        else gCTrust[i].sendTrust=0.500000;}
    //for(int i=0;i<gCTrustn;i++)
        //printf("id %s sendtrust %f\n",gCTrust[i].CarID,gCTrust[i].sendTrust);
        
    //计算作为evaluator trust
    for(int i=0;i<gCTrustn;i++)
        {Sum[i].sum=0;Sum[i].num=0;}
    //for(int k=0;k<msRLn;k++)
       // printf("msRLrating=ID%sNo%d\n",msRL[k].ms.m.CarID,msRL[k].ms.m.No);
    //for(int k=0;k<nTLsn;k++)
       // printf("msTLs=ID%sNo%d\n",mTLs[k].ms.m.CarID,mTLs[k].ms.m.No);
    int times=0;
    for(int k=0;k<msRLn;k++)
    { 
    
        for(int i=0;i<gCTrustn;i++)
        if(strcmp(msRL[k].RCarID,gCTrust[i].CarID)==0)
         {
            //printf("nTLsn=%d\n",nTLsn);
            for(int n=0;n<nTLsn;n++)
            if((strcmp(mTLs[n].ms.m.CarID,msRL[k].ms.m.CarID)==0)&&(mTLs[n].ms.m.No==msRL[k].ms.m.No))
            {
               // printf("times:%d\n",times++);
                if((mTLs[n].ratingT>0.500000&&msRL[k].rating>0.500000)||(mTLs[n].ratingT<0.500000&&msRL[k].rating<0.500000)){Sum[i].sum=Sum[i].sum+gCTrust[i].Trust*1.05;Sum[i].num++;//printf("sum[%d]=%fn=%d\n",i,Sum[i].sum,Sum[i].num);
                break;
                }
                else if((mTLs[n].ratingT>0.500000&&msRL[k].rating<0.500000)||(mTLs[n].ratingT<0.500000&&msRL[k].rating>0.500000)){Sum[i].sum=Sum[i].sum+gCTrust[i].Trust*0.9;Sum[i].num++;//printf("sum[%d]=%fn=%d\n",i,Sum[i].sum,Sum[i].num);
                break;}
                else {Sum[i].sum=Sum[i].sum+0.500000;Sum[i].num++;//printf("sum[%d]=%fn=%d\n",i,Sum[i].sum,Sum[i].num);
                break;}
            }
            //break;
         }
                
    }
    for(int i=0;i<gCTrustn;i++)
    { 
    //printf("evasum%f,num%d\n",Sum[i].sum,Sum[i].num);
    if(Sum[i].sum!=0)gCTrust[i].evaTrust=Sum[i].sum/Sum[i].num;
    else gCTrust[i].evaTrust=0.500000;}
    //for(int i=0;i<gCTrustn;i++)
        //printf("id %s evatrust %f\n",gCTrust[i].CarID,gCTrust[i].evaTrust);
    //全局信任值更新
    for(int i=0;i<gCTrustn;i++)
    {gCTrust[i].Trust=(gCTrust[i].sendTrust+gCTrust[i].evaTrust+gCTrust[i].Trust)/3;}
    //for(int i=0;i<gCTrustn;i++)
        //printf("id %s trust %f\n",gCTrust[i].CarID,gCTrust[i].Trust);
    //printf("jisuan send Trust\n");
    //printf("jisuan evaluator Trust\n");
    //printf("jisuan glocal Trust\n");
}
