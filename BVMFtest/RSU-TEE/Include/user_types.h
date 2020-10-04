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


/* User defined types */


#define LOOPS_PER_THREAD 500

typedef void *buffer_t;
typedef int array_t[10];
//评估消息信任值
 //定义消息类型  
struct message{
	char CarID[20];
	long No;
	char attri;
	char RSUID[20];
	//int length;
	char content[30];
};
//加上时间周期戳的消息类型
struct messageS{
	struct message m;
	long ti;
};
//加上评估者和评估值的消息类型
struct msgRtLt{
    struct messageS ms;
    char RCarID[20];
    float rating; 
};   
//评估值贝叶斯推断结果
struct mTrsLt{
    struct messageS ms;
    float  ratingT;
};
//全局车辆信任值
struct gCarTrust{
    char CarID[20];
    int CarNum;
    float Trust;
    float sendTrust;
    float evaTrust;
};
//传递评估值和trust部分对rating消息进行贝叶斯推断
struct ratingsD{
    float rating;
    float Trust;
};
//作为发送节点和评估节点的信任值
struct sETrust{
    char CarID[20];
    float sendTrust;
    float evaTrust;
};
struct gSum{
    float sum;
    int num;
};
//线程传递可变数组及参数结构体
struct ptdParm{
    int mSSize;
    int maxClient;
    int maxTrust;
    struct messageS *ms;
    struct msgRtLt *msR;
    struct msgRtLt *msRf;
    struct gCarTrust *gCTrust;
    int client;
};

//struct mTrsLt mTLst[5];
//struct mTrsLt mTLs[150];



