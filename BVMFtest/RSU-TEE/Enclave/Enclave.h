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


#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);
//void ecall_mymemcpy();
void MyStrCpy(char *DeStr,char *SoStr,size_t DeLen,size_t SoLen);
size_t MyAccum(size_t start,size_t end);
//void MySleep(char *DeStr,char *SoStr,size_t DeLen,size_t SoLen);
//void TeeCalGR(struct mTrsLt DeStr[5],struct msgRtLt SoStr[15]);
//void TeeCalGRA(float DeStr[5],float SoStr[15],int n);
//void TeeCalGRAT(float *DeStr,struct ratingsD *SoStr,size_t DeLen,size_t SoLen,int n);
void TeeCalGRAT(struct mTrsLt *mTLst, struct msgRtLt *msRf,struct gCarTrust *gCTrust,size_t DeLen,size_t SoLen,size_t gCLen,int n);
void TeeCalSEG(struct mTrsLt *mTLs, struct msgRtLt *msRL,struct gCarTrust *gCTrust,size_t DeLen,size_t SoLen,size_t gCLen,int nTLsn,int msRLn,int gCTrustn);
#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
