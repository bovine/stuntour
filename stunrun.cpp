/*
 * Copyright (c) 2002-2003, Jeffrey A. Lawson and Bovine Networking
 * Technologies, Inc. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of Bovine Networking Technologies, Inc. nor the names
 * of its contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
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
 */

// Transparent SSL Tunnel hooking.
// Jeff Lawson <jlawson@bovine.net>
// $Id: stunrun.cpp,v 1.4 2003/05/18 22:10:47 jlawson Exp $

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Standard Windows headers.
#include <windows.h>

// Standard ANSI C headers
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

// Microsoft Detours API hooking headers.
#include <detours.h>


//! Debug logging macros.
#ifdef NDEBUG
    #define DOUT(x)       // nothing when debugging is disabled.
#else
    #pragma message("building with DOUT() message logging enabled")
    static inline void dout_helper(const char *formatstr, ...) {
        va_list ap;
        char buffer[1024];
        va_start(ap, formatstr);
        _vsnprintf(buffer, sizeof(buffer), formatstr, ap);
        OutputDebugString(buffer);
        va_end(ap);
    }
    #define DOUT(x)   dout_helper x
#endif


//! Startup entry-point.
int main(int argc, char *argv[])
{
    char szMircFilename[MAX_PATH], szStunTourFilename[MAX_PATH];
    char *filepart;
    if (!GetFullPathName("mirc.exe", sizeof(szMircFilename), szMircFilename, &filepart) ||
        GetFileAttributes(szMircFilename) == -1L) {
        MessageBox(NULL, "Could not locate MIRC.EXE executable.",
                   "Unable to start", MB_OK | MB_ICONERROR);
        return -1;
    }
    if (!GetFullPathName("stuntour.dll", sizeof(szStunTourFilename), szStunTourFilename, &filepart) ||
        GetFileAttributes(szMircFilename) == -1L) {
        MessageBox(NULL, "Could not locate STUNTOUR.DLL interception library.",
                   "Unable to start", MB_OK | MB_ICONERROR);
        return -1;
    }



    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    memset(&si, 0, sizeof(STARTUPINFO));
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);
    if (!DetourCreateProcessWithDllA(szMircFilename,
                                        NULL,
                                        NULL,
                                        NULL,
                                        FALSE,
                                        0,
                                        NULL,
                                        NULL,
                                        &si,
                                        &pi,
                                        szStunTourFilename,
                                        NULL))
    {
        MessageBox(NULL, "Unable to launch mIRC with an injected library.",
                   "Unable to start", MB_OK | MB_ICONERROR);
        return 1;
    }
    return 0;
}
