// Transparent SSL Tunnel hooking.
// Jeff Lawson <jlawson@bovine.net>
// $Id: stunrun.cpp,v 1.1 2001/11/19 05:04:29 jlawson Exp $

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
#include "detours.h"


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
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    memset(&si, 0, sizeof(STARTUPINFO));
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);
    if (!DetourCreateProcessWithDllA("mirc32.exe",
                                        NULL,
                                        NULL,
                                        NULL,
                                        FALSE,
                                        0,
                                        NULL,
                                        NULL,
                                        &si,
                                        &pi,
                                        "stuntour.dll",
                                        NULL))
    {
        MessageBox(NULL, "Unable to launch mIRC with an injected library.",
                   "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    return 0;
}
