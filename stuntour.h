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
// $Id: stuntour.h,v 1.5 2003/07/20 04:04:04 jlawson Exp $

#ifndef STUNTOUR_H__
#define STUNTOUR_H__

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef WIN32
#define WIN32       // used by OpenSSL headers for platform checking
#endif

// Standard Windows headers.
#include <windows.h>
#include <winsock.h>

// Standard ANSI C headers
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

// Standard Template Library
#pragma warning(disable:4786 4512 4100)
#pragma warning(disable:4097 4127)
#include <map>
#include <set>

// OpenSSL/libeay crypto headers.
#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#if !defined(OPENSSL_VERSION_NUMBER) || (OPENSSL_VERSION_NUMBER < 0x0090581fL)
#error "Unsupported OpenSSL version for compilation."
#endif

// Microsoft Detours API hooking headers.
#include <detours.h>


//-----------------------------

//! This flag is a remnant of the old networking implementation that relied
//! heavily on the use of blocking sockets.  Leave it undefined, unless you
//! really want to use the old, deprecated behavior.
//#define PLEASEBLOCK 1

//! Defined to the registry key base for storage of local settings.
#define REGKEYBASE  "Software\\Bovine Networking Technologies, Inc.\\StunTour"

//! Define if you want to enable the experimental "DCC CHAT" to "DCC SCHAT"
//! interception.
#define HOOK_DCC_SCHAT 1

//-----------------------------

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


//-----------------------------


//! An internal class constructed for each connection that we are
//! currently intercepting and providing SSL tunnelling services for.
class SecureTunnel {
    //! address and port of the remote party.
    sockaddr_in addr;

    //! vital state information.
    SSL *ssl;
    SOCKET sock;

#ifndef PLEASEBLOCK
    //! pending data to send.
    std::string pendingsend;
    std::string morependingsend;
    bool write_wants_read;
#endif

    //! protected constructors.
    SecureTunnel() : ssl(NULL), sock(INVALID_SOCKET), bCertificateAccepted(false) { 
        addr.sin_addr.S_un.S_addr = INADDR_NONE;
    };
    SecureTunnel(SOCKET s, const sockaddr_in &inaddr) : addr(inaddr), ssl(NULL), sock(s), bCertificateAccepted(false) {
        // nothing else.
    };

public:

    //! Destructor.
    ~SecureTunnel();

    //! The publicly exposed method for creating a new secure connection.
    static SecureTunnel *Attach(SOCKET s, const sockaddr_in &inaddr, bool bAcceptNotConnect);

    // Network send and receive methods called from the winsock hooks.
    int Send(const char FAR *buf, int len);
    int Recv(char FAR *buf, int len);

    //! Determine the object pointer from an SSL object.
    static SecureTunnel *GetFromSSL(SSL *inssl);

    //! Query information about this object.
    std::string GetAddressAndPort() const;
    SOCKET GetSocket() { return sock; }
    SSL *GetSSL() { return ssl; }

    //! Certificate acceptance state.
    bool bCertificateAccepted;
};


//-----------------------------

struct ConfirmationDialogData
{
    // Identity information.
    SecureTunnel *stunnel;          //!< Connection object.
    X509 *err_cert;                 //!< actual OpenSSL certificate object.
    int preverify_ok;               //!< whether OpenSSL's initial checks succeeded.
    int err;
    int depth;

    // Response from user confirmation dialog checkbox.
    bool bRememberChoice;
};


//-----------------------------


// external reference prototypes.
const char *TranslateSSLError(int errorcode);
const char *TranslateX509Error(int errorcode);
const char *TranslateWinsockError(int errorcode);

// mIRC specific functions.
HWND GetOurParentWindow(void);

// port interception list functions.
bool AddInterceptedPort(unsigned short uPortNum, bool bOneShot);
std::string QueryInterceptedPortListSpace();

// certificate acceptance function.
DWORD ConfirmCertificateDialog(ConfirmationDialogData *certinfo);
bool CheckAllowCertificate(ConfirmationDialogData *certinfo);
void CloseConfirmationDialogForSocket(SOCKET sock);
void PersistAcceptanceForCertificate(ConfirmationDialogData *confinfo);

//! shared globals.
extern SSL_CTX *g_ctx;
extern int g_stunrefidx;
extern bool g_bSecureOutgoingDccChat;
extern const char g_sid_ctx[];
extern HINSTANCE g_hInstance;


//-----------------------------

#endif
