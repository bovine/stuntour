// Transparent SSL Tunnel hooking.
// Jeff Lawson <jlawson@bovine.net>
// $Id: stuntour.h,v 1.1 2003/02/03 06:34:16 jlawson Exp $

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

//! This flag probably will always need to be left on until experimental 
//! portions of the code are made fully operational.
//#define PLEASEBLOCK 1

//! Define this flag to draw a blue border around mIRC when a secure connection is made.
//#define SECUREBLUEWINDOW 1

//! Defined to the registry key base for storage of local settings.
#define REGKEYBASE  "Software\\Bovine Networking Technologies, Inc.\\StunTour"

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
    SecureTunnel() : ssl(NULL), sock(INVALID_SOCKET) {};
    SecureTunnel(SOCKET s, const sockaddr_in &inaddr) : addr(inaddr), ssl(NULL), sock(s) {};

public:

    ~SecureTunnel();
    static SecureTunnel *Attach(SOCKET s, const sockaddr_in &inaddr);
    int Send(const char FAR *buf, int len);
    int Recv(char FAR *buf, int len);

    static SecureTunnel *GetFromSSL(SSL *inssl);
    std::string GetAddressAndPort() const;
};


//-----------------------------


// external reference prototypes.
const char *TranslateSSLError(int errorcode);
const char *TranslateX509Error(int errorcode);
const char *TranslateWinsockError(int errorcode);
void SearchAndSubclassWindow(void);
bool AddInterceptedPort(unsigned short portnum);
std::string QueryInterceptedPortListSpace();


//! shared globals.
extern SSL_CTX *g_ctx;
extern int g_stunrefidx;
extern const char g_sid_ctx[];


//-----------------------------

#endif
