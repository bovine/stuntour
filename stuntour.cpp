// Transparent SSL Tunnel hooking.
// Jeff Lawson <jlawson@bovine.net>
// $Id: stuntour.cpp,v 1.1 2001/11/19 05:04:29 jlawson Exp $

/*
 * The implementation of the replacement API wrappers for the send/recv
 * functions are unfortunately not sufficiently conformant with the original
 * Winsock methods to be suitable for a generic hook for arbitrary applications.
 * Because of this, applications that were not originally written with some
 * of the characteristics that we assumed will probably break.
 *
 * The send() hook that we install will potentially block (particularly
 * during early session establishment) even if the socket was placed
 * in non-blocking mode.  This is because the underlying session
 * establishment requires many send/recv operations and our send() hook
 * needs to try to fully send as much of the caller's buffer as possible.
 *
 * The application should be written so that it is tolerant of select()
 * indicating that a socket is readable, but actually calling recv()
 * returns -1 and WSAEWOULDBLOCK.  This is because the socket readability
 * implied that there was low-level SSL traffic ready to read, but not
 * necessary user-readable data.
 *
 * OpenSSL has the annoying requirement that non-blocking sockets will
 * cause SSL_read() and SSL_write() to possibly indicate that it needs
 * to read or write but the socket would block.  When those events
 * occur, it expects the same SSL_read() or SSL_write() operation to be
 * repeated WITH THE SAME BUFFER/ARGUMENTS when the socket becomes
 * readable/writable.  This is very problematic for a generic application
 * and this wrapper doesn't attempt to accomodate this occurrence well.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef WIN32
#define WIN32       // used by openssl headers for platform checking
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


//! Defines what destination port number is automatically redirected
//! through an SSL-tunnel.
#define INTERCEPTED_PORT      994


//! This flag probably will always need to be left on.
#define PLEASEBLOCK 1


//! An internal class constructed for each connection that we are
//! currently intercepting and providing SSL tunnelling services for.
class SecureTunnel {
    //! address and port of the remote party.
    sockaddr_in addr;

    //! vital state information.
    SSL *ssl;
    SOCKET sock;

    //! protected constructors.
    SecureTunnel() : ssl(NULL), sock(INVALID_SOCKET) {};
    SecureTunnel(SOCKET s, const sockaddr_in &inaddr) : addr(inaddr), ssl(NULL), sock(s) {};

public:

    ~SecureTunnel();
    static SecureTunnel *Attach(SOCKET s, const sockaddr_in &inaddr);
    int Send(const char FAR *buf, int len);
    int Recv(char FAR *buf, int len);
};



//! Global mutex variables to allow thread-safe access to the map.
static CRITICAL_SECTION maplock;

//! This map stores all open intercepted connections.
typedef std::map<SOCKET, SecureTunnel*> securetunnelmap_t;
static securetunnelmap_t SecureTunnelMap;

//! global SSL context.
static SSL_CTX *ctx;

//! Unique context identifier used to initialize SSL with.
static const char sid_ctx[] = "stunnel SID";




// forward reference
static void SearchAndSubclassWindow(void);



//! Redirected trampolines used to intercept network connections.
DETOUR_TRAMPOLINE(int WINAPI Trampoline_connect(
        SOCKET /*s*/, const struct sockaddr FAR * /*name*/, int /*namelen*/),
                  connect);
DETOUR_TRAMPOLINE(int WINAPI Trampoline_send(
        SOCKET /*s*/, const char FAR * /*buf*/, int /*len*/, int /*flags*/),
                  send);
DETOUR_TRAMPOLINE(int WINAPI Trampoline_recv(
        SOCKET /*s*/, char FAR * /*buf*/, int /*len*/, int /*flags*/),
                  recv);
DETOUR_TRAMPOLINE(int WINAPI Trampoline_closesocket(
        SOCKET /*s*/),
                  closesocket);


//! Macro used to simplify error message translation.
#define MAPERROR(errcode)   case errcode: return #errcode;


//! Return a textual string representing of an SSL error code.
static const char *TranslateSSLError(int errorcode) {
    switch (errorcode) {
        MAPERROR(SSL_ERROR_NONE);
        MAPERROR(SSL_ERROR_SSL);
        MAPERROR(SSL_ERROR_WANT_READ);
        MAPERROR(SSL_ERROR_WANT_WRITE);
        MAPERROR(SSL_ERROR_WANT_X509_LOOKUP);
        MAPERROR(SSL_ERROR_SYSCALL);
        MAPERROR(SSL_ERROR_ZERO_RETURN);
        MAPERROR(SSL_ERROR_WANT_CONNECT);
        default: {
            static char buffer[20];
            sprintf(buffer, "SSL=%d", errorcode);
            return buffer;
        }
    }
}


//! Return a textual string representing of a Winsock error code.
static const char *TranslateWinsockError(int errorcode) {
    switch (errorcode) {
        MAPERROR(WSAEINTR);
        MAPERROR(WSAEBADF);
        MAPERROR(WSAEACCES);
        MAPERROR(WSAEFAULT);
        MAPERROR(WSAEINVAL);
        MAPERROR(WSAEMFILE);
        MAPERROR(WSAEWOULDBLOCK);
        MAPERROR(WSAEINPROGRESS);
        MAPERROR(WSAEALREADY);
        MAPERROR(WSAENOTSOCK);
        MAPERROR(WSAEDESTADDRREQ);
        MAPERROR(WSAEMSGSIZE);
        MAPERROR(WSAEPROTOTYPE);
        MAPERROR(WSAENOPROTOOPT);
        MAPERROR(WSAEPROTONOSUPPORT);
        MAPERROR(WSAESOCKTNOSUPPORT);
        MAPERROR(WSAEOPNOTSUPP);
        MAPERROR(WSAEPFNOSUPPORT);
        MAPERROR(WSAEAFNOSUPPORT);
        MAPERROR(WSAEADDRINUSE);
        MAPERROR(WSAEADDRNOTAVAIL);
        MAPERROR(WSAENETDOWN);
        MAPERROR(WSAENETUNREACH);
        MAPERROR(WSAENETRESET);
        MAPERROR(WSAECONNABORTED);
        MAPERROR(WSAECONNRESET);
        MAPERROR(WSAENOBUFS);
        MAPERROR(WSAEISCONN);
        MAPERROR(WSAENOTCONN);
        MAPERROR(WSAESHUTDOWN);
        MAPERROR(WSAETOOMANYREFS);
        MAPERROR(WSAETIMEDOUT);
        MAPERROR(WSAECONNREFUSED);
        MAPERROR(WSAELOOP);
        MAPERROR(WSAENAMETOOLONG);
        MAPERROR(WSAEHOSTDOWN);
        MAPERROR(WSAEHOSTUNREACH);
        MAPERROR(WSAENOTEMPTY);
        MAPERROR(WSAEPROCLIM);
        MAPERROR(WSAEUSERS);
        MAPERROR(WSAEDQUOT);
        MAPERROR(WSAESTALE);
        MAPERROR(WSAEREMOTE);
        MAPERROR(WSAEDISCON);
        MAPERROR(WSASYSNOTREADY);
        MAPERROR(WSAVERNOTSUPPORTED);
        MAPERROR(WSANOTINITIALISED);
        default: {
            static char buffer[20];
            sprintf(buffer, "WSA=%d", errorcode);
            return buffer;
        }
    }
}


#if 0
//! Puts a socket into blocking mode.
static int SetSocketBlocking(SOCKET sock)
{
    unsigned long value = 0;
    return ioctlsocket(sock, FIONBIO, &value);
}

//! Puts a socket into non-blocking mode.
static int SetSocketNonBlocking(SOCKET sock)
{
    // Use with a nonzero argp parameter to enable the nonblocking mode.
    unsigned long value = 1;
    return ioctlsocket(sock, FIONBIO, &value);
}
#endif

static void WaitForReadability(SOCKET socket)
{
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(socket, &rs);
    select(0, &rs, NULL, NULL, NULL);
}

static void WaitForWritability(SOCKET socket)
{
    fd_set ws;
    FD_ZERO(&ws);
    FD_SET(socket, &ws);
    select(0, NULL, &ws, NULL, NULL);
}


//! Destructor for our connection interception.
/*!
 * Handles freeing of the SSL context.
 */
SecureTunnel::~SecureTunnel() {
    if (ssl != NULL) {
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_free(ssl);
    }
}


//! The only public way to create an instance of the SecureTunnel class.
/*!
 * \param insock Supplies the opened socket handle that should be intercepted.
 * \param inaddr Indicates the destination address to where the socket
 *          was connecting to.
 * \return Returns a pointer to the new SecureTunnel class instance.
 */
SecureTunnel *SecureTunnel::Attach(SOCKET insock, const sockaddr_in &inaddr)
{
    // construct a new class instance.
    SecureTunnel *newobj = new SecureTunnel(insock, inaddr);
    if (!newobj) {
        WSASetLastError(WSAENOBUFS);
        return NULL;
    }

    // do the job.
    newobj->ssl = SSL_new(ctx);
    if (!newobj->ssl) {
        DOUT(("SSL_new failed to create a new context\n"));
        delete newobj;
        return NULL;
    }
    SSL_set_session_id_context(newobj->ssl,
                               (const unsigned char*) sid_ctx, strlen(sid_ctx));

    // Attempt to use the most recent id in the session cache.
    if ( ctx->session_cache_head ) {
        if ( ! SSL_set_session(newobj->ssl, ctx->session_cache_head) ) {
            DOUT(("Cannot set SSL session id to most recent used\n"));
        }
    }

    // Associate the socket with the SSL object.
    SSL_set_fd(newobj->ssl, insock);

    // Sets ssl to work in client mode.
    SSL_set_connect_state(newobj->ssl);

    // make blocking mode sockets not return until completion.
    SSL_set_mode(newobj->ssl, SSL_MODE_AUTO_RETRY);


    // Try to connect the ssl tunnel.
    int num = SSL_connect(newobj->ssl);
    if (num <= 0) {
        int sslerror = (int) SSL_get_error(newobj->ssl, num);
        int wsagle = WSAGetLastError();
        switch (sslerror) {
            case SSL_ERROR_NONE:
                // great, no problem.
                break;

            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_X509_LOOKUP:
                // not an error, but the connection could not be established yet.
                DOUT(("SSL_connect deferred SSL establishment because of a %s condition.\n",
                      TranslateSSLError(sslerror) ));
                break;

            case SSL_ERROR_SYSCALL:
                if (wsagle == WSAENOTCONN) {
                    // not an error, but the connection could not be established yet.
                    // (probably socket is non-blocking and the connect() is not done.)
                    DOUT(("SSL_connect deferred SSL establishment because not yet connected.\n"));
                    break;
                }
                // otherwise drop through to default case.

            default:
                DOUT(("SSL_connect returning failure (%s, %s)\n",
                      TranslateSSLError(sslerror), TranslateWinsockError(wsagle)));
                delete newobj;
                return NULL;
        }
    }

    return newobj;
}


//! Sends data over the encrypted SSL tunnel.
/*!
 * When an error is returned, the Winsock function WSAGetLastError() can
 * be used to determine the nature of the failure.
 *
 * If the socket was closed during the write attempt, then 0 will be
 * returned to the caller.
 *
 * \param buf Supplies a pointer to the input data buffer to send.
 * \param len Indicates the number of bytes to send.
 * \return Returns -1 on error, otherwise the number of bytes sent.
 *      Will never successfully return a value that is fewer than the
 *      argument 'len' requested.
 */
int SecureTunnel::Send(const char FAR *buf, int len)
{
    // catch easy argument errors.
    if (!buf || len < 0 || IsBadReadPtr(buf, len)) {
        WSASetLastError(WSAEFAULT);
        return -1;
    }
    if (len == 0) return 0;

    // First try performing the desired write.  If the socket is in
    // blocking mode then this operation will block until the entire
    // send (and any necessary protocol-level reads) is complete.
TryAgain:
    int num = SSL_write(ssl, buf, len);
    int sslerror = (int) SSL_get_error(ssl, num);
    switch (sslerror) {
        case SSL_ERROR_NONE:
            assert(num > 0 && num == len);
            return num;

#ifdef PLEASEBLOCK
        case SSL_ERROR_WANT_WRITE:
            WaitForWritability(sock);
            goto TryAgain;

        case SSL_ERROR_WANT_READ:
            WaitForReadability(sock);
            goto TryAgain;
#else
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            DOUT(("SecureTunnel::Send -- SSL_write returned %s - retry later\n",
                  TranslateSSLError(sslerror) ));
            WSASetLastError(WSAEWOULDBLOCK);
            return -1;
#endif

        case SSL_ERROR_SYSCALL:
            DOUT(("SecureTunnel::Send -- SSL_write (socket)\n"));
            WSASetLastError(WSAENETDOWN);
            return -1;

        case SSL_ERROR_ZERO_RETURN:
            DOUT(("SecureTunnel::Send -- SSL closed on write\n"));
            WSASetLastError(WSAENOTCONN);
            return 0;   // was -1

        case SSL_ERROR_SSL:
            DOUT(("SecureTunnel::Send -- SSL_write\n"));
            WSASetLastError(WSAENETDOWN);
            return -1;
        default:
            DOUT(("SecureTunnel::Send -- Unhandled SSL Error (%s, %s)\n",
                  TranslateSSLError(sslerror), TranslateWinsockError(WSAGetLastError()) ));
            WSASetLastError(WSAENETDOWN);
            return -1;
    }
}


//! Reads bytes from the encrypted channel and into a buffer.
/*!
 * When an error is returned, the Winsock function WSAGetLastError() can
 * be used to determine the nature of the failure.
 *
 * If the socket was closed during the read attempt, then 0 will be
 * returned to the caller.
 *
 * \param buf Supplies the buffer that should be filled with data.
 * \param len Indicates the maximum number of bytes that the buffer
 *      can accomodates.
 * \return Returns -1 on error, otherwise the number of bytes that were
 *      successfully read.  The number of bytes read may be less than
 *      the maximum size requested.
 */
int SecureTunnel::Recv(char FAR *buf, int len) {
    // catch easy argument errors.
    if (!buf || len < 0 || IsBadWritePtr(buf, len)) {
        WSASetLastError(WSAEFAULT);
        return -1;
    }
    if (len == 0) return 0;

    // First try performing the desired read.  If the socket is in
    // blocking mode then this operation will block until the entire
    // receive (and any necessary protocol-level write) is complete.
TryAgain:
    int num = SSL_read(ssl, buf, len);
    int sslerror = (int) SSL_get_error(ssl, num);
    switch (sslerror) {
        case SSL_ERROR_NONE:
            assert(num > 0 && num <= len);
            return num;

#ifdef PLEASEBLOCK
        case SSL_ERROR_WANT_WRITE:
            WaitForWritability(sock);
            goto TryAgain;
#else
        case SSL_ERROR_WANT_WRITE:
#endif
        case SSL_ERROR_WANT_READ:
            DOUT(("SecureTunnel::Recv -- SSL_read returned %s - retry later\n",
                  TranslateSSLError(sslerror) ));
            WSASetLastError(WSAEWOULDBLOCK);
            return -1;

        case SSL_ERROR_SYSCALL:
            DOUT(("SecureTunnel::Recv -- SSL_read (socket)\n"));
            WSASetLastError(WSAENETDOWN);
            return -1;

        case SSL_ERROR_ZERO_RETURN:
            DOUT(("SecureTunnel::Recv -- SSL closed on read\n"));
            WSASetLastError(WSAENOTCONN);
            return 0;   // was -1

        case SSL_ERROR_SSL:
            DOUT(("SecureTunnel::Recv -- SSL_read (%s, %s)\n",
                  TranslateSSLError(sslerror), TranslateWinsockError(WSAGetLastError()) ));
            WSASetLastError(WSAENETDOWN);
            return -1;

        default:
            DOUT(("SecureTunnel::Recv -- Unhandled SSL Error\n"));
            WSASetLastError(WSAENETDOWN);
            return -1;
    }
}



//! Decides if an outgoing connection on the specified port should be
//! intercepted and redirected through a dynamically opened SSL tunnel.
/*!
 * This method is called by our Detour_connect() hook.
 *
 * \param portnum Indicates the destination port number of the connection
 *      that is being considered for interception (host ordering).
 * \return Returns true if the connection should be intercepted,
 *      otherwise the connection should not be intercepted.
 */
static bool IsInterceptedPort(unsigned short portnum)
{
#if 0
    // In the future, we might want to allow a configurable list of
    // port number that we will intercept.  Eventually, this list might
    // be generated by looking at a registry key.
    typedef std::set<unsigned short> portlist_t;
    portlist_t InterceptedPortList;

    // But for now, we only populate the inception list with the hardcoded default.
    InterceptedPortList.insert(INTERCEPTED_PORT);

    portlist_t::iterator iter = InterceptedPortList.find(portnum);
    return(iter != InterceptedPortList.end());
#else
    return(portnum == INTERCEPTED_PORT);
#endif
}


//! This is our hook that is installed in place of the normal
//! Winsock connect() API.
static int WINAPI Detour_connect(
        SOCKET insock, const struct sockaddr FAR *name, int namelen)
{
    SearchAndSubclassWindow();

    // If any of the arguments look bogus, then immediately bail out and
    // just let the original Winsock method handle it.
    if (!insock || insock == INVALID_SOCKET || !name ||
        namelen < sizeof(sockaddr_in) || name->sa_family != AF_INET) {
        // This looks like a bogus connection attempt, so we'll ignore it
        // and just let the system API handle the error code.
        DOUT(("Detour_connect: bypassing connect 1\n"));
        return Trampoline_connect(insock, name, namelen);
    }


    // Decide if we should intercept this connection or not.
    const sockaddr_in &inaddr = *(const sockaddr_in *)name;
    if (!IsInterceptedPort(ntohs(inaddr.sin_port))) {
        // This isn't a connection to a port that we are cofigured to hook.
        DOUT(("Detour_connect: bypassing connect 2\n"));
        return Trampoline_connect(insock, name, namelen);
    }


//SetSocketBlocking(insock);      // put into blocking mode.

    // Call the underlying connect() and see if it succeeds.
    int retval = Trampoline_connect(insock, name, namelen);
    if (retval != 0) {
        int wsagle = WSAGetLastError();
        if (wsagle != WSAEWOULDBLOCK) {
            DOUT(("Detour_connect: pass-thru connect failed 3 (%s)\n",
                  TranslateWinsockError(wsagle)));
            return retval;
        } else {
            DOUT(("Detour_connect: processing connection in non-blocking mode (not yet connected)\n"));
        }
    } else {
        DOUT(("Detour_connect: processing connection in blocking mode (connected ok)\n"));
    }

    // Build the associated SSL state information around the socket.
    DOUT(("Detour_connect: attaching SSL onto connection to %s:%d (socket %d)\n",
          inet_ntoa(inaddr.sin_addr), (int) ntohs(inaddr.sin_port), (int) insock));
    SecureTunnel *stun = stun->Attach(insock, inaddr);
    if (!stun) {
        // We expect Attach() to call WSASetLastError() for us.
        // Note that for this case, the socket is actually still left open!
        DOUT(("Detour_connect: failed to attach\n"));
        return SOCKET_ERROR;
    }

#ifdef USE_MAKEPAIR
    SecureTunnelMap.insert(std::make_pair(insock, stun));
#else
    SecureTunnelMap.insert(std::pair<const SOCKET, SecureTunnel*>(insock, stun));
#endif

//SetSocketNonBlocking(insock);      // put back into non-blocking mode.

    return 0;
}



//! This is our hook that is installed in place of the normal
//! Winsock closesocket() API.
static int WINAPI Detour_closesocket(SOCKET insock)
{
    // Free the SecureTunnel class associated with this socket, if it is
    // one of the wrapped sockets that we manage.
    EnterCriticalSection(&maplock);
    securetunnelmap_t::iterator iter = SecureTunnelMap.find(insock);
    if (iter != SecureTunnelMap.end()) {
        SecureTunnel *ptr = iter->second;
        DOUT(("Detour_closesocket: releasing SSL structure for socket %d\n", (int) insock));
        SecureTunnelMap.erase(insock);
        delete ptr;
    }
    LeaveCriticalSection(&maplock);

    // close the actual socket and return the result.
    return Trampoline_closesocket(insock);
}


//! This is our hook that is installed in place of the normal
//! Winsock send() API.
static int WINAPI Detour_send(
        SOCKET insock, const char FAR *buf, int len, int flags)
{
    bool bHandled = false;
    bool bNested = false;
    int retval = -1;

    // Check if this socket is one of our managed sockets.
    // If so, then handle the actual send request.
    EnterCriticalSection(&maplock);
    if (maplock.LockCount == 0) {
        securetunnelmap_t::iterator iter = SecureTunnelMap.find(insock);
        if (iter != SecureTunnelMap.end()) {
            SecureTunnel *stun = iter->second;
            DOUT(("Detour_send: intercepting SSL send for socket %d\n", (int) insock));
            DOUT(("Detour_send: intercepting SSL data is: %s\n", buf));
            retval = stun->Send(buf, len);
            DOUT(("Detour_send: intercepted SSL send for socket %d returned %d\n", (int) insock, retval));
            bHandled = true;
        }
    } else {
        bNested = true;
    }
    LeaveCriticalSection(&maplock);

    // If this wasn't a managed socket (or is a nested call), then do
    // the normal thing for it.
    if (!bHandled) {
        if (bNested) {
            DOUT(("  Detour_send: nested send for socket %d\n", (int) insock));
        } else {
            DOUT(("Detour_send: invoking pass-thru send for socket %d\n", (int) insock));
        }
        retval = Trampoline_send(insock, buf, len, flags);
        if (bNested) {
            DOUT(("  Detour_send: nested send returned %d (%s)\n",
                  retval, TranslateWinsockError(WSAGetLastError())));
        } else {
            DOUT(("Detour_send: pass-thru for send returned %d (%s)\n",
                  retval, TranslateWinsockError(WSAGetLastError())));
        }
    }
    return retval;
}


//! This is our hook that is installed in place of the normal
//! Winsock recv() API.
static int WINAPI Detour_recv(
        SOCKET insock, char FAR *buf, int len, int flags)
{
    bool bHandled = false;
    bool bNested = false;
    int retval = -1;

    // Check if this socket is one of our managed sockets.
    // If so, then handle the actual read request.
    EnterCriticalSection(&maplock);
    if (maplock.LockCount == 0) {
        securetunnelmap_t::iterator iter = SecureTunnelMap.find(insock);
        if (iter != SecureTunnelMap.end()) {
            SecureTunnel *stun = iter->second;
            DOUT(("Detour_recv: intercepting SSL recv for socket %d\n", (int) insock));
            retval = stun->Recv(buf, len);
            bHandled = true;
        }
    } else {
        bNested = true;
    }
    LeaveCriticalSection(&maplock);

    // If this wasn't a managed socket, then do the normal thing for it.
    if (!bHandled) {
        if (bNested) {
            DOUT(("  Detour_send: nested recv for socket %d\n", (int) insock));
        } else {
            DOUT(("Detour_send: invoking pass-thru recv for socket %d\n", (int) insock));
        }
        retval = Trampoline_recv(insock, buf, len, flags);
        if (bNested) {
            DOUT(("  Detour_send: nested recv returned %d (%s)\n",
                  retval, TranslateWinsockError(WSAGetLastError())));
        } else {
            DOUT(("Detour_send: pass-thru for recv returned %d (%s)\n",
                  retval, TranslateWinsockError(WSAGetLastError())));
        }
    }
    return retval;
}


//! initialize the global SSL context.
/*!
 * Because this prepares the global state, this should be done only
 * once per program instance.
 */
void context_init(void)
{
    RAND_screen();
    if ( !RAND_status() ) {
        DOUT(("RAND_screen failed to sufficiently seed PRNG"));
    }

    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv3_client_method());

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    //SSL_CTX_set_timeout(ctx, options.session_timeout);

    //SSL_CTX_set_verify(ctx, options.verify_level, verify_callback);
    //SSL_CTX_set_info_callback(ctx, info_callback);

    //if (!SSL_CTX_set_cipher_list(ctx, options.cipher_list)) {
    //   sslerror("SSL_CTX_set_cipher_list");
    //   exit(1);
    //}
}


//! Free the global SSL context.
/*!
 * Because this prepares the global state, this should be done only
 * once per program instance.
 */
void context_free(void)
{
    SSL_CTX_free(ctx);
}


//! Initialization method that is invoked when the library is loaded.
/*!
 * returns 0 on error.
 */
int PerformStartup(void)
{
    // Make sure that we are running on Win2k.
    OSVERSIONINFO osverinfo;
    memset(&osverinfo, 0, sizeof(OSVERSIONINFO));
    osverinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (!GetVersionEx(&osverinfo) || osverinfo.dwMajorVersion < 5) {
        // must be at least version 5 (Windows 2000 or higher).
        return 0;
    }

    // Initialize Winsock for v1.1 services.
    WSADATA wsa_state;
    if (WSAStartup(0x0101, &wsa_state)!=0) {
        return 0;
    }

    // Install the API hooks.
    if (!DetourFunctionWithTrampoline(
             (PBYTE)Trampoline_connect, (PBYTE)Detour_connect)) {
        return 0;
    }
    if (!DetourFunctionWithTrampoline(
             (PBYTE)Trampoline_closesocket, (PBYTE)Detour_closesocket)) {
        return 0;
    }
    if (!DetourFunctionWithTrampoline(
             (PBYTE)Trampoline_send, (PBYTE)Detour_send)) {
        return 0;
    }
    if (!DetourFunctionWithTrampoline(
             (PBYTE)Trampoline_recv, (PBYTE)Detour_recv)) {
        return 0;
    }

    // initialize global SSL context.
    context_init();

    // initialize our locking mutex for our critical data.
    InitializeCriticalSection(&maplock);

    return 1;
}


//! Deinitialization method that is invoked when the library is unloaded.
/*!
 * returns 0 on error.
 */
int PerformShutdown(void)
{
    // shut down winsock services.
    WSACleanup();

    // free global SSL context.
    context_free();

    // unhook our calls.
    DetourRemove((PBYTE)Trampoline_connect, (PBYTE)Detour_connect);
    DetourRemove((PBYTE)Trampoline_closesocket, (PBYTE)Detour_closesocket);
    DetourRemove((PBYTE)Trampoline_send, (PBYTE)Detour_send);
    DetourRemove((PBYTE)Trampoline_recv, (PBYTE)Detour_recv);

    return 1;
}


//! Main entry point that is called when this library is loaded or unloaded
//! within the process-space of another application.
/*!
 * \param hInstDLL Handle to the DLL module.
 * \param fdwReason Reason for calling this function.  Indicates whether
 *      the library was being loaded or unloaded within the process.
 * \param lpvReserved Reserved value.
 * \return returns TRUE if it succeeds or FALSE if initialization fails.
 */
BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DOUT(("stuntour DllMain initializing\n"));
        DisableThreadLibraryCalls(hInstDLL);
        return PerformStartup();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        DOUT(("stuntour DllMain shutting down\n"));
        return PerformShutdown();
    }
    return TRUE;
}

// -----------------------------------
// mIRC specific things follow...


static HWND hwndSavedWindow = NULL;
static WNDPROC lpfnOldWindowProc = NULL;


static LRESULT CALLBACK Detour_mIRCWindowProc(
  HWND hwnd,      // handle to window
  UINT uMsg,      // message identifier
  WPARAM wParam,  // first message parameter
  LPARAM lParam   // second message parameter
)
{
    if (uMsg == WM_NCPAINT) {
        // First let the original method do its work.
        LRESULT lResult = CallWindowProc(lpfnOldWindowProc, hwnd, uMsg, wParam, lParam);

        // Now overpaint the border with a blue line.
        HDC hdc = GetDCEx(hwnd, (HRGN)wParam, DCX_WINDOW|DCX_INTERSECTRGN);
        if (hdc) {
            RECT windowrect, workrect;
            GetWindowRect(hwnd, &windowrect);

            HBRUSH hBlueBrush = CreateSolidBrush(RGB(0,0,255));
            int framewidth = GetSystemMetrics(SM_CXSIZEFRAME);
            int frameheight = GetSystemMetrics(SM_CYSIZEFRAME);

            // draw the top border.
            workrect.top = 0;
            workrect.left = 0;
            workrect.right = windowrect.right - windowrect.left;
            workrect.bottom = frameheight;
            FillRect(hdc, &workrect, hBlueBrush);

            // draw the left border.
            workrect.top = 0;
            workrect.left = 0;
            workrect.right = framewidth;
            workrect.bottom = windowrect.bottom - windowrect.top;
            FillRect(hdc, &workrect, hBlueBrush);

            // draw the right border.
            workrect.top = 0;
            workrect.left = windowrect.right - windowrect.left - framewidth;
            workrect.right = windowrect.right - windowrect.left;
            workrect.bottom = windowrect.bottom - windowrect.top;
            FillRect(hdc, &workrect, hBlueBrush);

            // draw the bottom border.
            workrect.top = windowrect.bottom - windowrect.top - frameheight;
            workrect.left = 0;
            workrect.right = windowrect.right - windowrect.left;
            workrect.bottom = windowrect.bottom - windowrect.top;
            FillRect(hdc, &workrect, hBlueBrush);

            //HPEN hBluePenWidth = CreatePen(PS_INSIDEFRAME, framewidth, RGB(0,0,255));
            //HPEN hBluePenHeight = CreatePen(PS_INSIDEFRAME, frameheight, RGB(0,0,255));
            //Rectangle(hdc, windowrect.left, windowrect.top, windowrect.right, windowrect.bottom);

            DeleteObject(hBlueBrush);
            ReleaseDC(hwnd, hdc);
        }

        // Return the original result code.
        return lResult;
    } else {
        return CallWindowProc(lpfnOldWindowProc, hwnd, uMsg, wParam, lParam);
    }
}


static void ForceNonclientRepaint(HWND hwnd)
{
    RedrawWindow(hwnd, NULL, NULL, RDW_FRAME | RDW_INVALIDATE | RDW_NOINTERNALPAINT | RDW_ERASENOW);
}


//! Method exported to mIRC that can be invoked to manually load the library.
extern "C" int __declspec(dllexport) __stdcall load_stunnel(
      HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
{
    DOUT(("mIRC callback for load_stunnel invoked\n"));
    strcpy(data, "/echo -s STunnel transparent hook is installed.");

    if (!lpfnOldWindowProc) {
        hwndSavedWindow = mWnd;
        lpfnOldWindowProc = (WNDPROC) GetWindowLong(mWnd, GWL_WNDPROC);
        SetWindowLong(mWnd, GWL_WNDPROC, (DWORD) Detour_mIRCWindowProc);
        ForceNonclientRepaint(mWnd);
    }

    return 2;       // mIRC should execute the command we returned..
}

//! Internal mIRC structure used to supervise library loading.
typedef struct {
    DWORD  mVersion;
    HWND   mHwnd;
    BOOL   mKeep;
} LOADINFO;

//! Method exported to mIRC to indicate that it should leave the library
//! always loaded, even after execution of the exported method has been run.
extern "C" void __declspec(dllexport) __stdcall LoadDll(LOADINFO *loadinfo)
{
    DOUT(("mIRC callback for LoadDll invoked\n"));
    loadinfo->mKeep = TRUE;
}

//! Method exported to mIRC to that it calls before it unloads the library.
extern "C" int __declspec(dllexport) __stdcall UnloadDll(int mTimeout)
{
    DOUT(("mIRC callback for UnloadDll invoked\n"));
    if (mTimeout == 1) {
        DOUT(("Instructing mIRC to not automatically unload library because of inactivity.\n"));
        return 0;       // return 0 to prevent unload, or 1 to allow it.
    } else {

        // Remove our windowproc subclassing hook.
        if (lpfnOldWindowProc != NULL) {
            SetWindowLong(hwndSavedWindow, GWL_WNDPROC, (DWORD) lpfnOldWindowProc);
            lpfnOldWindowProc = NULL;
            ForceNonclientRepaint(hwndSavedWindow);
        }

    }
    return 1;       // otherwise allow it.
}


static BOOL CALLBACK EnumWindowsProc(
  HWND hwnd,      // handle to parent window
  LPARAM lParam   // application-defined value
)
{
    char szClassName[64];
    if (GetClassName(hwnd, szClassName, sizeof(szClassName)) &&
        strcmp(szClassName, "mIRC32") == 0)
    {
        DWORD windowpid;
        GetWindowThreadProcessId(hwnd, &windowpid);
        if (windowpid == GetCurrentProcessId()) {
            // Found the window that is from our process.  Subclass it.

            if (!lpfnOldWindowProc) {
                hwndSavedWindow = hwnd;
                lpfnOldWindowProc = (WNDPROC) GetWindowLong(hwnd, GWL_WNDPROC);
                SetWindowLong(hwnd, GWL_WNDPROC, (DWORD) Detour_mIRCWindowProc);
                ForceNonclientRepaint(hwnd);
            }

            return FALSE;       // done enumerating.
        }
    }
    return TRUE;        // continue enumerating.
}

static void SearchAndSubclassWindow(void)
{
    if (!lpfnOldWindowProc) {
        EnumWindows(EnumWindowsProc, 0);
    }
}

// -----------------------------------

