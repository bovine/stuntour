// Transparent SSL Tunnel hooking.
// Jeff Lawson <jlawson@bovine.net>
// $Id: stuntour.cpp,v 1.3 2003/02/03 06:34:16 jlawson Exp $

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

// Our private header
#include "stuntour.h"



//! Defines what destination port numbers are automatically redirected
//! through an SSL-tunnel.
static unsigned short intercepted_ports[128] = {
    994,    // standard RFC allocated port for IRCS
    7000, 7001, 7002, 7003,     // blabber.net and others
    6657,   // sirc.hu
    6697,   // axenet
    9998, 9999,   // suidnet, chatsages
    6999,   // biteme-irc
    6000,   // wondernet
    9000,   // chatchannel.org
    25401,
    0     // terminating entry in list (don't remove).
};


//! Global mutex variables to allow thread-safe access to the map.
static CRITICAL_SECTION maplock;

//! This map stores all open intercepted connections.
typedef std::map<SOCKET, SecureTunnel*> securetunnelmap_t;
static securetunnelmap_t SecureTunnelMap;

//! global OpenSSL context.
SSL_CTX *g_ctx = NULL;

//! Allocated application-specific index for storing a SecureTunnel 
//! pointer refererence within an OpenSSL SSL object.
int g_stunrefidx = 0;

//! Unique context identifier used to initialize OpenSSL with.
const char g_sid_ctx[] = "StunTour SID";



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
const char *TranslateSSLError(int errorcode) {
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
            _snprintf(buffer, sizeof(buffer), "SSL=%d", errorcode);
            return buffer;
        }
    }
}

//! Return a textual string representing of an OpenSSL X.509 certificate verification error code.
const char *TranslateX509Error(int errorcode) {
    switch (errorcode) {
        MAPERROR(X509_V_OK);
        MAPERROR(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT);
        MAPERROR(X509_V_ERR_UNABLE_TO_GET_CRL);
        MAPERROR(X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE);
        MAPERROR(X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE);
        MAPERROR(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY);
        MAPERROR(X509_V_ERR_CERT_SIGNATURE_FAILURE);
        MAPERROR(X509_V_ERR_CRL_SIGNATURE_FAILURE);
        MAPERROR(X509_V_ERR_CERT_NOT_YET_VALID);
        MAPERROR(X509_V_ERR_CERT_HAS_EXPIRED);
        MAPERROR(X509_V_ERR_CRL_NOT_YET_VALID);
        MAPERROR(X509_V_ERR_CRL_HAS_EXPIRED);
        MAPERROR(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD);
        MAPERROR(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
        MAPERROR(X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD);
        MAPERROR(X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
        MAPERROR(X509_V_ERR_OUT_OF_MEM);
        MAPERROR(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
        MAPERROR(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN);
        MAPERROR(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
        MAPERROR(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE);
        MAPERROR(X509_V_ERR_CERT_CHAIN_TOO_LONG);
        MAPERROR(X509_V_ERR_CERT_REVOKED);
        MAPERROR(X509_V_ERR_INVALID_CA);
        MAPERROR(X509_V_ERR_PATH_LENGTH_EXCEEDED);
        MAPERROR(X509_V_ERR_INVALID_PURPOSE);
        MAPERROR(X509_V_ERR_CERT_UNTRUSTED);
        MAPERROR(X509_V_ERR_CERT_REJECTED);
        MAPERROR(X509_V_ERR_SUBJECT_ISSUER_MISMATCH);
        MAPERROR(X509_V_ERR_AKID_SKID_MISMATCH);
        MAPERROR(X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);
        MAPERROR(X509_V_ERR_KEYUSAGE_NO_CERTSIGN);
        MAPERROR(X509_V_ERR_APPLICATION_VERIFICATION);
        default: {
            static char buffer[20];
            _snprintf(buffer, sizeof(buffer), "X509=%d", errorcode);
            return buffer;
        }
    }
}

//! Return a textual string representing of a Winsock error code.
const char *TranslateWinsockError(int errorcode) {
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
            _snprintf(buffer, sizeof(buffer), "WSA=%d", errorcode);
            return buffer;
        }
    }
}


/*
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
*/


//! Returns a copy of the input buffer with non-printable characters masked.
static std::string FilterPrintableBuffer(const void *buf, size_t buflen)
{
    std::string newbuf((const char*)buf, buflen);
    for (size_t i = 0; i < buflen; i++) {
        if (!isprint(newbuf[i])) newbuf[i] = '.';
    }
    return newbuf;
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
    // Check the port in our built-in list of ports to hook.
    for (int i = 0; intercepted_ports[i] != 0; i++) {
        if (intercepted_ports[i] == portnum) return true;
    }
    return false;
}

//! Generates a string containing a list of all ports being hooked.
std::string QueryInterceptedPortListSpace()
{
    std::string output;
    for (int i = 0; intercepted_ports[i] != 0; i++) {
        char buf[32];
        _snprintf(buf, sizeof(buf), "%u ", intercepted_ports[i]);
        output += buf;
    }
    return output;
}

//! Generates a string containing a list of all ports being hooked.
static std::string QueryInterceptedPortListNull()
{
    std::string output;
    for (int i = 0; intercepted_ports[i] != 0; i++) {
        char buf[32];
        _snprintf(buf, sizeof(buf), "%u", intercepted_ports[i]);
        output.append(buf, strlen(buf) + 1);
    }
    output.append("\0", 1);     // ensure an extra, double-null
    return output;
}


//! Adds an additional port number to the internal list.
bool AddInterceptedPort(unsigned short portnum)
{
    if (portnum == 0) {
        return false;        // port cannot be zero.
    }

    // Check the port in our built-in list of ports to hook.
    for (int i = 0; i < sizeof(intercepted_ports) / sizeof(intercepted_ports[0]) - 1; i++) {
        if (intercepted_ports[i] == portnum) {
            DOUT(("AddInterceptedPort: port %u is already added\n", portnum));
            return true;        // already in list, nothing needs to be done.
        }
        if (intercepted_ports[i] == 0) {
            intercepted_ports[i] = portnum;
            DOUT(("AddInterceptedPort: successfully added port %u\n", portnum));
            return true;        // successfully added.
        }
    }
    DOUT(("AddInterceptedPort: could not add port %u because list is full\n", portnum));
    return false;       // port could not be added (due to maximum size).
}


//! Loads the initial list of intercepted ports from the registry.
static void InitializeInterceptedPortList(void)
{
    HKEY hkeySettings;
    if (RegCreateKeyEx(HKEY_CURRENT_USER, REGKEYBASE, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &hkeySettings, NULL) != ERROR_SUCCESS) {
        return;
    }

    DWORD dwType;
    char buffer[512];
    DWORD dwBufferSize = sizeof(buffer);
    if (RegQueryValueEx(hkeySettings, "Ports", NULL, &dwType, (LPBYTE) buffer, &dwBufferSize) == ERROR_SUCCESS) {
        if (dwType == REG_MULTI_SZ || dwType == REG_SZ) {
            char *endp = buffer + dwBufferSize;
            for (char *p = buffer; p < endp; ) {
                if (*p == '\0' || isspace(*p)) {
                    p++; continue;
                } else if (isdigit(*p)) {
                    char *skip = p + 1;
                    while (isdigit(*skip) && skip < endp) {
                        skip++;
                    }
                    *skip = '\0';

                    unsigned short portnum = (unsigned short) atoi(p);
                    AddInterceptedPort(portnum);
                    p = skip;
                } else {
                    p++;
                }
            }
        }
    }

    std::string newlist = QueryInterceptedPortListNull();
    RegSetValueEx(hkeySettings, "Ports", 0, REG_MULTI_SZ, 
        reinterpret_cast<const BYTE *>(newlist.c_str()), 
        static_cast<DWORD>(newlist.size()) );

    RegCloseKey(hkeySettings);
}



//! This is our hook that is installed in place of the normal
//! Winsock connect() API.
static int WINAPI Detour_connect(
        SOCKET insock, const struct sockaddr FAR *name, int namelen)
{
    DOUT(("Detour_connect called\n"));

#ifdef SECUREBLUEWINDOW
    SearchAndSubclassWindow();
#endif

    // If any of the arguments look bogus, then immediately bail out and
    // just let the original Winsock method handle it.
    if (!insock || 
        insock == INVALID_SOCKET || 
        !name ||
        namelen < sizeof(sockaddr_in) || 
        name->sa_family != AF_INET) 
    {
        // This looks like a bogus connection attempt, so we'll ignore it
        // and just let the system API handle the error code.
        DOUT(("Detour_connect: bypassing connect, due to bogus inputs\n"));
        return Trampoline_connect(insock, name, namelen);
    }


    // Decide if we should intercept this connection or not.
    const sockaddr_in &inaddr = *(const sockaddr_in *)name;
    if (!IsInterceptedPort(ntohs(inaddr.sin_port))) 
    {
        // This isn't a connection to a port that we are configured to hook.
        DOUT(("Detour_connect: bypassing connect, due to non-intercepted port\n"));
        return Trampoline_connect(insock, name, namelen);
    }


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
    SecureTunnel *stun = SecureTunnel::Attach(insock, inaddr);
    if (!stun) {
        // We expect Attach() to call WSASetLastError() for us.
        // Note that for this case, the socket is actually still left open!
        DOUT(("Detour_connect: failed to attach\n"));
        return SOCKET_ERROR;
    }

    // Add the tracking information to our storage container.
#ifdef USE_MAKEPAIR
    SecureTunnelMap.insert(std::make_pair(insock, stun));
#else
    SecureTunnelMap.insert(std::pair<const SOCKET, SecureTunnel*>(insock, stun));
#endif


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
    DOUT(("-----\n"));
            DOUT(("Detour_send: intercepting SSL send for socket %d\n", (int) insock));
            DOUT(("Detour_send: intercepting SSL data is: %s\n", FilterPrintableBuffer(buf, len).c_str() ));
            retval = stun->Send(buf, len);
            DOUT(("Detour_send: intercepted SSL send for socket %d returned %d\n", (int) insock, retval));
    DOUT(("-----\n"));
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
            DOUT(("  Detour_send: nested send of %d bytes for socket %d\n", (int) len, (int) insock));
        } else {
    DOUT(("-----\n"));
            DOUT(("Detour_send: invoking pass-thru send of %d bytes for socket %d\n", (int) len, (int) insock));
        }
        retval = Trampoline_send(insock, buf, len, flags);
        if (bNested) {
            DOUT(("  Detour_send: nested send returned %d (%s)\n",
                  retval, TranslateWinsockError(WSAGetLastError())));
        } else {
            DOUT(("Detour_send: pass-thru for send returned %d (%s)\n",
                  retval, TranslateWinsockError(WSAGetLastError())));
    DOUT(("-----\n"));
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
    DOUT(("-----\n"));
            DOUT(("Detour_recv: intercepting SSL recv for socket %d\n", (int) insock));
            retval = stun->Recv(buf, len);
            DOUT(("Detour_recv: intercepted SSL recv for socket %d returned %d (%s)\n", 
                    (int) insock, retval, TranslateWinsockError(WSAGetLastError()) ));
    DOUT(("-----\n"));
            bHandled = true;
        }
    } else {
        bNested = true;
    }
    LeaveCriticalSection(&maplock);

    // If this wasn't a managed socket, then do the normal thing for it.
    if (!bHandled) {
        if (bNested) {
            DOUT(("  Detour_recv: nested recv for socket %d\n", (int) insock));
        } else {
    DOUT(("-----\n"));
            DOUT(("Detour_recv: invoking pass-thru recv for socket %d\n", (int) insock));
        }
        retval = Trampoline_recv(insock, buf, len, flags);
        if (bNested) {
            DOUT(("  Detour_recv: nested recv returned %d (%s)\n",
                  retval, TranslateWinsockError(WSAGetLastError())));
        } else {
            DOUT(("Detour_recv: pass-thru for recv returned %d (%s)\n",
                  retval, TranslateWinsockError(WSAGetLastError())));
    DOUT(("-----\n"));
        }
    }
    return retval;
}


//! Callback invoked by OpenSSL during certificate verification.
/*!
 * This callback provides the ability to ask the user to confirm a 
 * new connection to a server.
 */

/* This needs to be called sometime later??
if(SSL_get_verify_result(ssl)!=X509_V_OK)
    berr_exit("Certificate doesn’t verify");
*/
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    DOUT(("verify_callback entered\n"));

    // Retrieve full details about certificate being verified.
    X509 *err_cert = X509_STORE_CTX_get_current_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    SSL *ssl = (SSL*) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    SecureTunnel *stun = SecureTunnel::GetFromSSL(ssl);


    char buf[256];
    std::string textbuffer;

    // Add the destination of the connection.
    textbuffer.append("Destination:  ");
    textbuffer.append(stun->GetAddressAndPort());
    textbuffer.append("\n\n");

    // Add the hostname and subject name do not match.
    textbuffer.append("Partial Subject Name:\n");
    X509_NAME_get_text_by_NID(X509_get_subject_name(err_cert), NID_commonName, buf, sizeof(buf));
    textbuffer.append(buf);
    textbuffer.append("\n\n");

    // Add the name to which the certificate was issued.
    textbuffer.append("Full Subject Name:\n");
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));
    textbuffer.append(buf);
    textbuffer.append("\n\n");




    if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
        textbuffer.append("Unknown Certificate Issuer:\n");
        X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, sizeof(buf));
        textbuffer.append(buf);
        textbuffer.append("\n\n");
    }

    /*
    if (depth > mydata->verify_depth) {
        preverify_ok = 0;
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err);
    }
    */
    if (!preverify_ok) {
        _snprintf(buf, sizeof(buf), "Verify error: %s (%s)\n",
                X509_verify_cert_error_string(err), TranslateX509Error(err));
        textbuffer.append(buf);

        _snprintf(buf, sizeof(buf), "Chain verify depth: %d\n\n", depth);
        textbuffer.append(buf);
    }

    DOUT(("verify_callback confirmation text:\n%s\n", textbuffer.c_str()));
    
    if (preverify_ok) {
        //MessageBox(NULL, textbuffer.c_str(), "Identity verified", MB_OK | MB_ICONINFORMATION);
        DOUT(("verify_callback implicitly confirming connection\n"));
        return 1;       // allow connection.
    } else if (MessageBox(NULL, textbuffer.c_str(), "Continue connecting?", MB_YESNO | MB_ICONEXCLAMATION) == IDYES) {
        DOUT(("verify_callback confirming connection continuation\n"));
        return 1;       // allow connection.
    } else {
        DOUT(("verify_callback rejecting connection\n"));
        return 0;       // reject connection.
    }
}


//! initialize the global SSL context.
/*!
 * Because this prepares the global state, this should be done only
 * once per program instance.
 */
static void context_init(void)
{
    // seed the random number generator.
    RAND_screen();
    if ( !RAND_status() ) {
        DOUT(("RAND_screen failed to sufficiently seed PRNG"));
    }

    // initialize other OpenSSL items.
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    g_ctx = SSL_CTX_new(SSLv3_client_method());
    if (!g_ctx) {
        DOUT(("SSL_CTX_new failed to allocate new context\n"));
        return;
    }

    // allocate an application-specific index for storing a pointer to 
    // the 'SecureTunnel' object inside of each 'SSL' object.
    g_stunrefidx = SSL_get_ex_new_index(0, "SecureTunnel reference", NULL, NULL, NULL);

    // initialize the certificate cache.
    SSL_CTX_set_session_cache_mode(g_ctx, SSL_SESS_CACHE_BOTH);
    //SSL_CTX_set_timeout(g_ctx, options.session_timeout);

    // enable callback verification during the certificate check.
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER, verify_callback);
    //SSL_CTX_load_verify_locations()
    //SSL_CTX_set_info_callback(g_ctx, info_callback);
    //SSL_CTX_set_options(g_ctx, SSL_OP_ALL);
 	//SSL_CTX_set_default_verify_paths(g_ctx);


    //if (!SSL_CTX_set_cipher_list(g_ctx, options.cipher_list)) {
    //   sslerror("SSL_CTX_set_cipher_list");
    //   exit(1);
    //}
}


//! Free the global SSL context.
/*!
 * Should be done before process termination.
 */
static void context_free(void)
{
    SSL_CTX_free(g_ctx);
}


//! Initialization method that is invoked when the library is loaded.
/*!
 * returns 0 on error.
 */
static int PerformStartup(void)
{
    DOUT(("stuntour PerformStartup beginning\n"));
    
    // Make sure that we are running on Win2k.
    OSVERSIONINFO osverinfo;
    memset(&osverinfo, 0, sizeof(OSVERSIONINFO));
    osverinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (!GetVersionEx(&osverinfo) || 
      osverinfo.dwPlatformId != VER_PLATFORM_WIN32_NT ||
      osverinfo.dwMajorVersion < 5)
    {
        // must be at least version 5 (Windows 2000 or higher).
        DOUT(("stuntour PerformStartup version check failed\n"));
        return 0;
    }

    // Initialize Winsock for v1.1 services.
    WSADATA wsa_state;
    if (WSAStartup(MAKEWORD(1, 1), &wsa_state) != 0) {
        DOUT(("stuntour PerformStartup Winsock init failed\n"));
        return 0;
    }

    // initialize global SSL context.
    context_init();

    // read in the list of additional ports from the registry
    InitializeInterceptedPortList();

    // initialize our locking mutex for our critical data.
    InitializeCriticalSection(&maplock);

    // Install the API hooks.
    if (!DetourFunctionWithTrampoline(
                (PBYTE)Trampoline_connect, (PBYTE)Detour_connect)) {
        DOUT(("stuntour PerformStartup Trampoline_connect failed\n"));
        return 0;
    }
    if (!DetourFunctionWithTrampoline(
                (PBYTE)Trampoline_closesocket, (PBYTE)Detour_closesocket)) {
        DOUT(("stuntour PerformStartup Trampoline_closesocket failed\n"));
        return 0;
    }
    if (!DetourFunctionWithTrampoline(
                (PBYTE)Trampoline_send, (PBYTE)Detour_send)) {
        DOUT(("stuntour PerformStartup Trampoline_send failed\n"));
        return 0;
    }
    if (!DetourFunctionWithTrampoline(
                (PBYTE)Trampoline_recv, (PBYTE)Detour_recv)) {
        DOUT(("stuntour PerformStartup Trampoline_recv failed\n"));
        return 0;
    }

    DOUT(("stuntour PerformStartup complete\n"));
    return 1;
}


//! Deinitialization method that is invoked when the library is unloaded.
/*!
 * \return Returns 0 on error.
 */
static int PerformShutdown(void)
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

    return 1;       // success
}


//! Main entry point that is called when this library is loaded or unloaded
//! within the process-space of another application.
/*!
 * \param hInstDLL Handle to the DLL module.
 * \param fdwReason Reason for calling this function.  Indicates whether
 *      the library was being loaded or unloaded within the process.
 * \param lpvReserved Reserved value.
 * \return Returns TRUE if it succeeds or FALSE if initialization fails.
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


