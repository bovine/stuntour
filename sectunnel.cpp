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
// $Id: sectunnel.cpp,v 1.4 2003/07/20 04:00:21 jlawson Exp $

// Our private header
#include "stuntour.h"



//! Blocks until the specified socket is marked as being readable.
static void WaitForReadability(SOCKET socket)
{
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(socket, &rs);
    select(0, &rs, NULL, NULL, NULL);
    DOUT(("WaitForReadability: socket %d is now readable\n", (int) socket));
}

//! Blocks until the specified socket is marked as being writable.
static void WaitForWritability(SOCKET socket)
{
    fd_set ws;
    FD_ZERO(&ws);
    FD_SET(socket, &ws);
    select(0, NULL, &ws, NULL, NULL);
    DOUT(("WaitForWritability: socket %d is now writable\n", (int) socket));
}



//! Destructor for our connection interception.
/*!
 * Handles freeing of the SSL context.
 */
SecureTunnel::~SecureTunnel()
{
    if (ssl != NULL) {
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_free(ssl);
    }
}

//! Returns a pointer to the controlling SecureTunnel object, given an SSL object.
SecureTunnel *SecureTunnel::GetFromSSL(SSL *inssl)
{
    return (SecureTunnel*) SSL_get_ex_data(inssl, g_stunrefidx);
}

//! The only public way to create an instance of the SecureTunnel class.
/*!
 * \param insock Supplies the opened socket handle that should be intercepted.
 * \param inaddr Indicates the destination address to where the socket
 *          was connecting to.
 * \return Returns a pointer to the new SecureTunnel class instance.
 */
SecureTunnel *SecureTunnel::Attach(SOCKET insock, const sockaddr_in &inaddr, bool bAcceptNotConnect)
{
    // construct a new class instance.
    SecureTunnel *newobj = new SecureTunnel(insock, inaddr);
    if (!newobj) {
        WSASetLastError(WSAENOBUFS);
        return NULL;
    }

    // do the job.
    newobj->ssl = SSL_new(g_ctx);
    if (!newobj->ssl) {
        DOUT(("SSL_new failed to create a new context\n"));
        delete newobj;
        return NULL;
    }
    SSL_set_session_id_context(newobj->ssl,
                               (const unsigned char*) g_sid_ctx, (unsigned int) strlen(g_sid_ctx));

    // Store a pointer to the SecureTunnel C++ object inside of the SSL object.
    SSL_set_ex_data(newobj->ssl, g_stunrefidx, (void*) newobj);

    // Attempt to use the most recent id in the session cache.
    if ( g_ctx->session_cache_head ) {
        if ( ! SSL_set_session(newobj->ssl, g_ctx->session_cache_head) ) {
            DOUT(("Cannot set SSL session id to most recent used\n"));
        }
    }

    // Associate the socket with the SSL object.
    SSL_set_fd(newobj->ssl, (int) insock);


    // make blocking mode sockets not return until completion.
    SSL_set_mode(newobj->ssl, SSL_MODE_AUTO_RETRY);
            // TODO: maybe use SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER


    int numval;
    if (bAcceptNotConnect) {
        // Sets ssl to work in server mode.
        SSL_set_accept_state(newobj->ssl);
AcceptAgain:
        // Try to connect the ssl tunnel.
        numval = SSL_accept(newobj->ssl);
    } else {
        // Sets ssl to work in client mode.
        SSL_set_connect_state(newobj->ssl);

        // Try to connect the ssl tunnel.
        numval = SSL_connect(newobj->ssl);
    }
    if (numval <= 0) {
        int sslerror = (int) SSL_get_error(newobj->ssl, numval);
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
                DOUT(("SSL_connect/SSL_accept deferred SSL establishment because of a %s condition.\n",
                      TranslateSSLError(sslerror) ));
                if (bAcceptNotConnect) {
                    if (sslerror == SSL_ERROR_WANT_WRITE) {
                        WaitForWritability(insock);
                        DOUT(("Socket is now writable, retrying accept.\n"));
                        goto AcceptAgain;
                    } else if (sslerror == SSL_ERROR_WANT_READ) {
                        WaitForReadability(insock);
                        DOUT(("Socket is now readable, retrying accept.\n"));
                        goto AcceptAgain;
                    }
                }
                break;

            case SSL_ERROR_SYSCALL:
                if (wsagle == WSAENOTCONN) {
                    // not an error, but the connection could not be established yet.
                    // (probably socket is non-blocking and the connect() is not done.)
                    DOUT(("SSL_connect/SSL_accept deferred SSL establishment because not yet connected.\n"));
                    break;
                }
                // otherwise drop through to default case.

            default: {
                DOUT(("SSL_connect/SSL_accept returned failure (%s, %s)\n",
                      TranslateSSLError(sslerror), TranslateWinsockError(wsagle)));
#ifndef NDEBUG
                FILE *fp = fopen("sslerror.txt", "wt");
                if (fp != NULL) {
                    ERR_print_errors_fp(fp);
                    fclose(fp);
                }
#endif
                delete newobj;
                return NULL;
            }
        }
    }

    return newobj;
}

//! Returns a string representation of the address and port of the
//! remote side of the connection.
std::string SecureTunnel::GetAddressAndPort() const
{
    char buf[64];
    _snprintf(buf, sizeof(buf), "%s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    return buf;
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
 *      argument 'len' requested (Note: Winsock send() doesn't guarantee that).
 */
int SecureTunnel::Send(const char FAR *buf, int len)
{
    // catch easy argument errors.
    if (!buf || len < 0 || IsBadReadPtr(buf, len)) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    if (len == 0) return 0;

#ifdef PLEASEBLOCK
    // Try performing the desired write.  If the socket is in
    // blocking mode then this operation will block until the entire
    // send (and any necessary protocol-level reads) is complete.
TryAgain:
    int numwrote = SSL_write(ssl, buf, len);
#else
    // Instead of actually sending the data we were just called with,
    // just append it to the end of our current secondary outgoing queue.
    morependingsend.append(buf, len);

    // If the primary outgoing queue is empty, then transfer everything
    // from the secondary outgoing queue into the primary one.
    if (pendingsend.empty()) {
        pendingsend = morependingsend;
        morependingsend.erase();
    }

TryAgain:
    // Try to send the primary outgoing queue (this may possibly be a 
    // continued attempt to do so, if the primary queue came from a 
    // previous call).
    write_wants_read = false;
    assert(!pendingsend.empty());
    int numwrote = SSL_write(ssl, pendingsend.c_str(), (int) pendingsend.size());
#endif


    // Handle the return code and error code from the write attempt.
    int sslerror = (int) SSL_get_error(ssl, numwrote);
    switch (sslerror) {
#ifdef PLEASEBLOCK
        case SSL_ERROR_NONE:
            assert(numwrote > 0 && numwrote == len);
            return numwrote;

        case SSL_ERROR_WANT_WRITE:
            WaitForWritability(sock);
            goto TryAgain;

        case SSL_ERROR_WANT_READ:
            WaitForReadability(sock);
            goto TryAgain;
#else
        case SSL_ERROR_NONE:
            assert(numwrote > 0 && numwrote == pendingsend.size());
            pendingsend.erase();
            DOUT(("SecureTunnel::Send -- SSL_write successfully sent entire contents of primary queue (was %d bytes)\n", numwrote));
            DOUT(("SecureTunnel::Send -- There are %d bytes in primary queue, %d bytes in secondary queue\n", pendingsend.size(), morependingsend.size()));
            if (!morependingsend.empty()) {
                pendingsend = morependingsend;
                morependingsend.erase();
                DOUT(("SecureTunnel::Send -- Looping again to attempt to send secondary queue\n"));
                goto TryAgain;
            }
            return len;     // lie and say what was actually requested was sent.

        case SSL_ERROR_WANT_READ:
            write_wants_read = true;
            DOUT(("SecureTunnel::Send -- SSL_write returned %s - transmission queued, but success being returned\n",
                  TranslateSSLError(sslerror) ));
            DOUT(("SecureTunnel::Send -- There are %d bytes in primary queue, %d bytes in secondary queue\n", pendingsend.size(), morependingsend.size()));
            return len;     // lie and say what was actually requested was sent.

        case SSL_ERROR_WANT_WRITE:
            DOUT(("SecureTunnel::Send -- SSL_write returned %s - transmission queued, but success being returned\n",
                  TranslateSSLError(sslerror) ));
            DOUT(("SecureTunnel::Send -- There are %d bytes in primary queue, %d bytes in secondary queue\n", pendingsend.size(), morependingsend.size()));
            return len;     // lie and say what was actually requested was sent.
#endif

        case SSL_ERROR_SYSCALL:
            DOUT(("SecureTunnel::Send -- SSL_write (socket error)\n"));
            WSASetLastError(WSAENETDOWN);
            return SOCKET_ERROR;

        case SSL_ERROR_ZERO_RETURN:
            DOUT(("SecureTunnel::Send -- SSL closed while writing\n"));
            WSASetLastError(WSAENOTCONN);
            return 0;   // was -1

        case SSL_ERROR_SSL:
            DOUT(("SecureTunnel::Send -- SSL_write returned general failure\n"));
            WSASetLastError(WSAENETDOWN);
            return SOCKET_ERROR;

        default:
            DOUT(("SecureTunnel::Send -- Unhandled SSL Error (%s, %s)\n",
                  TranslateSSLError(sslerror), TranslateWinsockError(WSAGetLastError()) ));
            WSASetLastError(WSAENETDOWN);
            return SOCKET_ERROR;
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
        return SOCKET_ERROR;
    }
    if (len == 0) return 0;


#ifndef PLEASEBLOCK
    DOUT(("SecureTunnel::Recv -- There are %d bytes in primary outgoing queue, %d bytes in secondary outgoing queue\n", pendingsend.size(), morependingsend.size()));

    // if a previous write attempt was blocking on the need to read, then 
    // try fulfilling the last write attempt again (since presumably our
    // caller knows that the socket is now readable, otherwise Recv() 
    // wouldn't have been called).
    if (/*write_wants_read &&*/ !pendingsend.empty()) {
        DOUT(("SecureTunnel::Recv -- retrying previous SSL_write\n"));

        int numwrote = SSL_write(ssl, pendingsend.c_str(), (int) pendingsend.size());
        int sslerror = (int) SSL_get_error(ssl, numwrote);
        switch (sslerror) {
            case SSL_ERROR_NONE:
                DOUT(("SecureTunnel::Recv -- previously blocked SSL_write completed\n"));
                assert(numwrote > 0 && numwrote == pendingsend.size());
                pendingsend.erase();
                if (!morependingsend.empty()) {
                    pendingsend = morependingsend;
                    morependingsend.erase();
                }
                DOUT(("SecureTunnel::Recv -- There are %d bytes in primary outgoing queue, %d bytes in secondary outgoing queue\n", pendingsend.size(), morependingsend.size()));
                write_wants_read = false;
                break;      // great, now try actually doing the read request.

            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                DOUT(("SecureTunnel::Recv -- previous SSL_write would block\n"));
                WSASetLastError(WSAEWOULDBLOCK);
                return SOCKET_ERROR;

            case SSL_ERROR_SYSCALL:
                DOUT(("SecureTunnel::Recv -- previous SSL_write (socket error)\n"));
                WSASetLastError(WSAENETDOWN);
                return SOCKET_ERROR;

            case SSL_ERROR_ZERO_RETURN:
                DOUT(("SecureTunnel::Recv -- previous SSL closed while writing\n"));
                WSASetLastError(WSAENOTCONN);
                return 0;   // was -1

            case SSL_ERROR_SSL:
                DOUT(("SecureTunnel::Recv -- previous SSL_write returned general failure\n"));
                WSASetLastError(WSAENETDOWN);
                return SOCKET_ERROR;

            default:
                DOUT(("SecureTunnel::Recv -- previous SSL_write Unhandled SSL Error (%s, %s)\n",
                    TranslateSSLError(sslerror), TranslateWinsockError(WSAGetLastError()) ));
                WSASetLastError(WSAENETDOWN);
                return SOCKET_ERROR;
        }
    }
#endif


#ifdef PLEASEBLOCK
    // Try performing the desired read.  If the socket is in
    // blocking mode then this operation will block until the entire
    // receive (and any necessary protocol-level write) is complete.
TryAgain:
    int numread = SSL_read(ssl, buf, len);
#else
    // Perform the actual read.
    int numread = SSL_read(ssl, buf, len);
#endif


    // Handle the return code and error code from the write attempt.
    int sslerror = (int) SSL_get_error(ssl, numread);
    switch (sslerror) {
        case SSL_ERROR_NONE:
            assert(numread > 0 && numread <= len);
            return numread;

        case SSL_ERROR_WANT_WRITE:
#ifdef PLEASEBLOCK
            WaitForWritability(sock);
            goto TryAgain;
#else
            // otherwise drop-through.
#endif
        case SSL_ERROR_WANT_READ:
            DOUT(("SecureTunnel::Recv -- SSL_read returned %s - retry later\n",
                  TranslateSSLError(sslerror) ));
            WSASetLastError(WSAEWOULDBLOCK);
            return SOCKET_ERROR;

        case SSL_ERROR_SYSCALL:
            DOUT(("SecureTunnel::Recv -- SSL_read (socket error)\n"));
            WSASetLastError(WSAENETDOWN);
            return SOCKET_ERROR;

        case SSL_ERROR_ZERO_RETURN:
            DOUT(("SecureTunnel::Recv -- SSL closed while reading\n"));
            WSASetLastError(WSAENOTCONN);
            return 0;

        case SSL_ERROR_SSL:
            DOUT(("SecureTunnel::Recv -- SSL_read returned general failure\n"));
            WSASetLastError(WSAENETDOWN);
            return SOCKET_ERROR;

        default:
            DOUT(("SecureTunnel::Recv -- Unhandled SSL Error (%s, %s)\n",
                TranslateSSLError(sslerror), TranslateWinsockError(WSAGetLastError()) ));
            WSASetLastError(WSAENETDOWN);
            return SOCKET_ERROR;
    }
}
