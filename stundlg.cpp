// Transparent SSL Tunnel hooking.
// Jeff Lawson <jlawson@bovine.net>
// $Id: stundlg.cpp,v 1.2 2003/05/18 21:33:43 jlawson Exp $

#include "stuntour.h"
#include "resource.h"


#define WM_STUNTOUR_CLOSE       (WM_USER + 1024)


//! Handle to the last-opened confirmation dialog.  Only one is permitted open at any time.
static HWND hwndLastConfirmDialog = NULL;


//! Force all waiting messages for the specified window to be processed immediately.
static void PumpWaitingMessages(HWND hwnd)
{
    MSG msg;
    while (PeekMessage(&msg, hwnd, 0, 0, PM_REMOVE)) {
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
}

//! Convert a binary buffer into a hexadecimal textual string.
std::string bin2hex(unsigned char *buffer, size_t buflen)
{
    std::string retval;
    if (buffer != NULL && buflen > 0) {
        for (unsigned i = 0; i < buflen; i++) {
            char hexbuf[3];
            _snprintf(hexbuf, sizeof(hexbuf), "%02X", buffer[i]);
            retval.append(hexbuf);
        }
    }
    return retval;
}


//! Decides whether the certificate should be implicitly allowed without any 
//! confirmation from the user.
/*!
 * \param confinfo Pointer to structure containing identity of certificate.
 * \return Returns true if the connection should be allowed without prompting.
 *        Otherwise the user should be asked whether to allow it.
 *
 * \sa ConfirmCertificateDialog
 */
bool CheckAllowCertificate(ConfirmationDialogData *confinfo)
{
    DOUT(("stundlg: CheckAllowCertificate called\n"));

    // OpenSSL will sometimes call the certificate verification routine 
    // multiple times when establishing a connection, but we should not
    // prompt the user to confirm the same connection multiple times.
    if (confinfo->stunnel->bAccepted) {
        DOUT(("stundlg: Returning acceptance since this stunnel object has already been authorized.\n"));
        return true;
    }

#if 0
    // If you trust OpenSSL's pre-verification step, then accept it.
    if (confinfo->preverify_ok) {
        DOUT(("stundlg: Returning acceptance since certificate preverification was ok.\n"));
        return true;
    }
#endif


#if 0
    // Check the registry setting that forces us to accept all certificates.
    // This is a pretty insecure mode since it allows anything.
    do {
        HKEY hkeySettings;
        if (RegCreateKeyEx(HKEY_CURRENT_USER, REGKEYBASE, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &hkeySettings, NULL) != ERROR_SUCCESS) {
            break;
        }
        DWORD dwType;
        char buffer[512];
        DWORD dwBufferSize = sizeof(buffer);
        bool AlwaysAllowAnyCert = false;
        if (RegQueryValueEx(hkeySettings, "AlwaysAllowAnyCert", NULL, &dwType, (LPBYTE) buffer, &dwBufferSize) == ERROR_SUCCESS && (dwType == REG_DWORD)) {
            AlwaysAllowAnyCert = (*reinterpret_cast<DWORD*>(buffer) != 0);
        } else {
            *reinterpret_cast<DWORD*>(buffer) = (AlwaysAllowAnyCert ? 1 : 0);

            RegSetValueEx(hkeySettings, "AlwaysAllowAnyCert", 0, REG_DWORD, 
                reinterpret_cast<const BYTE *>(buffer), sizeof(DWORD) );
        }
        RegCloseKey(hkeySettings);
        if (AlwaysAllowAnyCert) {
            DOUT(("stundlg: Returning acceptance since the AlwaysAllowAnyCert mode is enabled.\n"));
            return true;
        }
    } while (0);
#endif

    // Check the registry to see if the user has explicitly accepted this 
    // certificate in the past.
	unsigned char tmphash[SHA_DIGEST_LENGTH];
    if (X509_pubkey_digest(confinfo->err_cert, EVP_sha1(), tmphash, NULL) != 0) {
        std::string hexhash = bin2hex(tmphash, SHA_DIGEST_LENGTH);
        std::string regpath = std::string(REGKEYBASE "\\AllowedCerts\\").append(hexhash);
        HKEY hkeyAllowed;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, regpath.c_str(), 0, KEY_READ, &hkeyAllowed) == ERROR_SUCCESS) {
            DOUT(("stundlg: Returning acceptance for persisted certificate.\n"));
            RegCloseKey(hkeyAllowed);
            return true;
        }
    }

    return false;           // don't know, so prompt the user about what to do.
}

//! Save the fact that the user has manually accepted a certificate.
void PersistAcceptanceForCertificate(ConfirmationDialogData *confinfo)
{
	unsigned char tmphash[SHA_DIGEST_LENGTH];
    if (X509_pubkey_digest(confinfo->err_cert, EVP_sha1(), tmphash, NULL) != 0) {
        std::string hexhash = bin2hex(tmphash, SHA_DIGEST_LENGTH);
        std::string regpath = std::string(REGKEYBASE "\\AllowedCerts\\").append(hexhash);
        HKEY hkeyAllowed;
        if (RegCreateKeyEx(HKEY_CURRENT_USER, regpath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &hkeyAllowed, NULL) == ERROR_SUCCESS) {
            DOUT(("stundlg: Saving acceptance for persisted certificate.\n"));

            char buf[256];
            X509_NAME_oneline(X509_get_subject_name(confinfo->err_cert), buf, sizeof(buf));
            RegSetValueEx(hkeyAllowed, "SubjectName", 0, REG_SZ, reinterpret_cast<const BYTE*>(buf), static_cast<DWORD>(strlen(buf) + 1));

            RegCloseKey(hkeyAllowed);
        }
    }
}


//! Construct a text string providing as much detail as possible for the 
//! user to safely decide whether to accept the connection.
/*!
 * The resulting text contains information about the certificate, the issuer 
 * of the certificate, the connection, and the automated pre-validation 
 * done by OpenSSL.
 *
 * \param certinfo Pointer to structure containing identity of certificate.
 * \return Returns a string containing the text to be displayed.
 */
static std::string BuildConfirmationDetails(ConfirmationDialogData *confinfo)
{
    char buf[256];

    // Add the destination (IP Address and port) of the connection.
    std::string strDestination = confinfo->stunnel->GetAddressAndPort();

    // Add the name to which the certificate was issued.
    X509_NAME_get_text_by_NID(X509_get_subject_name(confinfo->err_cert), NID_commonName, buf, sizeof(buf));
    std::string strCommonName = buf;
    X509_NAME_oneline(X509_get_subject_name(confinfo->err_cert), buf, sizeof(buf));
    std::string strSubjectName = buf;

    // Get the name of the issuer of the certificate.
    X509_NAME_oneline(X509_get_issuer_name(confinfo->err_cert), buf, sizeof(buf));
    std::string strIssuerName = buf;
    bool bIssuerKnown;
    if (!confinfo->preverify_ok && (confinfo->err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
        bIssuerKnown = false;
    } else {
        bIssuerKnown = true;
    }

    std::string textbuffer;
    textbuffer.append("Destination:  ");
    textbuffer.append(strDestination);
    textbuffer.append("\r\n\r\n");

    textbuffer.append("Partial Subject Name:\r\n");
    textbuffer.append(strCommonName);
    textbuffer.append("\r\n\r\n");

    textbuffer.append("Full Subject Name:\r\n");
    textbuffer.append(strSubjectName);
    textbuffer.append("\r\n\r\n");

    textbuffer.append(bIssuerKnown ? "Known Issuer:\r\n" : "Unknown Issuer:\r\n");
    textbuffer.append(strIssuerName);
    textbuffer.append("\r\n\r\n");

    /*
    if (confinfo->depth > mydata->verify_depth) {
        confinfo->preverify_ok = 0;
        confinfo->err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, confinfo->err);
    }
    */

    if (!confinfo->preverify_ok) {
        _snprintf(buf, sizeof(buf), "Verify error: %s (%s)\n",
                X509_verify_cert_error_string(confinfo->err), TranslateX509Error(confinfo->err));
        textbuffer.append(buf);

        _snprintf(buf, sizeof(buf), "Chain verify depth: %d\n\n", confinfo->depth);
        textbuffer.append(buf);
    }


    return textbuffer;
}


//! Internal dialog procedure handler for the confirmation dialog.
// TODO: need to close existing dialog when an attempt to create a second instance.
// TODO: need to close existing dialog when associated socket is closed.
static INT_PTR CALLBACK ConfirmCertificateDialogProc(
    HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg != WM_MOUSEMOVE) {
        DOUT(("stundlg: DialogProc(hwndDlg:=%p, uMsg:=%08x, wParam:=%08x, lParam:=%08x)\n", (void*)hwndDlg, (int) uMsg, (int) wParam, (int) lParam));
    }

    switch (uMsg) {
        case WM_INITDIALOG:
        {
            ConfirmationDialogData *confinfo = reinterpret_cast<ConfirmationDialogData*>(lParam);
            SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG) (LONG_PTR) confinfo);

            // If there is another confirmation dialog already open, then close it.
            if (IsWindow(hwndLastConfirmDialog)) {
                DOUT(("stundlg: WM_INITDIALOG closing existing dialog instance hwndDlg=%p before continuing.\n", hwndLastConfirmDialog));
                //SendMessage(hwndLastConfirmDialog, WM_COMMAND, MAKEWPARAM(BN_CLICKED, IDCANCEL), NULL);
                SendMessage(hwndLastConfirmDialog, WM_STUNTOUR_CLOSE, 0, 0);
                PumpWaitingMessages(hwndLastConfirmDialog);
            }
            hwndLastConfirmDialog = hwndDlg;

            // Populate the details about the certficate.
            std::string textbuffer = BuildConfirmationDetails(confinfo);
            SetDlgItemText(hwndDlg, IDC_SERVERDETAILS, textbuffer.c_str());
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) 
            { 
            case IDYES:
            case IDNO:
            case IDCANCEL:
                EndDialog(hwndDlg, LOWORD(wParam) );
                return TRUE;

            default: break;
            }
            break;

        case WM_STUNTOUR_CLOSE:
            DOUT(("stundlg: Got close request for dialog %p\n", hwndDlg));
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;

        default: break;
    }
    return FALSE;
}


//! Displays a modal dialog box prompting the user to confirm a connection.
/*!
 * We intentionally only allow one instance of this dialog box to be 
 * displayed at any time (even for unrelated socket connections).  If this
 * method is called and an existing confirmation dialog box is already
 * open, the previous instance will be automatically closed with a 
 * result code of IDCANCEL.
 *
 * \param certinfo Pointer to structure containing identity of certificate.
 * \return Returns one of the following:
 *          - IDYES User accepted certificate.
 *          - IDNO User rejected certificate.
 *          - IDCANCEL Dialog was dismissed (possibly automatically)
 */
DWORD ConfirmCertificateDialog(ConfirmationDialogData *certinfo)
{
    DOUT(("stundlg: ConfirmCertificateDialog called\n"));
    DWORD dwResult = (DWORD) DialogBoxParam(g_hInstance, MAKEINTRESOURCE(IDD_CONFIRM), GetOurParentWindow(), ConfirmCertificateDialogProc, (LPARAM) certinfo);
    DOUT(("stundlg: ConfirmCertificateDialog return value is %d\n", (int) dwResult));
    return dwResult;
}


//! Close the confirmation dialog if it is currently displayed and related 
//! to the specified socket.
/*!
 * This method is intended to be used when a socket is being explicitly
 * closed by the application and it is no longer relevant to keep 
 * connection establishment confirmations related to it open.
 *
 * \param sock Socket handle to close dialogs for.
 * \return Does not return any value.
 */
void CloseConfirmationDialogForSocket(SOCKET sock)
{
    __try {
        if (IsWindow(hwndLastConfirmDialog)) {
            ConfirmationDialogData *confinfo = reinterpret_cast<ConfirmationDialogData*>((LONG_PTR) GetWindowLongPtr(hwndLastConfirmDialog, GWLP_USERDATA));
            if (confinfo != NULL && confinfo->stunnel->GetSocket() == sock) {
                DOUT(("stundlg: CloseConfirmationDialogForSocket closing existing dialog hwnd=%p for socket %d\n", hwndLastConfirmDialog, sock));
                //SendMessage(hwndLastConfirmDialog, WM_COMMAND, MAKEWPARAM(BN_CLICKED, IDCANCEL), NULL);
                SendMessage(hwndLastConfirmDialog, WM_STUNTOUR_CLOSE, 0, 0);
                PumpWaitingMessages(hwndLastConfirmDialog);
                hwndLastConfirmDialog = NULL;
            }            
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // nothing, ignore exceptions.
    }
}