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
// $Id: stunmirc.cpp,v 1.7 2004/01/22 09:07:05 jlawson Exp $

#include "stuntour.h"



// -----------------------------------

namespace BlueWindow {

    typedef std::map<HWND, WNDPROC> hwndprocmap_t;
    
    //! List of all windows that are currently subclassed.
    static hwndprocmap_t OldWindowProcs;

    //! New window proc used for subclassing.
    static LRESULT CALLBACK SubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    //! Method to force a window to be repainted.
    static void ForceNonclientRepaint(HWND hwnd);

    //! Entrypoint used to make another window become subclassed.
    bool SubclassNewWindow(HWND hwnd);

    //! Disables all active blue-window subclassing.
    void RemoveSubclassing(void);
};

//! Window procedure to add blue borders to windows via subclassing.
/*!
 * \param hwnd handle to window
 * \param uMsg message identifier
 * \param wParam first message parameter
 * \param lParam second message parameter
 */
LRESULT CALLBACK BlueWindow::SubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Obtain the original window procedure, before subclassing.
    WNDPROC lpfnOldWindowProc = NULL;
    hwndprocmap_t::const_iterator lpfnit = OldWindowProcs.find(hwnd);
    if (lpfnit != OldWindowProcs.end()) {
        lpfnOldWindowProc = lpfnit->second;
    } else {
        DOUT(("BlueWindow::SubclassProc called for unknown window %p. Ignoring.\n", (void*) hwnd));
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    // Start handling the special messages.
    if (uMsg == WM_NCPAINT) {
        // First let the original method do its work.
        LRESULT lResult = CallWindowProc(lpfnOldWindowProc, hwnd, uMsg, wParam, lParam);

        // Now overpaint the border with a blue line.
        HDC hdc = GetDCEx(hwnd, (HRGN)wParam, DCX_WINDOW|DCX_INTERSECTRGN);
        if (!hdc) {
            // If GetDCEx() failed, then try again with just GetWindowDC().
            hdc = GetWindowDC(hwnd);
        }
        if (hdc) {
            RECT windowrect, workrect;
            GetWindowRect(hwnd, &windowrect);

            HBRUSH hBlueBrush = CreateSolidBrush(RGB(0,0,255));
            const int framewidth = GetSystemMetrics(SM_CXSIZEFRAME);
            const int frameheight = GetSystemMetrics(SM_CYSIZEFRAME);

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
    } else if (uMsg == WM_DESTROY) {
        // Window is about to be destroyed, so remove the subclassing.
        SetWindowLongPtr(hwnd, GWL_WNDPROC, PtrToLong(lpfnOldWindowProc));
        OldWindowProcs.erase(hwnd);
        return CallWindowProc(lpfnOldWindowProc, hwnd, uMsg, wParam, lParam);
    } else {
        // Otherwise let the normal window proc handle it.
        return CallWindowProc(lpfnOldWindowProc, hwnd, uMsg, wParam, lParam);
    }
}

//! Forces a window to be fully repainted.
inline void BlueWindow::ForceNonclientRepaint(HWND hwnd)
{
    RedrawWindow(hwnd, NULL, NULL, RDW_FRAME | RDW_INVALIDATE | RDW_NOINTERNALPAINT | RDW_ERASENOW);
}

//! Entrypoint used to make another window become subclassed.
bool BlueWindow::SubclassNewWindow(HWND hwnd)
{
    DWORD windowpid;
    
    if (hwnd != NULL && IsWindow(hwnd) && 
        GetWindowThreadProcessId(hwnd, &windowpid) && 
        windowpid == GetCurrentProcessId() &&
        OldWindowProcs.find(hwnd) == OldWindowProcs.end())
    {
        // Found the window that is from our process.  Subclass it.
        WNDPROC lpfnOldWindowProc = (WNDPROC) LongToPtr(GetWindowLongPtr(hwnd, GWL_WNDPROC));
        OldWindowProcs.insert(std::make_pair<HWND, WNDPROC>(hwnd, lpfnOldWindowProc));
        SetWindowLongPtr(hwnd, GWL_WNDPROC, PtrToLong(BlueWindow::SubclassProc));
        ForceNonclientRepaint(hwnd);
        return true;
    }

    return false;       // could not successfully subclass specified window.
}

//! Removes subclassing from all windows.
void BlueWindow::RemoveSubclassing(void)
{
    for (hwndprocmap_t::const_iterator lpfnit = OldWindowProcs.begin();
        lpfnit != OldWindowProcs.end(); lpfnit++)
    {
		SetWindowLongPtr(lpfnit->first, GWL_WNDPROC, PtrToLong(lpfnit->second));
        ForceNonclientRepaint(lpfnit->first);
    }
    OldWindowProcs.clear();
}


// -----------------------------------

//! Identifies the HWND of the main application window of the mIRC instance 
//! that is executing this DLL.
/*!
 * \return The HWND of the main application window, if it can be identified.
 *      Otherwise NULL is returned.
 */
HWND GetOurParentWindow(void)
{
    //! Silly nested class so that we can define a local function.
    class foo {
        foo() {};
    public:
        static BOOL CALLBACK GOPWEnumWindowsProc(
                HWND hwnd,      //!< handle to parent window
                LPARAM lParam   //!< application-defined value
        )
        {
            char szClassName[64];
            if ( GetClassName(hwnd, szClassName, sizeof(szClassName)) &&
                (strcmp(szClassName, "mIRC32") == 0 || strcmp(szClassName, "mIRC") == 0)
                )
            {
                DWORD windowpid;
                GetWindowThreadProcessId(hwnd, &windowpid);
                if (windowpid == GetCurrentProcessId()) {
                    // Found the window that is from our process.
                    *reinterpret_cast<HWND*>(lParam) = hwnd;
                    return FALSE;       // done enumerating.
                }
            }
            return TRUE;        // continue enumerating.
        }
    };

    // Actually do the enumeration call.
    HWND hWnd = NULL;
    EnumWindows(foo::GOPWEnumWindowsProc, (LPARAM) &hWnd);
    DOUT(("GetOurParentWindow: found hwnd %p\n", hWnd));
    return hWnd;
}

// -----------------------------------

//! Method exported to mIRC that can be invoked to manually load the library.
/*
 * This doesn't really do anything significant, since simply loading the
 * library into the process-space will cause the winsock hooks to be installed.
 */
extern "C" int __declspec(dllexport) __stdcall load_stunnel(
      HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
{
    DOUT(("mIRC callback for load_stunnel invoked\n"));
    strcpy(data, "/echo -s StunTour transparent SSL hook is installed. http://www.bovine.net/~jlawson/coding/stuntour/");

#if 0
    // Make the entire main mIRC application window have a blue border.
    BlueWindow::SubclassNewWindow(mWnd);
#endif

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
/*
 * The only thing that this method does is try to disallow mIRC from
 * unloading our library (and breaking our hooks).
 */
extern "C" int __declspec(dllexport) __stdcall UnloadDll(int mTimeout)
{
    DOUT(("mIRC callback for UnloadDll invoked\n"));
    if (mTimeout == 1) {
        DOUT(("Instructing mIRC to not automatically unload library because of inactivity.\n"));
        return 0;       // return 0 to prevent unload, or 1 to allow it.
    } else {
        // Remove our windowproc subclassing hooks.
        BlueWindow::RemoveSubclassing();
    }
    return 1;       // otherwise allow it.
}


//! Method exported to mIRC that can be invoked to add interception for a port number.
/*
 * This displays a list of all sockets that are being relayed or adds additional ports.
 */
extern "C" int __declspec(dllexport) __stdcall hook_ports(
      HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
{
    DOUT(("mIRC callback for hook_ports invoked\n"));

    if (data != NULL) {
        if (strncmp(data, "-oneshot ", 9) == 0) {
            // one-shot port interception.
            AddInterceptedPort(static_cast<unsigned short>(atoi(data + 9)), true);
        } else {
            // normal port interception.
            AddInterceptedPort(static_cast<unsigned short>(atoi(data)), false);
        }
    }

    strcpy(data, "/echo -s StunTour transparent SSL hook active for: ");
    strcat(data, QueryInterceptedPortListSpace().c_str());

    return 2;       // mIRC should execute the command we returned..
}

//! Method exported to mIRC that can be invoked to subclass a specified 
//! window (by hwnd) and make its window frame blue.
extern "C" int __declspec(dllexport) __stdcall blue_window(
      HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
{
    DOUT(("mIRC callback for blue_window invoked\n"));

    if (data != NULL) {
		HWND hwnd = (HWND) LongToHandle(atoi(data));
        bool bResult = BlueWindow::SubclassNewWindow(hwnd);
        if (bResult) {
            DOUT(("blue_window successfully subclassed new window %p\n", (void*) hwnd));
        } else {
            DOUT(("blue_window failed to subclass new window.\n"));
        }
    }

    return 1;       // mIRC should just continue executing.
}


//! Method exported to mIRC that can be invoked to add interception for a port number.
/*
 * This displays a list of all sockets that are being relayed or adds additional ports.
 */
extern "C" int __declspec(dllexport) __stdcall secure_dcc_chat(
      HWND mWnd, HWND aWnd, char *data, char *parms, BOOL show, BOOL nopause)
{
    DOUT(("mIRC callback for secure_dcc_chat invoked\n"));

#ifdef HOOK_DCC_SCHAT
    g_bSecureOutgoingDccChat = true;

    strcpy(data, "/echo -s StunTour will convert the next DCC CHAT into a DCC SCHAT");
#else
    strcpy(data, "/echo -s StunTour was not compiled with HOOK_DCC_SCHAT enabled");
#endif

    return 2;       // mIRC should execute the command we returned..
}

