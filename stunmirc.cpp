// Transparent SSL Tunnel hooking.
// Jeff Lawson <jlawson@bovine.net>
// $Id: stunmirc.cpp,v 1.1 2003/02/03 06:34:16 jlawson Exp $

#include "stuntour.h"



// -----------------------------------
// mIRC blue-window painting specific things follow...

#ifdef SECUREBLUEWINDOW

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

void SearchAndSubclassWindow(void)
{
    if (!lpfnOldWindowProc) {
        EnumWindows(EnumWindowsProc, 0);
    }
}

#endif


// -----------------------------------

// mIRC plugin specific things follow...


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

#ifdef SECUREBLUEWINDOW
    if (!lpfnOldWindowProc) {
        hwndSavedWindow = mWnd;
        lpfnOldWindowProc = (WNDPROC) GetWindowLong(mWnd, GWL_WNDPROC);
        SetWindowLong(mWnd, GWL_WNDPROC, (DWORD) Detour_mIRCWindowProc);
        ForceNonclientRepaint(mWnd);
    }
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

#ifdef SECUREBLUEWINDOW
        // Remove our windowproc subclassing hook.
        if (lpfnOldWindowProc != NULL) {
            SetWindowLong(hwndSavedWindow, GWL_WNDPROC, (DWORD) lpfnOldWindowProc);
            lpfnOldWindowProc = NULL;
            ForceNonclientRepaint(hwndSavedWindow);
        }
#endif

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
        unsigned short portnum = static_cast<unsigned short>(atoi(data));
        AddInterceptedPort(portnum);
    }

    strcpy(data, "/echo -s StunTour transparent SSL hook active for: ");
    strcat(data, QueryInterceptedPortListSpace().c_str());

    return 2;       // mIRC should execute the command we returned..
}