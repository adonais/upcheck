#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "resource.h"
#include "spinlock.h"
#include <commctrl.h>
#include <process.h>
#include <shlwapi.h>
#include <windows.h>
#include "progressui.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#define TIMER_ID 1
#define TIMER_INTERVAL 100
#define MAX_TEXT_LEN 600

#define RESIZE_WINDOW(hwnd, extrax, extray)                                                                                                               \
    {                                                                                                                                                     \
        RECT windowSize;                                                                                                                                  \
        GetWindowRect(hwnd, &windowSize);                                                                                                                 \
        SetWindowPos(hwnd, 0, 0, 0, windowSize.right - windowSize.left + extrax, windowSize.bottom - windowSize.top + extray, SWP_NOMOVE | SWP_NOZORDER); \
    }

#define MOVE_WINDOW(hwnd, dx, dy)                                                     \
    {                                                                                 \
        RECT rc;                                                                      \
        POINT pt;                                                                     \
        GetWindowRect(hwnd, &rc);                                                     \
        pt.x = rc.left;                                                               \
        pt.y = rc.top;                                                                \
        ScreenToClient(GetParent(hwnd), &pt);                                         \
        SetWindowPos(hwnd, 0, pt.x + dx, pt.y + dy, 0, 0, SWP_NOSIZE | SWP_NOZORDER); \
    }

typedef struct _StringTable
{
    WCHAR title[MAX_PATH + 1];
    WCHAR info[MAX_PATH + 1];
} StringTable;

static float sProgress; // between 0 and 100
static BOOL sQuit = FALSE;
static BOOL sIndeterminate = FALSE;
static StringTable sUIStrings;

static void
UpdateDialog(HWND hDlg)
{
    int pos = (int) (sProgress + 0.5f);
    HWND hWndPro = GetDlgItem(hDlg, IDC_PROGRESS);
    SendMessage(hWndPro, PBM_SETPOS, pos, 0L);
}

// The code in this function is from MSDN:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winui/winui/windowsuserinterface/windowing/dialogboxes/usingdialogboxes.asp
static void
CenterDialog(HWND hDlg)
{
    RECT rc, rcOwner, rcDlg;

    // Get the owner window and dialog box rectangles.
    HWND desktop = GetDesktopWindow();

    GetWindowRect(desktop, &rcOwner);
    GetWindowRect(hDlg, &rcDlg);
    CopyRect(&rc, &rcOwner);

    // Offset the owner and dialog box rectangles so that
    // right and bottom values represent the width and
    // height, and then offset the owner again to discard
    // space taken up by the dialog box.

    OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
    OffsetRect(&rc, -rc.left, -rc.top);
    OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);

    // The new position is the sum of half the remaining
    // space and the owner's original position.

    SetWindowPos(hDlg,
                 HWND_TOP,
                 rcOwner.left + (rc.right / 2),
                 rcOwner.top + (rc.bottom / 2),
                 0,
                 0, // ignores size arguments
                 SWP_NOSIZE);
}

static void
InitDialog(HWND hDlg)
{
    SetWindowTextW(hDlg, sUIStrings.title);
    SetWindowTextW(GetDlgItem(hDlg, IDC_INFO), sUIStrings.info);

    // Set dialog icon
    HICON hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_DIALOG));
    if (hIcon)
        SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM) hIcon);

    HWND hWndPro = GetDlgItem(hDlg, IDC_PROGRESS);
    SendMessage(hWndPro, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    if (sIndeterminate)
    {
        LONG_PTR val = GetWindowLongPtr(hWndPro, GWL_STYLE);
        SetWindowLongPtr(hWndPro, GWL_STYLE, val | PBS_MARQUEE);
        SendMessage(hWndPro, (UINT) PBM_SETMARQUEE, (WPARAM) TRUE, (LPARAM) 50);
    }

    // Resize the dialog to fit all of the text if necessary.
    RECT infoSize, textSize;
    HWND hWndInfo = GetDlgItem(hDlg, IDC_INFO);

    // Get the control's font for calculating the new size for the control
    HDC hDCInfo = GetDC(hWndInfo);
    HFONT hInfoFont, hOldFont = NULL;
    hInfoFont = (HFONT) SendMessage(hWndInfo, WM_GETFONT, 0, 0);

    if (hInfoFont)
        hOldFont = (HFONT) SelectObject(hDCInfo, hInfoFont);

    // Measure the space needed for the text on a single line. DT_CALCRECT means
    // nothing is drawn.
    if (DrawText(hDCInfo, sUIStrings.info, -1, &textSize, DT_CALCRECT | DT_NOCLIP | DT_SINGLELINE))
    {
        GetClientRect(hWndInfo, &infoSize);
        SIZE extra;
        // Calculate the additional space needed for the text by subtracting from
        // the rectangle returned by DrawText the existing client rectangle's width
        // and height.
        extra.cx = (textSize.right - textSize.left) - (infoSize.right - infoSize.left);
        extra.cy = (textSize.bottom - textSize.top) - (infoSize.bottom - infoSize.top);
        if (extra.cx < 0)
            extra.cx = 0;
        if (extra.cy < 0)
            extra.cy = 0;
        if ((extra.cx > 0) || (extra.cy > 0))
        {
            RESIZE_WINDOW(hDlg, extra.cx, extra.cy);
            RESIZE_WINDOW(hWndInfo, extra.cx, extra.cy);
            RESIZE_WINDOW(hWndPro, extra.cx, 0);
            MOVE_WINDOW(hWndPro, 0, extra.cy);
        }
    }

    if (hOldFont)
        SelectObject(hDCInfo, hOldFont);

    ReleaseDC(hWndInfo, hDCInfo);

    CenterDialog(hDlg); // make dialog appear in the center of the screen

    SetTimer(hDlg, TIMER_ID, TIMER_INTERVAL, NULL);
}

// Message handler for update dialog.
static LRESULT CALLBACK
DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
        case WM_INITDIALOG:
            InitDialog(hDlg);
            return TRUE;

        case WM_TIMER:
            if (sQuit)
            {
                EndDialog(hDlg, 0);
                KillTimer(hDlg, TIMER_ID);
            }
            else
            {
                UpdateDialog(hDlg);
            }
            return TRUE;

        case WM_COMMAND:
            return TRUE;
    }
    return FALSE;
}

bool WINAPI
set_ui_strings(void)
{
    WCHAR ini[MAX_PATH + 1] = { L'\0' };
    WCHAR buf[MAX_PATH + 1] = { L'\0' };
    char result[6] = { 0 };
    if (!init_file_strings(L"application.ini", ini))
    {
        return false;
    }
    if (!read_appkey(L"App", L"RemotingName", sUIStrings.title, sizeof(sUIStrings.title), ini))
    {
        return false;
    }
    if (!read_appkey(L"App", L"RemotingName", sUIStrings.info, sizeof(sUIStrings.info), ini))
    {
        return false;
    }
    wcsncat(sUIStrings.title, L" ", MAX_PATH);
    wcsncat(sUIStrings.info, L" ", MAX_PATH);
    if (find_local_str(result, 5) && strcmp(result, "zh-CN") == 0)
    {
        wcsncat(sUIStrings.title, L"更新", MAX_PATH);
        wcsncat(sUIStrings.info, L"正在安装更新，将于稍后启动…", MAX_PATH);
    }
    else
    {
        wcsncat(sUIStrings.title, L"Update", MAX_PATH);
        wcsncat(sUIStrings.info, L"is installing your updates and will start in a few moments…", MAX_PATH);
    }
    return true;
}

unsigned WINAPI
show_progress(void *p)
{
    fn_show *show = (fn_show *) p;
    sIndeterminate = show->indeterminate;
    if (!sIndeterminate)
    {
        // Only show the Progress UI if the process is taking a significant amount of
        // time where a significant amount of time is defined as .5 seconds after
        // show_progress is called sProgress is less than 70.
        Sleep(500);

        if (sQuit || sProgress > 70.0f)
            return 0;
    }

    // Don't load the UI if there's an <exe_name>.Local directory for redirection.
    WCHAR appPath[MAX_PATH + 1] = { L'\0' };

    // Don't load the UI if the strings for the UI are not provided.
    if (show->initstrings && !set_ui_strings())
    {
        return 0;
    }

    if (!GetModuleFileNameW(NULL, appPath, MAX_PATH))
    {
        return 0;
    }

    // Use an activation context that supports visual styles for the controls.
    // C调用COM组件，最好的方法是使用Activation Context API加载指定清单.
    ACTCTXW actx = { 0 };
    actx.cbSize = sizeof(ACTCTXW);
    actx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
    actx.hModule = GetModuleHandle(NULL); // Use the embedded manifest
    // This is needed only for Win XP but doesn't cause a problem with other
    // versions of Windows.
    // 直接使用manifest文件时只设置这个就可以了
    actx.lpSource = appPath;
    actx.lpResourceName = MAKEINTRESOURCE(IDR_COMCTL32_MANIFEST);

    HANDLE hactx = INVALID_HANDLE_VALUE;
    hactx = CreateActCtxW(&actx);
    ULONG_PTR actxCookie = 0;
    if (hactx != INVALID_HANDLE_VALUE)
    {
        // Push the specified activation context to the top of the activation stack.
        ActivateActCtx(hactx, &actxCookie);
    }
    // 如果一个运行在 Windows XP 上的应用程序清单指定要
    // 使用 ComCtl32.dll 版本 6 或更高版本来启用可视化方式
    //则需要 InitCommonControlsEx()。否则，将无法创建窗口
    // ICC_PROGRESS_CLASS,注册Progress Bar类
    INITCOMMONCONTROLSEX icc = { sizeof(INITCOMMONCONTROLSEX), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG), NULL, (DLGPROC) DialogProc);

    if (hactx != INVALID_HANDLE_VALUE)
    {
        // Deactivate the context now that the comctl32.dll is loaded.
        DeactivateActCtx(0, actxCookie);
    }

    return 1;
}

void WINAPI
quit_progress()
{
    sQuit = TRUE;
}

void WINAPI
update_progress(float progress)
{
    sProgress = progress; // 32-bit writes are atomic
}
