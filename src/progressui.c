#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "resource.h"
#include "ini_parser.h"
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
                 SWP_NOSIZE|SWP_SHOWWINDOW);
}

static void
InitDialog(HWND hDlg)
{
    SetWindowTextW(hDlg, sUIStrings.title);
    SetWindowTextW(GetDlgItem(hDlg, IDC_INFO), sUIStrings.info);

    // Set dialog icon
    HICON hIcon = LoadIconW(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_DIALOG));
    if (hIcon)
        SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM) hIcon);

    HWND hWndPro = GetDlgItem(hDlg, IDC_PROGRESS);
    SendMessage(hWndPro, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    if (sIndeterminate)
    {
        LONG_PTR val = GetWindowLongPtrW(hWndPro, GWL_STYLE);
        SetWindowLongPtrW(hWndPro, GWL_STYLE, val | PBS_MARQUEE);
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

static bool
euapi_get_string(void)
{
    bool ret = false;
    WCHAR *p = NULL;
    WCHAR path[MAX_PATH] = {0};
    TCHAR lang_path[MAX_PATH] = {0};
    HMODULE lang_symbol = NULL;
    if (!get_process_path(path, MAX_PATH)[0])
    {
        return false;
    }
    if((p = wcsrchr(path , L'\\')))
    {
        *p = 0 ;
    }
    uint32_t cid = (uint32_t) GetSystemDefaultLCID();
    switch (cid)
    {
        case 0x0804: // 简中
        {
            _snwprintf(lang_path, MAX_PATH-1, L"%s\\locales\\zh-cn.dll", path);
            break;
        }
        default:
            _snwprintf(lang_path, MAX_PATH-1, L"%s\\locales\\en-us.dll", path);
            break;
    }
    if (!(lang_symbol = LoadLibraryExW(lang_path, NULL, LOAD_LIBRARY_AS_DATAFILE)))
    {
        printf("LoadLibraryExW[%ls] failed, cause: %lu\n", lang_path, GetLastError());
        return false;
    }
    do
    {
        if (!LoadString(lang_symbol, 44061, sUIStrings.title, MAX_PATH - 1))
        {
            printf("LoadString %d return false\n", 44061);
            break;
        }
        if (!LoadString(lang_symbol, 44062, sUIStrings.info, MAX_PATH - 1))
        {
            printf("LoadString %d return false\n", 44062);
            break;
        }
        ret = true;
    } while(0);
    FreeLibrary(lang_symbol);
    return ret;
}

bool
set_ui_strings(void)
{
    bool ret = false;
#if EUAPI_LINK
    ret = euapi_get_string();
#else
    char *names = NULL;
    char *app_ini = NULL;
    WCHAR *pini = NULL;
    char result[6] = { 0 };
    do
    {
        if ((pini = init_file_strings(L"application.ini", NULL)) == NULL)
        {
            break;
        }
        if ((app_ini = ini_utf16_utf8(pini, NULL)) == NULL)
        {
            break;
        }
        if (!ini_read_string("App", "RemotingName", &names, app_ini, true))
        {
            break;
        }
        ret = true;
    } while(0);
    if (ret)
    {
        wcsncat(sUIStrings.title, L" ", MAX_PATH);
        wcsncpy(sUIStrings.info, sUIStrings.title, MAX_PATH);
        if (find_local_str(result, 5) && strcmp(result, "zh-CN") == 0)
        {
            wcsncat(sUIStrings.title, L"更新", MAX_PATH);
            wcsncat(sUIStrings.info, L"正在安装更新，将于稍后启动…", MAX_PATH);
        }
        else
        {
            wcsncat(sUIStrings.title, L"Update", MAX_PATH);
            wcsncat(sUIStrings.info, L"Is Installing Your Updates And Will Start In A Few Moments…", MAX_PATH);
        }
    }
    ini_safe_free(names);
    ini_safe_free(pini);
    ini_safe_free(app_ini);
#endif
    return ret;
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
    // Don't load the UI if the strings for the UI are not provided.
    if (show->initstrings && !sUIStrings.title[0])
    {
        return 0;
    }
    // 如果一个运行在 Windows XP 上的应用程序清单指定要
    // 使用 ComCtl32.dll 版本 6 或更高版本来启用可视化方式
    // 则需要 InitCommonControlsEx()。否则，将无法创建窗口
    // ICC_PROGRESS_CLASS,注册Progress Bar类
    INITCOMMONCONTROLSEX icc = { sizeof(INITCOMMONCONTROLSEX), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);
    DialogBoxW(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG), NULL, (DLGPROC) DialogProc);
    return (1);
}

void
quit_progress()
{
    sQuit = TRUE;
}

void
update_progress(float progress)
{
    sProgress = progress; // 32-bit writes are atomic
}
