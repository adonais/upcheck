#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <process.h>
#include <windows.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <detours.h>
#include "7zc.h"
#include "spinlock.h"

#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable : 6102 6103) // /analyze warnings
#endif

#include <strsafe.h>
#pragma warning(pop)

#define BUFFSIZE 1024
#define LEN_NAME 6
#define UNUSED(c) (c) = (c)
#define is_valid_handle(x) (x != NULL && x != INVALID_HANDLE_VALUE)
#define STR_IS_NUL(s) (s == NULL || *s == 0)

typedef int (WINAPI *SHFileOperationWPtr)(LPSHFILEOPSTRUCTW lpFileOp);

//////////////////////////////////////////////////////////////////////////////
//
static BOOLEAN s_fRemove = FALSE;
static CHAR s_szDllPath[MAX_PATH] = {0};

//////////////////////////////////////////////////////////////////////////////
//
//  This code verifies that the named DLL has been configured correctly
//  to be imported into the target process.  DLLs must export a function with
//  ordinal #1 so that the import table touch-up magic works.
//
static BOOL CALLBACK
ExportCallback(_In_opt_ PVOID pContext, _In_ ULONG nOrdinal, _In_opt_ LPCSTR pszName, _In_opt_ PVOID pCode)
{
    (void) pContext;
    (void) pCode;
    (void) pszName;

    if (nOrdinal == 1)
    {
        *((BOOL *) pContext) = TRUE;
    }
    return TRUE;
}

BOOL
DoesDllExportOrdinal1(PCHAR pszDllPath)
{
    HMODULE hDll = LoadLibraryExA(pszDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hDll == NULL)
    {
        printf("setdll.exe: LoadLibraryEx(%s) failed with error %lu.\n", pszDllPath, GetLastError());
        return FALSE;
    }

    BOOL validFlag = FALSE;
    DetourEnumerateExports(hDll, &validFlag, ExportCallback);
    FreeLibrary(hDll);
    return validFlag;
}

//////////////////////////////////////////////////////////////////////////////
//
static BOOL CALLBACK
ListBywayCallback(_In_opt_ PVOID pContext, _In_opt_ LPCSTR pszFile, _Outptr_result_maybenull_ LPCSTR *ppszOutFile)
{
    (void) pContext;

    *ppszOutFile = pszFile;
    return TRUE;
}

static BOOL CALLBACK
ListFileCallback(_In_opt_ PVOID pContext, _In_ LPCSTR pszOrigFile, _In_ LPCSTR pszFile, _Outptr_result_maybenull_ LPCSTR *ppszOutFile)
{
    (void) pContext;
    *ppszOutFile = pszFile;
    printf("    %s -> %s\n", pszOrigFile, pszFile);
    return TRUE;
}

static BOOL CALLBACK
AddBywayCallback(_In_opt_ PVOID pContext, _In_opt_ LPCSTR pszFile, _Outptr_result_maybenull_ LPCSTR *ppszOutFile)
{
    PBOOL pbAddedDll = (PBOOL) pContext;
    if (!pszFile && !*pbAddedDll)
    { // Add new byway.
        *pbAddedDll = TRUE;
        *ppszOutFile = s_szDllPath;
    }
    return TRUE;
}

static BOOL
SetFile(LPWSTR pszPath)
{
    BOOL bGood = TRUE;
    HANDLE hOld = INVALID_HANDLE_VALUE;
    HANDLE hNew = INVALID_HANDLE_VALUE;
    PDETOUR_BINARY pBinary = NULL;
    WCHAR szOrg[MAX_PATH];
    WCHAR szNew[MAX_PATH];
    WCHAR szOld[MAX_PATH];

    szOld[0] = '\0';
    szNew[0] = '\0';
    if (pszPath == NULL || pszPath[0] == 0)
    {
        return FALSE;
    }
    StringCchCopyW(szOrg, sizeof(szOrg), pszPath);
    StringCchCopyW(szNew, sizeof(szNew), szOrg);
    StringCchCatW(szNew, sizeof(szNew), L"#");
    StringCchCopyW(szOld, sizeof(szOld), szOrg);
    StringCchCatW(szOld, sizeof(szOld), L"~");
    printf("  %ls:\n", pszPath);

    hOld = CreateFileW(szOrg, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hOld == INVALID_HANDLE_VALUE)
    {
        printf("Couldn't open input file: %ls, error: %lu\n", szOrg, GetLastError());
        bGood = FALSE;
        goto end;
    }

    hNew = CreateFileW(szNew, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hNew == INVALID_HANDLE_VALUE)
    {
        printf("Couldn't open output file: %ls, error: %lu\n", szNew, GetLastError());
        bGood = FALSE;
        goto end;
    }

    if ((pBinary = DetourBinaryOpen(hOld)) == NULL)
    {
        printf("DetourBinaryOpen failed: %lu\n", GetLastError());
        goto end;
    }

    if (hOld != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hOld);
        hOld = INVALID_HANDLE_VALUE;
    }

    {
        BOOL bAddedDll = FALSE;

        DetourBinaryResetImports(pBinary);

        if (!s_fRemove)
        {
            if (!DetourBinaryEditImports(pBinary, &bAddedDll, AddBywayCallback, NULL, NULL, NULL))
            {
                printf("DetourBinaryEditImports failed: %lu\n", GetLastError());
            }
        }

        if (!DetourBinaryEditImports(pBinary, NULL, ListBywayCallback, ListFileCallback, NULL, NULL))
        {

            printf("DetourBinaryEditImports failed: %lu\n", GetLastError());
        }

        if (!DetourBinaryWrite(pBinary, hNew))
        {
            printf("DetourBinaryWrite failed: %lu\n", GetLastError());
            bGood = FALSE;
        }

        DetourBinaryClose(pBinary);
        pBinary = NULL;

        if (hNew != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hNew);
            hNew = INVALID_HANDLE_VALUE;
        }

        if (bGood)
        {
            if (!DeleteFileW(szOld))
            {
                DWORD dwError = GetLastError();
                if (dwError != ERROR_FILE_NOT_FOUND)
                {
                    printf("Warning: Couldn't delete %ls: %lu\n", szOld, dwError);
                    bGood = FALSE;
                }
            }
            if (!MoveFileExW(szNew, szOrg, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING))
            {
                printf("Error: Couldn't install %ls as %ls: %lu\n", szNew, szOrg, GetLastError());
                bGood = FALSE;
            }
        }

        DeleteFileW(szNew);
    }

end:
    if (pBinary)
    {
        DetourBinaryClose(pBinary);
        pBinary = NULL;
    }
    if (hNew != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hNew);
        hNew = INVALID_HANDLE_VALUE;
    }
    if (hOld != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hOld);
        hOld = INVALID_HANDLE_VALUE;
    }
    return bGood;
}

static BOOL
lookup_file_exist(const WCHAR *wide_dir)
{
    const DWORD attrs = GetFileAttributes(wide_dir);
    return (INVALID_FILE_ATTRIBUTES != attrs && !(FILE_ATTRIBUTE_DIRECTORY & attrs));
}

static BOOL
fixed_file(LPCWSTR path, LPCSTR desc, LPCSTR con, BOOL back)
{
    long pos = 0;
    char buff[BUFFSIZE + 1] = { 0 };
    FILE *fp = NULL;
    BOOL  comma = FALSE;
    BOOL js_file = wcsstr(path, L"nsContextMenu.") != NULL;
    if (FAILED(_wfopen_s(&fp, path, L"rb+")))
    {
        printf("fopen_s %ls false\n", path);
        return FALSE;
    }
    while (fgets(buff, BUFFSIZE, fp) != NULL)
    {
        if (strstr(buff, desc) != NULL)
        {
            pos = ftell(fp);
            if (js_file)
            {
                /* 上一个函数块是否以逗号结尾 */
                char str_t[MAX_PATH] = { 0 };
                fseek(fp, -((long)strlen(buff)+8), SEEK_CUR);
                if (fread(str_t, 8, 1, fp) > 0)
                {
                    comma = strstr(str_t, "},") != NULL;
                }                
            }
            if (back)
            {
                pos -= (long) strlen(buff);
            }
            break;
        }
    }
    if (pos)
    {
        size_t bytes = 0;
        fseek(fp, 0, SEEK_END);
        long len = ftell(fp);
        len -= pos;
        // printf("len = %lu\n", len);
        fseek(fp, pos, SEEK_SET);
        char *next = (char *) calloc(len, sizeof(char));
        if (!next)
        {
            printf("calloc next false\n");
            fclose(fp);
            return FALSE;
        }
        char *backup = (char *) calloc(len, sizeof(char));
        DWORD offset = 0;
        if (!backup)
        {
            printf("calloc backup false\n");
            fclose(fp);
            free(next);
            return FALSE;
        }
        while (!feof(fp))
        {
            bytes = fread(next, 1, 128, fp);
            if (bytes > 0)
            {
                memcpy(backup + offset, next, bytes);
                offset += (DWORD) bytes;
            }
        }
        fseek(fp, pos, SEEK_SET);
        fwrite(con, strlen(con), 1, fp);
        if (js_file)
        {
            if (comma)
            {
                /* downloandlink函数添加逗号 */
                fwrite(",\n\n", 3, 1, fp);
            }
            else
            {
                /* 最新版的js没有逗号 */
                fwrite("\n\n", 2, 1, fp);
            }
        }
        fwrite(backup, offset, 1, fp);
        free(next);
        free(backup);
    }
    fclose(fp);
    return (pos > 0);
}

static UINT64
get_file_size(const HANDLE hfile)
{  
    UINT64 size = 0;
    GetFileSizeEx(hfile, (LARGE_INTEGER *) &size);
    return size;
}

static BOOL
exist_key_desc(LPCWSTR pszPath, LPCSTR key)
{
    BOOL bGood = TRUE;
    UINT64 size = 0;
    DWORD bw = 0;
    char *buff = NULL;
    HANDLE hfile = INVALID_HANDLE_VALUE;
    if (pszPath == NULL || pszPath[0] == 0)
    {
        return FALSE;
    }
    if (!key)
    {
        key = (LPCSTR)s_szDllPath;
    }
    if ((hfile = CreateFileW(pszPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        printf("Couldn't open input file: %ls, error: %lu\n", pszPath, GetLastError());
        bGood = FALSE;
        goto end_err;
    }
    if ((size = get_file_size(hfile)) < 0x20)
    {
        printf("So small\n");
        bGood = FALSE;
        goto end_err;
    }
    if ((buff = (char *)malloc((size_t)size)) == NULL)
    {
        bGood = FALSE;
        goto end_err;
    }
    if (!ReadFile(hfile, buff, (DWORD)size, &bw, 0))
    {
        printf("ReadFile return false\n");
        bGood = FALSE;
        goto end_err;
    }
    if (check_memstr(buff, (int)bw, key) == NULL)
    {
        bGood = FALSE;
    }
end_err:
    if (hfile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hfile);
    }
    if (buff)
    {
        free(buff);
    }
    return bGood;
}

static int
edit_files(LPCWSTR path)
{
    BOOL cn = FALSE;
    BOOL late128 = FALSE;
    WCHAR f_xul[MAX_PATH + 1] = { 0 };
    WCHAR f_dtd[MAX_PATH + 1] = { 0 };
    WCHAR f_js[MAX_PATH + 1] = { 0 };
    WCHAR f_context[MAX_PATH + 1] = { 0 };
    LPCSTR js_desc1 = "this.showItem(\"context-savepage\", shouldShow);";
    LPCSTR js_desc2 = "Backwards-compatibility wrapper";
    LPCSTR js_inst1 =
        "\n\
    // hack by adonais\n\
    this.showItem(\n\
      \"context-downloadlink\",\n\
      this.onSaveableLink || this.onPlainTextLink\n\
    );";
    LPCSTR js_inst2 =
        "\
  downloadLink() {\n\
    if (AppConstants.platform === \"win\") {\n\
    const exeName = \"upcheck.exe\";\n\
    let exe = Services.dirsvc.get(\"GreBinD\", Ci.nsIFile);\n\
    let cfile = Services.dirsvc.get(\"ProfD\", Ci.nsIFile);\n\
    exe.append(exeName);\n\
    cfile.append(\"cookies.sqlite\");\n\
    let process = Cc[\"@mozilla.org/process/util;1\"]\n\
                    .createInstance(Ci.nsIProcess);\n\
    process.init(exe);\n\
    process.startHidden = true;\n\
    process.noShell = true;\n\
    process.run(false, [\"-i\", this.linkURL, \"-b\", encodeURIComponent(cfile.path), \"-m\", \"1\"], 6);\n\
    }\n\
  }";
    LPCSTR xul_desc = "gContextMenu.saveLink();";
    LPCSTR xul_inst =
        "\
      <menuitem id=\"context-downloadlink\"\n\
                data-l10n-id=\"main-context-menu-download-link\"\n\
                oncommand=\"gContextMenu.downloadLink();\"/>\n";
    LPCSTR xul_desc1 = "data-l10n-id=\"main-context-menu-save-link\"";
    LPCSTR xul_inst1 =
        "\
                />\n\
      <menuitem id=\"context-downloadlink\"\n\
                data-l10n-id=\"main-context-menu-download-link\"\n";
    LPCSTR context_desc1 = "case \"context-savelinktopocket\":";
    LPCSTR context_desc2 = "case \"context-copyemail\":";
    LPCSTR context_inst1 =
        "\
        case \"context-downloadlink\":\n\
          gContextMenu.downloadLink();\n\
          break;\n";
    LPCSTR dtd_desc = "main-context-menu-copy-email";
    LPCSTR dtd_inst1 =
        "\
main-context-menu-download-link = \n\
    .label = 使用Upcheck下载此链接\n";
    LPCSTR dtd_inst2 =
        "\
main-context-menu-download-link = \n\
    .label = Download Link With Upcheck\n";
    LPCWSTR file1 = L"chrome\\browser\\content\\browser\\browser.xhtml";
    LPCWSTR file2 = L"chrome\\browser\\content\\browser\\nsContextMenu.js";
    LPCWSTR file3 = L"localization\\zh-CN\\browser\\browserContext.ftl";
    LPCWSTR file4 = L"localization\\en-US\\browser\\browserContext.ftl";
    LPCWSTR file5 = L"chrome\\browser\\content\\browser\\nsContextMenu.sys.mjs";
    LPCWSTR file6 = L"chrome\\browser\\content\\browser\\browser-context.js";
    if (STR_IS_NUL(path))
    {
        printf("lpath is null\n");
        return -1;
    }
    _snwprintf(f_dtd, MAX_PATH, L"%s\\%s", path, file3);
    _snwprintf(f_context, MAX_PATH, L"%s\\%s", path, file6);
    cn = lookup_file_exist(f_dtd);
    late128 = lookup_file_exist(f_context);
    if (!cn)
    {
        _snwprintf(f_dtd, MAX_PATH, L"%s\\%s", path, file4);
        if (!lookup_file_exist(f_dtd))
        {
            return -1;
        }
    }
    if (exist_key_desc(f_dtd, "main-context-menu-download-link"))
    {
        printf("Omni does not need to be fixed\n");
        return 1;
    }
    _snwprintf(f_xul, MAX_PATH, L"%s\\%s", path, file1);
    _snwprintf(f_js, MAX_PATH, L"%s\\%s", path, late128 ? file5 : file2);
    if (!(lookup_file_exist(f_xul) && lookup_file_exist(f_js)))
    {
        printf("file not exist\n");
        return -1;
    }
    if (!fixed_file(f_js, js_desc1, js_inst1, FALSE))
    {
        printf("fixed_file js_desc1 return false\n");
        return -1;
    }
    if (!fixed_file(f_js, js_desc2, js_inst2, TRUE))
    {
        printf("fixed_file js_desc2 return false\n");
        return -1;
    }
    if (!fixed_file(f_xul, late128 ? xul_desc1 : xul_desc, late128 ? xul_inst1 : xul_inst, FALSE))
    {
        printf("fixed_file f_xul return false\n");
        return -1;
    }
    if (late128)
    {
        if (!(fixed_file(f_context, context_desc1, context_inst1, TRUE) || fixed_file(f_context, context_desc2, context_inst1, TRUE)))
        {
            printf("fixed_file context_desc return false\n");
            return -1;
        }
    }
    if (cn)
    {             
        if (!fixed_file(f_dtd, dtd_desc, dtd_inst1, TRUE))
        {
            printf("fixed_file ftl_inst1 return false\n");
            return -1;
        }
    }
    else
    { 
        if (!fixed_file(f_dtd, dtd_desc, dtd_inst2, TRUE))
        {
            printf("fixed_file ftl_inst1 return false\n");
            return -1;
        }
    }
    return 0;
}

static BOOL
cmd_erase_dir(LPCWSTR lpszDir, BOOL noRecycle)
{
    int ret = -1;
    WCHAR *pszFrom = NULL;
    size_t len = 0;
    SHFileOperationWPtr fnSHFileOperationW = NULL;
    HMODULE shell32 = GetModuleHandleW(L"shell32.dll");
    if (!shell32 || !lpszDir)
    {
        return FALSE;
    }
    do
    {
        len = wcslen(lpszDir);
        fnSHFileOperationW = (SHFileOperationWPtr) GetProcAddress(shell32, "SHFileOperationW");
        if (fnSHFileOperationW == NULL)
        {
            break;
        }
        if ((pszFrom = (WCHAR *) calloc(len+4, sizeof(WCHAR))) == NULL)
        {
            break;
        }
        wcscpy_s(pszFrom, len + 2, lpszDir);
        pszFrom[len] = 0;
        pszFrom[len + 1] = 0;

        SHFILEOPSTRUCTW fileop;
        fileop.hwnd = NULL;                              // no status display
        fileop.wFunc = FO_DELETE;                        // delete operation
        fileop.pFrom = pszFrom;                          // source file name as double null terminated string
        fileop.pTo = NULL;                               // no destination needed
        fileop.fFlags = FOF_NOCONFIRMATION | FOF_SILENT; // do not prompt the user

        if (!noRecycle)
        {
            fileop.fFlags |= FOF_ALLOWUNDO;
        }
        fileop.fAnyOperationsAborted = FALSE;
        fileop.lpszProgressTitle = NULL;
        fileop.hNameMappings = NULL;
        // SHFileOperation returns zero if successful; otherwise nonzero
        ret = fnSHFileOperationW(&fileop);
    } while (0);
    if (pszFrom)
    {
        free(pszFrom);
    }
    return (0 == ret);
}

static WCHAR *
rand_str(WCHAR *str, const int len)
{
    int i;
    for (i = 0; i < len; ++i)
        str[i] = 'A' + rand() % 26;
    str[len] = '\0';
    return str;
}

static BOOL
Patched_File(LPCWSTR pfile)
{
    int err = 0;
    WCHAR aPath[MAX_PATH + 1] = { 0 };
    WCHAR temp[LEN_NAME + 1];
    WCHAR omni[MAX_PATH + 1] = { 0 };
    WCHAR aCmd[URL_LEN + 1] = { 0 };
    if (pfile == NULL || pfile[1] != ':')
    {
        return FALSE;
    }
    if (!PathFileExistsW(pfile))
    {
        printf("omni.ja file not exist\n");
        return FALSE;
    }
    if (!GetTempPathW(MAX_PATH, aPath))
    {
        return FALSE;
    }
    if (FAILED(StringCchCatW(aPath, MAX_PATH, L"omni_")))
    {
        return FALSE;
    }
    srand((unsigned int) time(NULL));
    if (FAILED(StringCchCatW(aPath, MAX_PATH, rand_str(temp, LEN_NAME))))
    {
        return FALSE;
    }
    do
    {
        _snwprintf(aCmd, URL_LEN, L"x -aoa -o\"%s\" \"%s\"", aPath, pfile);
        if (exec_zmain1(aCmd) == -1)
        {
            printf("exec_zmain1 failed\n");
            err = 1;
            break;
        }  
        _snwprintf(omni, MAX_PATH, L"%s", pfile);
        if (!(PathRemoveFileSpecW(omni) && PathAppendW(omni, L"omni.zip")))
        {
            printf("PathAppend failed\n");
            err = 1;
            break;
        }
        if ((err = edit_files(aPath)) != 0)
        {
            if (err < 0)
            {
                printf("edit_files failed\n");
            }
            break;
        }
        if (FAILED(StringCchCatW(aPath, MAX_PATH, L"\\*")))
        {
            err = 1;
            break;
        }
        _snwprintf(aCmd, URL_LEN, L"a -tzip -mx=0 -mmt=4 \"%s\" \"%s\"", omni, aPath);
        if ((err = exec_zmain1(aCmd)) != 0)
        {
            printf("compress file failed\n");
        }
        PathRemoveFileSpecW(aPath);
    } while(0);
    cmd_erase_dir(aPath, TRUE);
    if (!err)
    {
        return MoveFileExW(omni, pfile, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);
    }
    return FALSE;
}
//////////////////////////////////////////////////////////////////////////////
//

static int
get_file_bits(const wchar_t* path)
{
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS pe_header;
    int ret = 1;
    HANDLE hFile = CreateFileW(path,GENERIC_READ,
                               FILE_SHARE_READ,NULL,OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,NULL);
    if( !is_valid_handle(hFile) )
    {
        return ret;
    }
    do
    {
        DWORD readed = 0;
        DWORD m_ptr  = SetFilePointer( hFile,0,NULL,FILE_BEGIN );
        if ( INVALID_SET_FILE_POINTER == m_ptr )
        {
            break;
        }
        ret = ReadFile( hFile,&dos_header,sizeof(IMAGE_DOS_HEADER),&readed,NULL );
        if( ret && readed != sizeof(IMAGE_DOS_HEADER) && \
            dos_header.e_magic != IMAGE_DOS_SIGNATURE )
        {
            break;
        }
        m_ptr = SetFilePointer( hFile,dos_header.e_lfanew,NULL,FILE_BEGIN );
        if ( INVALID_SET_FILE_POINTER == m_ptr )
        {
            break;
        }
        ret = ReadFile( hFile,&pe_header,sizeof(IMAGE_NT_HEADERS),&readed,NULL );
        if( ret && readed != sizeof(IMAGE_NT_HEADERS) )
        {
            break;
        }
        if (pe_header.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        {
            ret = 32;
            break;
        }
        if (pe_header.FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 ||
            pe_header.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            ret = 64;
        }
    } while (0);
    CloseHandle(hFile);
    return ret;
}

int
exec_7z(int argn, WCHAR **parg)
{
    return exec_zmain2(argn, parg);
}

int
file_mozdll(void)
{
    wchar_t mozglue[MAX_PATH+1] = L"mozglue.dll";
    if (!path_combine(mozglue, MAX_PATH) || !lookup_file_exist(mozglue))
    {
        printf("%ls not exist\n", mozglue);
        return 1;
    }
    return get_file_bits(mozglue);
}

BOOL
inject_mozdll(void)
{
    BOOL ret = TRUE;
    wchar_t mozglue[MAX_PATH+1] = L"mozglue.dll";
    wchar_t updater[MAX_PATH+1] = L"updater.exe";
    wchar_t omni[MAX_PATH+1] = L"browser\\omni.ja";
    wchar_t portable[MAX_PATH+1] = {0};
    int bits = 0;
    s_fRemove = FALSE;
    if (!path_combine(mozglue, MAX_PATH) || !lookup_file_exist(mozglue))
    {
        printf("%ls not exist\n", mozglue);
        return FALSE;
    }
    if ((bits = get_file_bits(mozglue)) < 32)
    {
        return FALSE;
    }
    if (!path_combine(updater, MAX_PATH))
    {
        printf("path_combine[updater] failed\n");
        return FALSE;
    }
    if (!path_combine(omni, MAX_PATH))
    {
        printf("path_combine[omni] failed\n");
        return FALSE;
    }
    if (bits == 64)
    {
        wcsncpy(portable, L"portable64.dll", MAX_PATH);
    }
    else
    {
        wcsncpy(portable, L"portable32.dll", MAX_PATH);
    }
    if (!path_combine(portable, MAX_PATH) || !lookup_file_exist(portable))
    {
        printf("%ls not exist\n", portable);
        return FALSE;
    }
    if (bits == 64)
    {
        wcsncpy(portable, L"portable64.dll", MAX_PATH);
        printf("PE32+ executable (x86-64), for MS Windows\n");
    }
    else
    {
        wcsncpy(portable, L"portable32.dll", MAX_PATH);
        printf("PE32 executable (i386), for MS Windows\n");
    }
    if (!WideCharToMultiByte(CP_ACP, 0, portable, -1, s_szDllPath, sizeof(s_szDllPath), NULL, NULL))
    {
        return FALSE;
    }
    if (lookup_file_exist(updater) && !exist_key_desc(updater, NULL))
    {
        SetFile(updater);
    }
    if (!exist_key_desc(mozglue, NULL))
    {
        ret = SetFile(mozglue);
    }
    else
    {
        printf("Import table does not need to be fixed\n");
    }
    if (ret)
    {
        ret = Patched_File(omni);
    }
    return ret;
}
