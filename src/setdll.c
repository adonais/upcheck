#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <process.h>
#include <windows.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <detours.h>
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
    return ret;
}
