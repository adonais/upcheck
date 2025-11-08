#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include "ini_parser.h"
#include <curl/curl.h>
#include "spinlock.h"

#pragma comment(lib, "advapi32.lib")

volatile long g_locked = 0;

static HMODULE curl_symbol = NULL;
ptr_curl_easy_strerror euapi_curl_easy_strerror = NULL;
ptr_curl_easy_setopt euapi_curl_easy_setopt = NULL;
ptr_curl_easy_perform euapi_curl_easy_perform = NULL;
ptr_curl_easy_getinfo euapi_curl_easy_getinfo = NULL;
ptr_curl_slist_append euapi_curl_slist_append = NULL;
ptr_curl_slist_free_all euapi_curl_slist_free_all = NULL;
ptr_curl_share_init euapi_curl_share_init = NULL;
ptr_curl_share_setopt euapi_curl_share_setopt = NULL;
ptr_curl_share_cleanup euapi_curl_share_cleanup = NULL;
ptr_curl_global_init euapi_curl_global_init = NULL;
ptr_curl_easy_init euapi_curl_easy_init = NULL;
ptr_curl_global_cleanup euapi_curl_global_cleanup = NULL;
ptr_curl_easy_cleanup euapi_curl_easy_cleanup = NULL;
ptr_curl_easy_reset euapi_curl_easy_reset = NULL;

#ifdef LOG_DEBUG
static char logfile_buf[MAX_PATH];

void __cdecl 
logmsg(const char * format, ...)
{
    va_list args;
    char    buffer[MAX_MESSAGE] = {0};
    va_start (args, format);
    if (strlen(logfile_buf) > 0)
    {
        FILE *pFile = NULL;
        int  len = wvnsprintfA(buffer, MAX_MESSAGE, format, args);
        if (len > 0 && len < MAX_MESSAGE)
        {
            buffer[len] = '\0';
            if ((pFile = fopen(logfile_buf, "a+")) != NULL)
            {
                fwrite(buffer, strlen(buffer), 1, pFile);
                fclose(pFile);
            }
        }
    }
    va_end(args);
}

void
init_logs(void)
{
    if (*logfile_buf == '\0' && GetEnvironmentVariableA("APPDATA", logfile_buf, MAX_PATH) > 0)
    {
        strncat(logfile_buf, "\\", MAX_PATH);
        strncat(logfile_buf, "upcheck.log", MAX_PATH);
    }
}
#endif

bool
ini_path_init(void)
{
#if EUAPI_LINK
    return true;
#else
    bool  ret = false;
    WCHAR ini_path[MAX_PATH + 1] = {0};
    if (*file_info.ini != '\0' && strlen(file_info.ini) > 10)
    {
        return false;
    }
    GetModuleFileNameW(NULL, ini_path, MAX_PATH);
    PathRemoveFileSpecW(ini_path);
    PathAppendW(ini_path, L"portable.ini");
    ret = PathFileExistsW(ini_path);
    return (ret && WideCharToMultiByte(CP_UTF8, 0, ini_path, -1, file_info.ini, MAX_PATH, NULL, NULL) > 0);
#endif
}

void
wchr_replace(LPWSTR path)        /* 替换unix风格的路径符号 */
{
    LPWSTR   lp = NULL;
    intptr_t pos;
    do
    {
        lp = StrChrW(path, L'/');
        if (lp)
        {
            pos = lp - path;
            path[pos] = L'\\';
        }
    } while (lp != NULL);
}

bool
exists_dir(LPCWSTR path)
{
    DWORD fileattr = GetFileAttributesW(path);
    if (fileattr != INVALID_FILE_ATTRIBUTES)
    {
        return (fileattr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    return false;
}

bool
create_dir(LPCWSTR dir)
{
    LPWSTR p = NULL;
    WCHAR  tmp_name[MAX_PATH];
    wcscpy(tmp_name, dir);
    p = wcschr(tmp_name, L'\\');
    for ( ; p != NULL; *p = L'\\', p = wcschr(p+1, L'\\') )
    {
        *p = L'\0';
        if (exists_dir(tmp_name))
        {
            continue;
        }
        CreateDirectoryW(tmp_name, NULL);
    }
    return (CreateDirectoryW(tmp_name, NULL)||GetLastError() == ERROR_ALREADY_EXISTS);
}

WCHAR *
path_utf8_utf16(const char *path)
{
    size_t len = 0;
    wchar_t *res = NULL;
    wchar_t *u16 = ini_utf8_utf16(path, &len);
    if (u16 && len < BUFF_LEN)
    {
        if ((res = (wchar_t *)calloc(BUFF_LEN, sizeof(wchar_t))))
        {
            _snwprintf(res, BUFF_LEN - 1, L"%s", u16);
        }
        free(u16);
        return res;
    }
    return u16;
}

WCHAR *
path_utf16_clone(const wchar_t *path)
{
    wchar_t *res = NULL;
    if (path && ((res = (wchar_t *)calloc(BUFF_LEN, sizeof(wchar_t)))))
    {
        _snwprintf(res, BUFF_LEN - 1, L"%s", path);
    }
    return res;
}

char *
path_add_quotes(const char *path)
{
    char *buf = NULL;
    if (path)
    {
        int len = (int)strlen(path) + 4;
        if (*path == '"')
        {
            buf = _strdup(path);
        }
        else if ((buf = (char *)calloc(1, len + 1)) != NULL)
        {
            _snprintf(buf, len, "\"%s\"", path);
        }
    }
    return buf;
}

BOOL
move_file_wrapper(const WCHAR *srcfile, const WCHAR *dst, uint32_t flags)
{
    BOOL ret = FALSE;
    WCHAR *path = path_utf16_clone(dst);
    if (path)
    {
        uint32_t attrs = GetFileAttributesW(path);
        if ((attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_READONLY))
        {   // 取消只读属性
            attrs &= ~FILE_ATTRIBUTE_READONLY;
            SetFileAttributesW(path, attrs);
        }
        PathRemoveFileSpecW(path);
        if (create_dir(path))
        {
            ret = MoveFileExW(srcfile, dst, flags);
        }
        free(path);
    }
    return ret;
}

bool
path_combine(LPWSTR lpfile, const int len)
{
    int n = 1;
    if (NULL == lpfile || *lpfile == L' ')
    {
        return false;
    }
    if (len > 0 && lpfile[1] != L':')
    {
        WCHAR modname[MAX_PATH + 1] = {0};
        wchr_replace(lpfile);
        if (GetModuleFileNameW(NULL, modname, MAX_PATH) > 0)
        {
            WCHAR tmp_path[MAX_PATH] = {0};
            if (PathRemoveFileSpecW(modname) && PathCombineW(tmp_path, modname, lpfile))
            {
                n = _snwprintf(lpfile, (size_t)len, L"%s", tmp_path);
            }
        }
    }
    return (n > 0 && n < len);
}

// 判断*pstr文件是否存在, *pstr必须是已分配的堆内存
// 如果它是相对路径, 转换为绝对路径, 会重新分配内存
bool
utf8_path_exist(char **pstr)
{
    bool ret = false;
    if (pstr && *pstr)
    {
        WCHAR *u16 = NULL;
        if (strlen(*pstr) > 0 && (u16 = path_utf8_utf16(*pstr)) != NULL)
        {
            size_t len = wcslen(u16);
            if (len < URL_LEN)
            {
                len = URL_LEN;
            }
            if (path_combine(u16, (const int)len))
            {
                char *tmp = NULL;
                if (PathFileExistsW(u16))
                {
                    ret = true;
                }
                if ((*pstr)[1] != ':' && (tmp = ini_utf16_utf8(u16, NULL)) != NULL)
                {
                    free(*pstr);
                    *pstr = tmp;
                }
            }
            free(u16);
        }
    }
    return ret;
}

int
get_cpu_works(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int) (si.dwNumberOfProcessors);
}

void
enter_spinlock(void)
{
    SIZE_T spinCount = 0;
    // Wait until the flag is false.
    while (_InterlockedCompareExchange(&g_locked, 1, 0) != 0)
    {
        // Prevent the loop from being too busy.
        if (spinCount < 32)
        {
            Sleep(0);
        }
        else
        {
            Sleep(1);
        }
        spinCount++;
    }
}

void
leave_spinlock(void)
{
    // No need to generate a memory barrier here, since InterlockedExchange()
    // generates a full memory barrier itself.
    InterlockedExchange(&g_locked, 0);
}

char *
check_memstr(char *full_data, int full_data_len, const char *substr)
{
    if (full_data == NULL || full_data_len <= 0 || substr == NULL || *substr == '\0')
    {
        return NULL;
    }
    const int sublen = (const int)strlen(substr);
    char *cur = full_data;
    int last_possible = full_data_len - sublen + 1;
    for (int i = 0; i < last_possible; i++)
    {
        if (*cur == *substr)
        {
            // assert(full_data_len - i >= sublen);
            if (memcmp(cur, substr, sublen) == 0)
            {
                // found
                return cur;
            }
        }
        cur++;
    }
    return NULL;
}

static inline size_t
get_file_lenth(LPCWSTR path)
{
    struct _stati64 statbuf;
    return (_wstati64(path, &statbuf) < 0 ? (size_t)0 : (size_t)statbuf.st_size);
}

WCHAR*
init_file_strings(LPCWSTR names, size_t *psize)
{
    bool ret = false;
    WCHAR *path = NULL;
    do
    {
        if ((path = (WCHAR *)calloc(1, sizeof(WCHAR) * URL_LEN)) == NULL)
        {
            break;
        }
        if (!GetModuleFileNameW(NULL, path, URL_LEN))
        {
            break;
        }
        if (!PathRemoveFileSpecW(path))
        {
            break;
        }
        if (!PathAppendW(path, names))
        {
            break;
        }
        if (!PathFileExistsW(path))
        {
            break;
        }
        if (psize)
        {
            *psize = get_file_lenth(path);
        }
        ret = true;
    } while (0);
    if (!ret)
    {
        free(path);
        path = NULL;
    }
    return path;
}

bool
find_local_str(char *result, const int len)
{
    FILE *fp = NULL;
    char *u = NULL;
    bool found = false;
    size_t buf_len = 0;
    char *buff = NULL;
    WCHAR *omni = NULL;
    const char *ctags = "chrome/zh-CN";
    if ((omni = init_file_strings(L"omni.ja", &buf_len)) == NULL)
    {
        printf("%s, init_file_strings() return false\n", __FUNCTION__);
        return false;
    }
    if (len < 5 || buf_len < 5)
    {
        free(omni);
        return false;
    }
    if ((fp = _wfopen(omni, L"rb")) == NULL)
    {
        printf("open omni.ja false\n");
        free(omni);
        return false;
    }
    if ((buff = (char *)malloc(buf_len)) == NULL)
    {
        fclose(fp);
        free(omni);
        return false;
    }
    if ((buf_len = fread(buff, 1, buf_len, fp)) > 0)
    {
        if ((u = check_memstr(buff, (int)buf_len, ctags)) != NULL)
        {
            u += strlen("chrome/");
            found = true;
        }
    }
    if (found)
    {
        strncpy(result, u, 5);
    }
    fclose(fp);
    free(omni);
    free(buff);
    return found;
}

/* 将hex编码的MD5转换成字符串 */
static void
md5_to_str(byte* in_md5_hex, char* out_md5_str)
{
    int i = 0;

    for (i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(out_md5_str + i * 2, "%.2x", in_md5_hex[i]);
    }
    out_md5_str[MD5_DIGEST_LENGTH * 2] = '\0';
}

bool
get_file_md5(LPCWSTR path, char* md5_str)
{
    bool res = false;
    BYTE*  pbHash=NULL;
    byte*  rgbFile=NULL;
    HANDLE hFile=NULL;
    HCRYPTPROV hProv=0;
    HCRYPTPROV hHash=0;
    do
    {
    #define MD5_SIZE 1024*1000*10
        DWORD cbRead;
        DWORD dwHashLen=sizeof(DWORD);

        hFile=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if (hFile==INVALID_HANDLE_VALUE)                                        //如果CreateFile调用失败
        {
            printf("CreateFile error : %lu\n", GetLastError());
            return false;
        }

        if(!CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))       //获得CSP中一个密钥容器的句柄
        {
            printf("CryptAcquireContext error : %lu\n", GetLastError());
            break;
        }

        if(!CryptCreateHash(hProv,CALG_MD5,0,0,&hHash))     //初始化对数据流的hash，创建并返回一个与CSP的hash对象相关的句柄
        {
            printf("CryptCreateHash error : %lu\n", GetLastError());
            break;
        }
        if((rgbFile=(byte*)calloc(MD5_SIZE, 1)) == NULL)
        {
            printf("allocation failed\n");
            break;

        }
        while (ReadFile(hFile,rgbFile,MD5_SIZE,&cbRead,NULL))
        {
            if (cbRead==0)        //读取文件
            {
                break;
            }
            if(!CryptHashData(hHash,rgbFile,cbRead,0))      //hash文件
            {
                printf("CryptHashData error : %lu\n", GetLastError());
                break;
            }
        }
        if (!CryptGetHashParam(hHash,HP_HASHVAL,NULL,&dwHashLen,0))      //获取内存长度
        {
            printf("CryptGetHashParam error : %lu\n", GetLastError());
        }
        if((pbHash=(byte*)calloc(dwHashLen, 1)) == NULL)
        {
            printf("allocation failed\n");
            break;

        }
        if(CryptGetHashParam(hHash,HP_HASHVAL,pbHash,&dwHashLen,0))  //获得md5值
        {
            md5_to_str(pbHash, md5_str);
            res = true;
        }
    #undef MD5_SIZE
    }while (0);
    if(hHash)          //销毁hash对象
    {
        CryptDestroyHash(hHash);
    }
    if(hProv)
    {
        CryptReleaseContext(hProv,0);
    }
    if (hFile)
    {
        CloseHandle(hFile);
    }
    if (rgbFile)
    {
        free(rgbFile);
    }
    if (pbHash)
    {
        free(pbHash);
    }
    return res;
}

HANDLE
create_new(LPCWSTR wcmd, LPCWSTR param, const LPCWSTR pcd, int flags, DWORD *opid, const int attached)
{
    PROCESS_INFORMATION pi = {0};
    WCHAR my_cmd[URL_LEN + 1] = { 0 };
#ifndef EUAPI_LINK
    if (!(wcmd || param))
    {
        GetModuleFileNameW(NULL, my_cmd, URL_LEN);
        PathRemoveFileSpecW(my_cmd);
        PathAppendW(my_cmd, L"tobedeleted");
        erase_dir(my_cmd);
        PathRemoveFileSpecW(my_cmd);
        if (attached < 2)
        {
            *my_cmd = 0;
        }
        else if (attached == 2)
        {
            PathAppendW(my_cmd, L"zen.exe");
        }
        else
        {
            PathAppendW(my_cmd, L"firefox.exe");
        }
    }
#endif
    if (wcmd)
    {
        wcsncpy(my_cmd, wcmd, URL_LEN);
    }
    if (param && *param)
    {
        wcsncat(my_cmd, L" ", URL_LEN);
        wcsncat(my_cmd, param, URL_LEN);
    }
    if (*my_cmd)
    {
        DWORD dwCreat = 0;
        STARTUPINFOW si = {si.cb = sizeof(si)};
        si.dwFlags = STARTF_USESHOWWINDOW;
        if (flags > 1)
        {
            si.wShowWindow = SW_SHOWNOACTIVATE;
        }
        else if (flags == 1)
        {
            si.wShowWindow = SW_MINIMIZE;
        }
        else if (!flags)
        {
            si.wShowWindow = SW_HIDE;
            dwCreat |= CREATE_NEW_PROCESS_GROUP;
        }
        if (!CreateProcessW(NULL, my_cmd, NULL, NULL, FALSE, dwCreat, NULL, pcd, &si, &pi))
        {
            printf("CreateProcessW error %lu\n", GetLastError());
            return NULL;
        }
        if (NULL != opid)
        {
            *opid = pi.dwProcessId;
        }
    }
    return pi.hProcess;
}

bool
exec_ppv(LPCSTR cmd, LPCSTR pcd, int flags)
{
    bool res = false;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    DWORD dw = 0;
    WCHAR *wdir = NULL;
    WCHAR *process = ini_utf8_utf16(cmd, NULL);
    if (!process)
    {
        return false;
    }
    do
    {
        if (NULL != pcd)
        {
            if (!(wdir = ini_utf8_utf16(pcd, NULL)))
            {
                break;
            }
        }
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        if (!flags)
        {
            si.wShowWindow = SW_HIDE;
            dw |= CREATE_NEW_PROCESS_GROUP;
        }
        else if (flags == 1)
        {
            si.wShowWindow = SW_SHOWNOACTIVATE;
        }
        else
        {
            si.wShowWindow = SW_NORMAL;
            dw |= CREATE_NEW_CONSOLE;
        }
        if(!CreateProcessW(NULL,
                          process,
                          NULL,
                          NULL,
                          false,
                          dw,
                          NULL,
                          wdir,
                          &si,&pi))
        {
            printf("CreateProcessw error %lu\n", GetLastError());
            break;
        }
        else
        {
            res = true;
        }
        CloseHandle(pi.hProcess);
    }while(0);
    if (wdir)
    {
        free(wdir);
    }
    if (process)
    {
        free(process);
    }
    return res;
}

const WCHAR *
get_file_name(LPCWSTR path)
{
    const WCHAR *p = wcsrchr(path, L'\\');
    if (p)
    {
        return (p + 1);
    }
    return NULL;
}

bool
search_process(LPCWSTR names)
{
    bool   ret = false;
    PROCESSENTRY32W pe32 = {0};
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hSnapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    pe32.dwSize=sizeof(pe32);
    if (!Process32FirstW(hSnapshot,&pe32))
    {
        return false;
    }
    do
    {
        if (!_wcsicmp(pe32.szExeFile, names) && pe32.th32ProcessID != GetCurrentProcessId())
        {
            ret = true;
            break;
        }
    } while (Process32NextW(hSnapshot,&pe32));
    CloseHandle(hSnapshot);
    return ret;
}

char*
url_decode(const char *input)
{
    char *working, *output;
    size_t output_length = (int)strlen(input) + NAMES_LEN;
    if ((working = output = calloc(1, output_length)) == NULL)
    {
        return NULL;
    }
    while(*input)
    {
        if(*input == '%')
        {
            char buffer[3] = {input[1], input[2], 0};
            *working = (char)strtol(buffer, NULL, 16);
            working++;
            input += 3;
        }
        else
        {
            *working++ = *input++;
        }
    }
    return output;
}

wchar_t *
u16_dec_path(const wchar_t *path)
{
    char *dec_u8 = NULL;
    wchar_t *dec_path = NULL;
    char *u8_path = ini_utf16_utf8(path, NULL);
    if (u8_path && (dec_u8 = url_decode(u8_path)) != NULL)
    {
        dec_path = ini_utf8_utf16(dec_u8, NULL);
    }
    ini_safe_free(dec_u8);
    ini_safe_free(u8_path);
    return dec_path;
}

WCHAR *
get_process_path(WCHAR *path, const int len)
{
    WCHAR *p = NULL;
    if (!GetModuleFileNameW(NULL , path, len - 1))
    {
        return NULL;
    }
    if ((p = wcsrchr(path , L'\\')) != NULL)
    {
        *p = 0;
    }
    return path;
}

size_t
get_first_line(char **lineptr, const WCHAR *path)
{
    size_t len = 0;
    FILE * stream = _wfopen(path, L"rb");
    if (stream)
    {
        int trash = 0;
        char *buf = NULL;
        while (!feof(stream))
        {
            trash = fgetc(stream);
            if (trash == '\n')
            {
                break;
            }
            ++len;
        }
        fseek(stream, 0, SEEK_SET);
        if (len > 0 && (buf = (char *)malloc(len + 1)) != NULL)
        {
            if ((len = fread(buf, 1, len, stream)) > 0)
            {
                buf[len] = 0;
                *lineptr = buf;
            }
        }
        fclose(stream);
    }
    if (!len)
    {
        *lineptr = _strdup("");
    }
    return len;
}

CURLcode
libcurl_init(long flags)
{
    if (euapi_curl_global_init)
    {
        return CURLE_OK;
    }
#if defined(EUAPI_LINK) && EUAPI_LINK > 0
    WCHAR path[MAX_PATH + 1] = {0};
    WCHAR main_path[MAX_PATH + 1] = {0};
    if (!get_process_path(path, MAX_PATH)[0])
    {
        return CURLE_FAILED_INIT;
    }
    _snwprintf(main_path, MAX_PATH, L"%s", path);
    PathRemoveFileSpecW(main_path);
    if (!enviroment_variables_set(L"PATH", main_path, VARIABLES_APPEND))
    {
        return CURLE_FAILED_INIT;
    }
    wcsncat(path, L"\\libcurl.dll" , MAX_PATH);
    if (!curl_symbol && !(curl_symbol = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH)))
    {
        printf("LoadLibraryExW[%ls] failed, cause: %lu\n", path, GetLastError());
        return CURLE_FAILED_INIT;
    }
    euapi_curl_global_init = (ptr_curl_global_init)GetProcAddress(curl_symbol,"curl_global_init");
    euapi_curl_easy_init = (ptr_curl_easy_init)GetProcAddress(curl_symbol,"curl_easy_init");
    euapi_curl_global_cleanup = (ptr_curl_global_cleanup)GetProcAddress(curl_symbol,"curl_global_cleanup");
    euapi_curl_easy_cleanup = (ptr_curl_easy_cleanup)GetProcAddress(curl_symbol,"curl_easy_cleanup");
    euapi_curl_easy_setopt = (ptr_curl_easy_setopt)GetProcAddress(curl_symbol,"curl_easy_setopt");
    euapi_curl_easy_perform = (ptr_curl_easy_perform)GetProcAddress(curl_symbol,"curl_easy_perform");
    euapi_curl_slist_append = (ptr_curl_slist_append)GetProcAddress(curl_symbol,"curl_slist_append");
    euapi_curl_slist_free_all = (ptr_curl_slist_free_all)GetProcAddress(curl_symbol,"curl_slist_free_all");
    euapi_curl_easy_getinfo = (ptr_curl_easy_getinfo)GetProcAddress(curl_symbol,"curl_easy_getinfo");
    euapi_curl_easy_strerror = (ptr_curl_easy_strerror)GetProcAddress(curl_symbol,"curl_easy_strerror");
    euapi_curl_share_init = (ptr_curl_share_init)GetProcAddress(curl_symbol,"curl_share_init");
    euapi_curl_share_setopt = (ptr_curl_share_setopt)GetProcAddress(curl_symbol,"curl_share_setopt");
    euapi_curl_share_cleanup = (ptr_curl_share_cleanup)GetProcAddress(curl_symbol,"curl_share_cleanup");
    euapi_curl_easy_reset = (ptr_curl_easy_reset)GetProcAddress(curl_symbol,"curl_easy_reset");
#else
    euapi_curl_global_init = curl_global_init;
    euapi_curl_easy_init = curl_easy_init;
    euapi_curl_global_cleanup = curl_global_cleanup;
    euapi_curl_easy_cleanup = curl_easy_cleanup;
    euapi_curl_easy_setopt = curl_easy_setopt;
    euapi_curl_easy_perform = curl_easy_perform;
    euapi_curl_slist_append = curl_slist_append;
    euapi_curl_slist_free_all = curl_slist_free_all;
    euapi_curl_easy_getinfo = curl_easy_getinfo;
    euapi_curl_easy_strerror = curl_easy_strerror;
    euapi_curl_share_init = curl_share_init;
    euapi_curl_share_setopt = curl_share_setopt;
    euapi_curl_share_cleanup = curl_share_cleanup;
    euapi_curl_easy_reset = curl_easy_reset;
#endif
    if (euapi_curl_global_init && euapi_curl_easy_init && euapi_curl_global_cleanup && euapi_curl_easy_setopt && euapi_curl_easy_perform &&
        euapi_curl_easy_cleanup && euapi_curl_slist_append && euapi_curl_slist_free_all && euapi_curl_easy_getinfo && euapi_curl_easy_strerror &&
        euapi_curl_share_init && euapi_curl_share_setopt && euapi_curl_share_cleanup && euapi_curl_easy_reset)
    {
        return euapi_curl_global_init(flags);
    }
    return CURLE_FAILED_INIT;
}

void
libcurl_destory(void)
{
    if (euapi_curl_global_cleanup)
    {
        euapi_curl_global_cleanup();
        if (curl_symbol)
        {
            FreeLibrary(curl_symbol);
            curl_symbol = NULL;
        }
        euapi_curl_global_init = NULL;
        euapi_curl_easy_init = NULL;
        euapi_curl_global_cleanup = NULL;
        euapi_curl_easy_setopt = NULL;
        euapi_curl_easy_perform = NULL;
        euapi_curl_easy_cleanup = NULL;
        euapi_curl_slist_append = NULL;
        euapi_curl_slist_free_all = NULL;
        euapi_curl_easy_getinfo = NULL;
        euapi_curl_easy_strerror = NULL;
        euapi_curl_share_init = NULL;
        euapi_curl_share_setopt = NULL;
        euapi_curl_share_cleanup = NULL;
        euapi_curl_easy_reset = NULL;
    }
}

void
libcurl_set_proxy(CURL *curl)
{
    if (curl && file_info.ini[0])
    {
        if (file_info.ini_proxy[0])
        {
            euapi_curl_easy_setopt(curl, CURLOPT_PROXY, file_info.ini_proxy);
            if (file_info.ini_usewd[0])
            {
                euapi_curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, file_info.ini_usewd);
            }
        }
    }
}

void
libcurl_set_ssl(CURL *curl)
{
    if (get_os_version() > 603)
    {
        euapi_curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, EUAPI_CERT | CURLSSLOPT_NO_REVOKE);
        euapi_curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
    }
    else
    {   // 不受支持的操作系统证书可能过期
        euapi_curl_easy_setopt(curl, CURLOPT_SSLVERSION, 0);
        euapi_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        euapi_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
}

HANDLE
share_create(HANDLE handle, uint32_t dw_protect, size_t size, LPCWSTR name)
{
    DWORD hi = 0, lo = 0;
    if (size > 0)
    {
        lo = (uint32_t) (size & 0xffffffff);
        hi = (uint32_t) (((uint64_t) size >> 32) & 0xffffffff);
    }
    if (!handle)
    {
        return CreateFileMapping(INVALID_HANDLE_VALUE, NULL, dw_protect, hi, lo, name);
    }
    return CreateFileMapping(handle, NULL, dw_protect, hi, lo, name);
}

HANDLE
share_open(uint32_t dw_access, LPCWSTR name)
{
    return OpenFileMapping(dw_access, false, name);
}

LPVOID
share_map(HANDLE hmap, size_t bytes, uint32_t dw_access)
{
    return MapViewOfFile(hmap, dw_access, 0, 0, bytes);
}

void
share_unmap(LPVOID memory)
{
    if (memory)
    {
        UnmapViewOfFile(memory);
        memory = NULL;
    }
}

void
share_close(HANDLE handle)
{
    if ((intptr_t)handle > 0)
    {
        CloseHandle(handle);
        handle = NULL;
    }
}

bool
enviroment_variables_set(LPCWSTR szname, LPCWSTR sz_newval, sys_flag dw_flag)
{
    DWORD dw_err;
    LPWSTR sz_val;
    DWORD dw_result;
    /* 附加到指定环境变量末尾 */
    if (dw_flag == VARIABLES_APPEND)
    {
        if (!(sz_val = (LPWSTR)malloc((BUFSIZE + 1) *2)))
        {
            return false;
        }
        /* 获取指定环境变量的值 */
        dw_result = GetEnvironmentVariableW(szname, sz_val, BUFSIZE);
        if (dw_result == 0) /* 出错处理 */
        {
            dw_err = GetLastError();
            if (ERROR_ENVVAR_NOT_FOUND == dw_err)
            {
                printf("Environment variable %ls does not exist.\n", szname);
            }
            else
            {
                printf("error: %lu\n", dw_err);
            }
            free(sz_val);
            return false;
        }
        if (BUFSIZE <= dw_result) /* 缓冲区太小 */
        {
            DWORD new_valsize = (DWORD)wcslen(sz_newval) + dw_result;
            sz_val = (LPWSTR) realloc(sz_val, (new_valsize + 1) * 2);
            if (NULL == sz_val)
            {
                printf("Memory error\n");
                return false;
            }
            if (!(dw_result = GetEnvironmentVariableW(szname, sz_val, new_valsize)))
            {
                free(sz_val);
                printf("GetEnvironmentVariable failed (%lu)\n", GetLastError());
                return false;
            }
        }
        wcscat(sz_val, L";");      /* 分隔符 */
        wcscat(sz_val, sz_newval); /* 追加 */
        if (!SetEnvironmentVariableW(szname, sz_val))
        {
            printf("Set Value Error %lu", GetLastError());
            free(sz_val);
            return false;
        }
        free(sz_val);
    }
    /* 设置新的环境变量 */
    else if (dw_flag == VARIABLES_RESET)
    {
        if (!SetEnvironmentVariableW(szname, sz_newval))
        {
            printf("Set value error %lu\n", GetLastError());
            return false;
        }
    }
    /* 指定环境变量清零 */
    else if (dw_flag == VARIABLES_NULL)
    {
        if (!SetEnvironmentVariableW(szname, NULL))
        {
            printf("Set value error %lu\n", GetLastError());
            return false;
        }
    }
    return true;
}

const uint32_t
get_os_version(void)
{
    typedef void (WINAPI *RtlGetNtVersionNumbersPtr)(DWORD*, DWORD*, DWORD*);
    RtlGetNtVersionNumbersPtr fnRtlGetNtVersionNumbers = NULL;
    uint32_t major_ver, minor_ver, build_num;
    uint32_t ver = 0;
    HMODULE nt_dll = GetModuleHandleW(L"ntdll.dll");
    if (nt_dll)
    {
        fnRtlGetNtVersionNumbers = (RtlGetNtVersionNumbersPtr)GetProcAddress(nt_dll, "RtlGetNtVersionNumbers");
    }
    if (fnRtlGetNtVersionNumbers)
    {
    #define VER_NUM 5
        WCHAR pos[VER_NUM] = { 0 };
        fnRtlGetNtVersionNumbers(&major_ver, &minor_ver,&build_num);
        _snwprintf(pos, VER_NUM, L"%u%d%u", major_ver, 0, minor_ver);
        ver = wcstol(pos, NULL, 10);
    #undef VER_NUM
    }
    return ver;
}

LPWSTR
wstr_replace(LPWSTR in, size_t in_size, LPCWSTR pattern, LPCWSTR by)
{
    WCHAR *in_ptr = in;
    WCHAR res[URL_LEN] = { 0 };
    size_t offset = 0;
    WCHAR *needle;
    while ((needle = StrStrW(in, pattern)) && offset < in_size && offset < URL_LEN)
    {
        wcsncpy(res + offset, in, needle - in);
        offset += needle - in;
        in = needle + (int) wcslen(pattern);
        wcsncpy(res + offset, by, URL_LEN - offset);
        offset += (int) wcslen(by);
    }
    wcsncpy(res + offset, in, URL_LEN - offset);
    _snwprintf(in_ptr, in_size, L"%s", res);
    return in_ptr;
}

char*
str_replace(char *in, const size_t in_size, const char *pattern, const char *by)
{
    char *in_ptr = in;
    char res[URL_LEN] = {0};
    size_t offset = 0;
    char *needle;
    while ((needle = strstr(in, pattern)) && offset < in_size && offset < URL_LEN)
    {
        strncpy(res + offset, in, needle - in);
        offset += needle - in;
        in = needle + (int) strlen(pattern);
        strncpy(res + offset, by, URL_LEN - offset);
        offset += (int) strlen(by);
    }
    strncpy(res + offset, in, URL_LEN - offset);
    _snprintf(in_ptr, in_size, "%s", res);
    in = in_ptr;
    return in;
}

int
do_file_copy(LPCWSTR parent, copy_file_ptr fnback, const bool recurs)
{
    int ret = 0;
    HANDLE hfile = NULL;
    WIN32_FIND_DATAW fd = {0};
    WCHAR pathname[MAX_PATH] = {0};
    WCHAR sub[MAX_PATH] = {0};
    BOOL  finded = TRUE;
    if(parent[wcslen(parent) -1] != '\\')
    {
        _snwprintf(pathname, MAX_PATH, L"%s\\*.*", parent);
    }
    else
    {
        _snwprintf(pathname, MAX_PATH, L"%s*.*", parent);
    }
    if ((hfile = FindFirstFileW(pathname, &fd)) != INVALID_HANDLE_VALUE)
    {
        do
        {
            if(wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
            {
                _snwprintf(sub, MAX_PATH, L"%s\\%s", parent, fd.cFileName);
                if (recurs && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                {
                    do_file_copy(sub, fnback, true);
                }
                else if (fnback(sub))
                {
                    ret = 1;
                    break;
                }
            }
        } while (FindNextFileW(hfile, &fd) != 0);
        FindClose(hfile);
    }
    if (recurs)
    {
        RemoveDirectoryW(parent);
    }
    return ret;
}

void
erase_dir(LPCWSTR parent)
{
    HANDLE hfile = NULL;
    WIN32_FIND_DATAW fd = {0};
    WCHAR path_name[MAX_PATH] = {0};
    WCHAR sub[MAX_PATH] = {0};
    if( parent[wcslen(parent) -1] != '\\' )
    {
        _snwprintf(path_name, MAX_PATH, L"%s\\*.*", parent);
    }
    else
    {
        _snwprintf(path_name, MAX_PATH, L"%s*.*", parent);
    }
    if ((hfile = FindFirstFileW(path_name, &fd)) != INVALID_HANDLE_VALUE)
    {
        do
        {
            if(wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
            {
                _snwprintf(sub, MAX_PATH, L"%s\\%s", parent, fd.cFileName);
                if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    erase_dir(sub);
                }
                else
                {
                    DeleteFileW(sub);
                }
            }
        } while (FindNextFileW(hfile, &fd) != 0);
        FindClose(hfile);
    }
    RemoveDirectoryW(parent);
}

wchar_t *
strpath_copy(wchar_t *s1, const wchar_t *s2)
{
    wchar_t *s = s1;
    for (; *s2 != L'\0'; )
    {
        if (*s2 == L'\\')
        {
            *s = L'\0';
            break;
        }
        else
        {
            (*s++ = *s2++);
        }
    }
    return s1;
}

bool
getw_cwd(LPWSTR lpstr, DWORD wlen)
{
    int   i = 0;
    WCHAR fullpath[MAX_PATH+1] = {0};
    if (GetModuleFileNameW(NULL, fullpath, MAX_PATH) > 0)
    {
        for(i = (int)wcslen(fullpath); i>0; i--)
        {
            if (fullpath[i] == L'\\')
            {
                fullpath[i] = L'\0';
                break;
            }
        }
        if (i > 0)
        {
            i = _snwprintf(lpstr, wlen, L"%s", fullpath);
        }
    }
    return (i > 0 && i < (int)wlen);
}
