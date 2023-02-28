#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <curl/curl.h>
#include "ini_parser.h"
#include "spinlock.h"

extern file_info_t file_info;

typedef size_t (*fn_write_data)(void *contents, size_t size, size_t nmemb, void *userp);

static size_t
write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    DWORD written;
    WriteFile(stream, ptr, (DWORD)(size * nmemb), &written, NULL);
    return written;
}

int
init_process(const char *url, fn_write_data write_data, void *userdata)
{
    CURLcode res = 1;
    CURL *curl_handle = euapi_curl_easy_init();

    if (curl_handle)
    {
        euapi_curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_ACCEPT_ENCODING, "");
        euapi_curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, userdata);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 3L);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "aria2/1.34.0");
        euapi_curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_SSL_OPTIONS, EUAPI_CERT | CURLSSLOPT_NO_REVOKE);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_USE_SSL, CURLUSESSL_TRY);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 60L);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 90L);
        res = euapi_curl_easy_perform(curl_handle);
        if (res != CURLE_OK)
        {
            printf("euapi_curl_easy_perform() failed: %s\n", euapi_curl_easy_strerror(res));
        }
        euapi_curl_easy_cleanup(curl_handle);
    }
    return (int) res;
}

static bool
is_64bit_os(void)
{
    SYSTEM_INFO info = {0};
    GetNativeSystemInfo(&info);
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 || info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
    {
        return true;
    }
    return false;
}

static int
search_file_bits(const wchar_t* path)
{
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS pe_header;
    int      ret = 0;
    HANDLE    hFile = CreateFileW(path,GENERIC_READ,
                                FILE_SHARE_READ,NULL,OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,NULL);
    if( hFile == INVALID_HANDLE_VALUE )
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

/* 主进程是64位, 函数返回64 */
/* 主进程是32位, 函数返回32 */
/* 主进程已退出, 函数返回0  */
static int
get_file_bits(void)
{
    int  bits = 0;
    char *dll = NULL;
    HANDLE hProcess = NULL;
    bool x64 = is_64bit_os();
    do
    {
        int wow64 = 0;
        if (!x64)
        {
            bits = 32;
            break;
        }
        if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, file_info.pid)) == NULL)
        {
            char dll[MAX_PATH+1] = {0};
            WCHAR wdll[MAX_PATH+1] = {0};
            printf("OpenProcess(%lu) failed, cause: %lu\n", file_info.pid, GetLastError());
            if (!init_file_strings(L"mozglue.dll", dll))
            {
                printf("init_file_strings mozglue.dll return false\n");
                break;
            }
            if (!MultiByteToWideChar(CP_UTF8, 0, dll, -1, wdll, MAX_PATH))
            {
                printf("MultiByteToWideChar return false\n");
                break;
            }
            if ((bits = search_file_bits(wdll)) == 0)
            {
                printf("search_file_bits mozglue.dll return false\n");
            }
            break;
        }
        if (!IsWow64Process(hProcess, &wow64))
        {
            printf("IsWow64Processreturn false\n");
            break;
        }
        if (wow64)
        {
            bits = 32;
        }
        else
        {
            bits = 64;
        }
    } while (0);
    if (hProcess)
    {
        CloseHandle(hProcess);
    }
    return bits;
}

static bool
ini_query(const char *ini)
{
#define INFO_LEN 16
    bool res = false;
    uint64_t dt_remote = 0;
    uint64_t dt_locale = 0;
    char result[6] = { 0 };
    char app_ini[MAX_PATH + 1] = {0};
    char info[INFO_LEN + 1] = {0};
    char *url = NULL;
    char *c_md5 = NULL;
    int   bits = get_file_bits();
    if (bits == 64)
    {
        printf("is_64bits\n");
        strncpy(info, "win64.", INFO_LEN);
    }
    else if (bits == 32)
    {
        printf("is_32bits\n");
        strncpy(info, "win32.", INFO_LEN);
    }
    else
    {
        printf("unknown platform\n");
        return false;
    }
    if (find_local_str(result, 5) && strcmp(result, "zh-CN") == 0)
    {
        printf("locales:zh-CN\n");
        strncat(info, "zh-CN", INFO_LEN);
    }
    else
    {
        printf("locales:en-US\n");
        strncat(info, "en-US", INFO_LEN);
    }
    do
    {
        if (!init_file_strings(L"application.ini", app_ini))
        {
            printf("init_file_strings application.ini return false\n");
            break;
        }
        if ((dt_locale = ini_read_uint64("App", "BuildID", app_ini)) > 0)
        {
            dt_remote = ini_read_uint64("updates", info, ini);
        }
        if (dt_locale >= dt_remote)
        {
            printf("dt_locale(%I64u) >= dt_remote(%I64u), do not update\n", dt_locale, dt_remote);
            break;
        }
        if (!ini_read_string(info, "url", &url, ini))
        {
            printf("ini_read_string url return false\n");
            break;
        }
        if (!ini_read_string(info, "md5", &c_md5, ini))
        {
            printf("ini_read_string md5 return false\n");
            break;
        }
        strncpy(file_info.md5, c_md5, MD5_LEN);
        strncpy(file_info.url, url, URL_LEN);
    }while(0);
    if (c_md5)
    {
        free(c_md5);
    }
    if (url)
    {
        free(url);
    }
    return true;
#undef INFO_LEN
}

/* 连不上更新服务器或函数执行失败,返回-1 */
/* 需要更新,返回0                        */
/* 不需要更新,返回1                      */
#if defined(__clang__)
# pragma clang optimize off
#elif defined(_MSC_VER)
# pragma optimize("g", off)
#endif
int
init_resolver(void)
{
    HANDLE pfile;
    WCHAR temp_path[MAX_PATH];
    WCHAR temp_names[MAX_PATH];
    char  ini_names[MAX_PATH + 1] = {0};
    char* url = NULL;
    int   res = -1;
    if (!GetTempPathW(MAX_PATH, temp_path))
    {
        return res;
    }
    if (!GetTempFileNameW(temp_path, L"INI", 0, temp_names))
    {
        printf("GetTempFileNameW return false\n");
        return res;
    }
    if (!ini_read_string("update", "url", &url, file_info.ini))
    {
        printf("ini_read_string portable.ini update return false\n");
        return res;
    }
    pfile = CreateFileW(temp_names, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (pfile == INVALID_HANDLE_VALUE)
    {
        SYS_FREE(url);
        printf("CreateFileW temp file return false\n");
        return res;
    }
    res = init_process(url, &write_data, pfile);
    CloseHandle(pfile);
    if (res != CURLE_OK)
    {
        res = -1;
    }
    else
    {
        FlushFileBuffers(pfile);
        WideCharToMultiByte(CP_UTF8, 0, temp_names, -1, ini_names, MAX_PATH, NULL, NULL);
        res = !ini_query(ini_names);
    }
    SYS_FREE(url);
    DeleteFileW(temp_names);
    return res;
}
#if defined(__clang__)
# pragma clang optimize on
#elif defined(_MSC_VER)
# pragma optimize("g", on)
#endif
