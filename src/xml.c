#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <curl/curl.h>
#include "ini_parser.h"
#include "spinlock.h"

#define INFO_LEN 32

typedef struct _xml_buffer
{
    int size;
    int cur;
    char str[MAX_BUFFER_SIZE];
}xml_buffer;

typedef size_t (*fn_write_data)(void *contents, size_t size, size_t nmemb, void *userp);

static size_t
write_data_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    xml_buffer *pbuf = (xml_buffer *)stream;
    int written = (int)(size * nmemb);
    if (written < pbuf->size)
    {
        memcpy(&pbuf->str[pbuf->cur], ptr, written);
        pbuf->cur += written;
        pbuf->size -= written;
    }
    else
    {
        written = 0;
    }
    return (size_t)written;
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
        euapi_curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "aria2/1.36.0");
        euapi_curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_SSL_OPTIONS, EUAPI_CERT | CURLSSLOPT_NO_REVOKE);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_USE_SSL, CURLUSESSL_TRY);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 60L);
        euapi_curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 90L);
        // 设置代理
        libcurl_set_proxy(curl_handle);
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
    WCHAR *dll = NULL;
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
            printf("OpenProcess(%u) failed, cause: %lu\n", file_info.pid, GetLastError());
        #if EUAPI_LINK
            if ((dll = init_file_strings(L"libcurl.dll", NULL)) == NULL)
            {
                printf("init_file_strings libcurl.dll return false\n");
                break;
            }
        #else
            if ((dll = init_file_strings(L"mozglue.dll", NULL)) == NULL)
            {
                printf("init_file_strings mozglue.dll return false\n");
                break;
            }
        #endif
            if ((bits = search_file_bits(dll)) == 0)
            {
                printf("search_file_bits [mozglue.dll|libcurl.dll] return false\n");
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
    if (dll)
    {
        free(dll);
    }
    return bits;
}

static int
ini_query_edit(xml_buffer *pbuf)
{
    int res = -1;
    char *c_md5 = NULL;
    char *url = NULL;
    char info[INFO_LEN + 1] = {0};
    uint64_t dt_remote = 0;
    ini_cache ini_handler = NULL;
    int  bits = get_file_bits();
    if (bits == 64)
    {
        printf("is_64bits\n");
        strncpy(info, "x64", INFO_LEN);
    }
    else if (bits == 32)
    {
        printf("is_32bits\n");
        strncpy(info, "x86", INFO_LEN);
    }
    else
    {
        printf("unknown platform\n");
        return res;
    }
    if (!(ini_handler = iniparser_create_cache(pbuf->str, pbuf->cur, false)))
    {
        printf("iniparser_create_cache return false\n");
        return res;
    }
    while (file_info.dt_local > 0 && (dt_remote = inicache_read_uint64("updates", info, &ini_handler)) > 0)
    {
        res = dt_remote > file_info.dt_local ? 0 : 1;
        if (res == 0)
        {
            if (!inicache_read_string(info, "url", &url, &ini_handler))
            {
                printf("ini_read_string url return false\n");
                res = -1;
                break;
            }
            if (!inicache_read_string(info, "md5", &c_md5, &ini_handler))
            {
                printf("ini_read_string md5 return false\n");
                res = -1;
                break;
            }
            strncpy(file_info.md5, c_md5, MD5_LEN);
            strncpy(file_info.url, url, URL_LEN);
        }
        break;
    }
    ini_safe_free(c_md5);
    ini_safe_free(url);
    iniparser_destroy_cache(&ini_handler);
    return res;
}

static int
ini_query_ice(xml_buffer *pbuf)
{

    int res = -1;
    uint64_t dt_remote = 0;
    uint64_t dt_locale = 0;
    char result[6] = { 0 };
    char info[INFO_LEN + 1] = {0};
    char *url = NULL;
    char *c_md5 = NULL;
    char *app_ini = NULL;
    WCHAR *pini = NULL;
    ini_cache ini_handler = NULL;
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
        return res;
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
    if (get_os_version() < 100)
    {
        strncat(info, ".esr", INFO_LEN);
    }
    do
    {
        if (!(ini_handler = iniparser_create_cache(pbuf->str, pbuf->cur, false)))
        {
            printf("iniparser_create_cache return false\n");
            break;
        }
        if ((pini = init_file_strings(L"application.ini", NULL)) == NULL)
        {
            printf("init_file_strings application.ini return false\n");
            break;
        }
        if ((app_ini = ini_utf16_utf8(pini, NULL)) == NULL)
        {
            break;
        }
        if ((dt_locale = ini_read_uint64("App", "BuildID", app_ini, true)) > 0)
        {
            dt_remote = inicache_read_uint64("updates", info, &ini_handler);
        }
        if (dt_locale >= dt_remote)
        {
            printf("dt_locale(%I64u) >= dt_remote(%I64u), do not update\n", dt_locale, dt_remote);
            res = 1;
            break;
        }
        if (!inicache_read_string(info, "url", &url, &ini_handler))
        {
            printf("inicache_read_string url return false\n");
            res = strstr(info, ".esr") ? 1 :-1;
            break;
        }
        if (!inicache_read_string(info, "md5", &c_md5, &ini_handler))
        {
            printf("inicache_read_string md5 return false\n");
            res = -1;
            break;
        }
        strncpy(file_info.md5, c_md5, MD5_LEN);
        strncpy(file_info.url, url, URL_LEN);
        printf("dt_locale = %I64u, dt_remote = %I64u, c_md5 = %s, app_url = %s\n", dt_locale, dt_remote, c_md5, url);
        res = 0;
    }while(0);
    ini_safe_free(c_md5);
    ini_safe_free(url);
    ini_safe_free(pini);
    ini_safe_free(app_ini);
    iniparser_destroy_cache(&ini_handler);
    return res;
}

/* 连不上更新服务器或函数执行失败,返回-1 */
/* 需要更新,返回0                        */
/* 不需要更新,返回1                      */
int
init_resolver(void)
{
    char* url = NULL;
    int   res = -1;
    xml_buffer xbuf = {MAX_BUFFER_SIZE};
    if (*file_info.ini && !ini_read_string("update", "url", &url, file_info.ini, true))
    {
        printf("ini_read_string portable.ini update return false\n");
        return res;
    }
    else if (*file_info.ini_uri && !(url = _strdup(file_info.ini_uri)))
    {
        printf("file_info.ini_uri maybe null\n");
        return res;
    }
    if ((res = init_process(url, &write_data_callback, &xbuf)) != CURLE_OK)
    {
        printf("init_process[%s] error, cause: %d\n", url, res);
        res = -1;
    }
    else
    {
        if (file_info.ini_uri[0])
        {
            res = ini_query_edit(&xbuf);
        }
        else
        {
            res = ini_query_ice(&xbuf);
        }
    }
    ini_safe_free(url);
    return res;
}
