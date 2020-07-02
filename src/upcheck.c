#ifndef CURL_STATICLIB
#define CURL_STATICLIB
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>
#include <process.h>
#include <shlwapi.h>
#include <shlobj.h>
#include "upcheck.h"
#include "ini_parser.h"
#include "urlcode.h"
#include "7zc.h"
#include "progressui.h"
#include "updates.h"
#include "xml.h"
#include "cookies.h"
#include "thunderagent.h"

typedef HRESULT (WINAPI *SHGetKnownFolderIDListPtr)(REFKNOWNFOLDERID rfid,
        DWORD            dwFlags,
        HANDLE           hToken,
        PIDLIST_ABSOLUTE *ppidl);
        
static int64_t downloaded_size;
static int64_t total_size;
static LOCK_MUTEXT g_mutex;
static SHGetKnownFolderIDListPtr sSHGetKnownFolderIDListStub;

file_info_t file_info;

static bool
ini_path_init(void)
{
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
}

static HWND
get_moz_hwnd(void)
{
    HWND hwnd = NULL;
    int i = 10;
    while (!hwnd && i--)
    {
        bool m_loop = false;
        DWORD dwProcessId = 0;
        hwnd = FindWindowExW(NULL, hwnd, L"MozillaWindowClass", NULL);
        GetWindowThreadProcessId(hwnd, &dwProcessId);
        m_loop = (dwProcessId > 0 && dwProcessId == file_info.pid);
        if (!m_loop)
        {
            hwnd = NULL;
        }
        if (NULL != hwnd && m_loop)
        {
            break;
        }
        SleepEx(800, false);
    }
    return hwnd;
}

/* 智能分析需要保持的文件名并建立目录 */
static void
path_parsing(LPCWSTR save_path)
{
    if (NULL == save_path)
    {
        return;
    }
    if (PathFindExtensionW(save_path)[0] == L'.')
    {
        _snwprintf(file_info.names, MAX_PATH, L"%ls", save_path);
    }
    else if (!PathIsFileSpecW(save_path) && save_path[1] == L':')
    {
        size_t len = 0;
        _snwprintf(file_info.names, MAX_PATH, L"%ls", save_path);
        len = wcslen(file_info.names);
        if (file_info.names[len - 1] != L'\\')
        {
            file_info.names[len] = L'\\';
        }
        create_dir(save_path);
        return;
    }
    else
    {
        // is file
        WCHAR tmp_path[MAX_PATH + 1] = { 0 };
        _snwprintf(tmp_path, MAX_PATH, L"%ls\\%ls", save_path, file_info.names);
        path_combine(tmp_path, MAX_PATH);
        _snwprintf(file_info.names, MAX_PATH, L"%ls", tmp_path);
    }
    if (true)
    {
        // creator dir
        WCHAR path[MAX_PATH + 1] = { 0 };
        _snwprintf(path, MAX_PATH, L"%ls", file_info.names);
        if (PathRemoveFileSpecW(path))
        {
            create_dir(path);
        }
    }
}

static bool
init_command_data(void)
{
    int i;
    bool found = false;
    WCHAR **pv = &__wargv[1];
    for (i = 0; i < __argc - 1; i++)
    {
        if (_wcsicmp(pv[i], L"-i") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            WCHAR tmp[URL_LEN + 1] = { 0 };
            _snwprintf(tmp, URL_LEN, L"%ls", pv[i + 1]);
            if (wcscmp(tmp, L"auto") == 0)
            {
                // 自动分析ini文件下载
                if (!ini_path_init())
                {
                    return false;
                }
                else
                {
                    continue;
                }
            }
            else
            {
                // 直接获得url参数, 转换成utf-8编码
                if (!WideCharToMultiByte(CP_UTF8, 0, tmp, -1, file_info.url, sizeof(file_info.url), NULL, NULL))
                {
                    return false;
                }
                else if (strstr(file_info.url, "baidu.com") || strstr(file_info.url, "www.baidupcs.com"))
                {
                    _snprintf(file_info.referer, VALUE_LEN, "https://pan.baidu.com/disk/home");
                }                
            }
        } // 下载目录
        else if (_wcsicmp(pv[i], L"-o") == 0)
        {
            found = true;
            VERIFY(i + 1 < __argc - 1);
            path_parsing(pv[i + 1]);
        } // 下载时线程数目
        else if (_wcsicmp(pv[i], L"-t") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            file_info.thread_num = _wtoi(pv[i + 1]);
        } // 断线重连
        else if (_wcsicmp(pv[i], L"-r") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            file_info.re_bind = _wtoi(pv[i + 1]);
        } // 杀死进程
        else if (_wcsicmp(pv[i], L"-k") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            file_info.pid = _wtoi(pv[i + 1]);
        } // 设置cookies
        else if (_wcsicmp(pv[i], L"-b") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            WCHAR *dot = NULL;
            WCHAR cookies[VALUE_LEN + 1] = { 0 };
            char  un_cookies[MAX_PATH + 1] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, pv[i + 1], -1, un_cookies, MAX_PATH, NULL, NULL);
            char *u8_cookies = url_decode(un_cookies);
            if (u8_cookies == NULL)
            {
                continue;
            }
            MultiByteToWideChar(CP_UTF8, 0, u8_cookies, -1, cookies, VALUE_LEN);
            SYS_FREE(u8_cookies);
            dot = wcsrchr(cookies, L'.');
            if (dot && _wcsicmp(dot + 1, L"sqlite") == 0)
            {              
                /* encode with sqlite3 */
                if (dump_cookies(cookies))
                {
                    printf("convert sqlite to txt fail.\n");
                }
                continue;
            }
            WideCharToMultiByte(CP_UTF8, 0, cookies, -1, file_info.cookies, sizeof(file_info.cookies), NULL, NULL);
        } // 解压目录
        else if (_wcsicmp(pv[i], L"-e") == 0)
        {
            file_info.extract = true;
            VERIFY(i + 1 < __argc - 1);
            _snwprintf(file_info.unzip_dir, MAX_PATH, L"%ls", pv[i + 1]);
        } // 更新完毕后启动的进程名
        else if (_wcsicmp(pv[i], L"-s") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            if (!ini_path_init())
            {
                return false;
            }
            _snwprintf(file_info.process, MAX_PATH, L"%ls", pv[i + 1]);
        }
        else if (_wcsicmp(pv[i], L"-u") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            file_info.up = true;
        }
        else if (_wcsicmp(pv[i], L"-h") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            file_info.handle = (HANDLE)(uintptr_t) _wtoi(pv[i + 1]);
        }
        else if (_wcsicmp(pv[i], L"-d") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            _snwprintf(file_info.del, VALUE_LEN, L"%ls", pv[i + 1]);
        }
        else if (_wcsicmp(pv[i], L"-m") == 0)
        {
            VERIFY(i + 1 < __argc - 1);
            // thunder
            file_info.use_thunder = true;
        }
    }
    if (!(found || file_info.up)) /* default download directory */
    {
        WCHAR path[MAX_PATH + 1] = { 0 };
        HMODULE h_shell32 = NULL;
        ITEMIDLIST* pIDList = NULL;
        if ((h_shell32 = GetModuleHandleW(L"shell32.dll")) == NULL)
        {
            return false;
        }   
        sSHGetKnownFolderIDListStub = (SHGetKnownFolderIDListPtr)GetProcAddress(h_shell32, "SHGetKnownFolderIDList"); 
        if (!sSHGetKnownFolderIDListStub)
        {
            if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL,SHGFP_TYPE_CURRENT, path)))
            {
                return false;
            }   
            else
            {
                PathAppendW(path, L"Downloads");
                path_parsing(path);
            }               
        }
        else 
        {
            if(FAILED(SHGetKnownFolderIDList(&FOLDERID_Downloads, 0,NULL,&pIDList)))
            {
                return false;
            }
            if(FAILED(SHGetPathFromIDListW(pIDList, path)))
            {
                return false;
            }
            path_parsing(path);            
        }
        printf("download dir[%ls]\n", path);
    }
    return true;
}

static void
curl_set_cookies(CURL *curl)
{
    LPCSTR agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36";
    if (strlen(file_info.referer) > 1)
    {
        char cookies[COOKE_LEN + 1] = { 0 };
        curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
        curl_easy_setopt(curl, CURLOPT_REFERER, file_info.referer);
        if (!parse_baidu_cookies(cookies, COOKE_LEN))
        {
            _snprintf(file_info.cookies, COOKE_LEN, "%s", cookies);
            curl_easy_setopt(curl, CURLOPT_COOKIE, file_info.cookies);
        }
    }
    else if (strlen(file_info.cookies) > 1)
    {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, file_info.cookies);
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "aria2/1.34.0");
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, " ");
    }
}

static int
get_name_from_cd(char const *const cd, char *oname)
{
    char const *const cdtag = "Content-disposition:";
    char const *const key = "filename=";
    char *val = NULL;

    // Example Content-Disposition: filename=name1367; charset=funny; option=strange
    val = strcasestr(cd, key);
    if (!val)
    {
        printf("No key-value for \"%s\" in \"%s\"", key, cdtag);
        return (1);
    }
    // Move to value
    val += strlen(key);
    if (*val == '"')
    {
        val++;
    }
    // Copy value as oname
    while (*val != '\0' && *val != ';' && *val != '"' && *val != '\r' && *val != '\n')
    {
        *oname++ = *val++;
    }
    *oname = '\0';
    return 0;
}

static int
get_name_from_url(char const *url, char *oname)
{
    char const *u = url;
    char const *p = NULL;
    u = strstr(u, "://");
    if (u)
    {

        u += strlen("://");
    }
    else
    {
        u = url;
    }
    u = strrchr(u, '/');
    if (NULL == u)
    {
        return (1);
    }
    // Remove last '/'
    p = ++u;
    if ((p = strchr(u, '?')) != NULL || (p = strchr(u, '=')) != NULL || (p = strchr(u, '&')) != NULL)
    {
        /* 没有从重定向url得到正确文件名 */
        _snprintf(oname, MAX_PATH, "%s", "a.zip");
        return 0;
    }
    // Copy value as oname
    while (*u != '\0' && *u != '\r' && *u != '\n')
    {
        *oname++ = *u++;
    }
    *oname = '\0';

    return 0;
}

size_t
curl_header_parse(void *hdr, size_t size, size_t nmemb, void *userdata)
{
    const size_t cb = size * nmemb;
    const char *hdr_str = hdr;
    const char *cdtag = "Content-Disposition:";
    const char *lctag = "Location:";
    dnld_params_t *dnld_params = (dnld_params_t *) userdata;
    /* Example: Ranges supports
     * Accept-Ranges: bytes
     */
    if (strcasestr(hdr_str, "Accept-Ranges: bytes"))
    {
        printf("this server Accept-Ranges: bytes\n");
    }
    if (strcasestr(hdr_str, cdtag) && strncasecmp(hdr_str, cdtag, strlen(cdtag)) == 0)
    {
        int ret;
        printf("Found c-d: %s\n", hdr_str);
        ret = get_name_from_cd(hdr_str + strlen(cdtag), dnld_params->remote_fname);
        if (ret)
        {
            printf("ERR: bad remote name\n");
        }
    }
    else if (strcasestr(hdr_str, lctag) && strncasecmp(hdr_str, lctag, strlen(lctag)) == 0)
    {
        int ret = get_name_from_url(hdr_str + strlen(lctag), dnld_params->remote_fname);
        if (ret)
        {
            printf("ERR: bad url name\n");
        }
    }
    if (strlen(dnld_params->remote_fname) > 1)
    {
        _snprintf(file_info.remote_names, MAX_PATH, "%s", dnld_params->remote_fname);
    }
    else
    {
        _snprintf(file_info.remote_names, MAX_PATH, "%s", "a.zip");
    }
    return cb;
}

static void
lock_cb(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr)
{
    (void) access;  /* unused */
    (void) userptr; /* unused */
    (void) handle;  /* unused */
    (void) data;    /* unused */
    DO_LOCK(&g_mutex);
}

static void
unlock_cb(CURL *handle, curl_lock_data data, void *userptr)
{
    (void) userptr; /* unused */
    (void) handle;  /* unused */
    (void) data;    /* unused */
    DO_UNLOCK(&g_mutex);
}

static size_t
download_package(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    enter_spinlock();
    curl_node *node = (curl_node *) userdata;
    size_t written = 0;
    if (!total_size)
    {
        written = fwrite(ptr, 1, nmemb * size, node->fp);
    }
    else if (node->startidx <= node->endidx)
    {
        int64_t real_size = size * nmemb;
        if (node->startidx + real_size > node->endidx)
        {
            real_size = node->endidx - node->startidx + 1;
        }

        if (fseek(node->fp, node->startidx, SEEK_SET) != 0)
        {
            ;
        }
        else
        {
            written = fwrite(ptr, 1, (size_t) real_size, node->fp);
            node->startidx += real_size;
        }
        downloaded_size += real_size;
    }
    leave_spinlock();
    if (total_size > 0)
    {
        update_ranges(node->tid, node->startidx, downloaded_size);
    }
    return written;
}

int
sets_progress_func(void *ptr, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
    if (total_size > 0)
    {
        int tmp = (int) (downloaded_size * 100 / total_size);
        printf("Download progress: %d%%\n", tmp);
    }
    else if (dltotal > 0.1)
    {
        printf("Download progress: %d%%\n", (int) (dlnow * 100.0 / dltotal));
    }
    return 0;
}

unsigned WINAPI
run_thread(void *pdata)
{
    int i = 0;
    curl_node *pnode = (curl_node *) pdata;
    do
    {
        CURL *curl = curl_easy_init();
        if (curl)
        {
            CURLcode res = CURLE_OK;
            char *m_ranges = NULL;
            curl_easy_setopt(curl, CURLOPT_URL, pnode->url);
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
            if (total_size > 0)
            {
                if ((m_ranges = SYS_MALLOC(FILE_LEN)) == NULL)
                {
                    break;
                }
                _snprintf(m_ranges, FILE_LEN, "%I64d-%I64d", pnode->startidx, pnode->endidx);
                curl_easy_setopt(curl, CURLOPT_RANGE, m_ranges);
                printf("\n[%s] setup \n", m_ranges);
                curl_set_cookies(curl);
                curl_easy_setopt(curl, CURLOPT_SHARE, pnode->share);
            }
            if (m_ranges)
            {
                SYS_FREE(m_ranges);
            }
            // 设置重定向的最大次数,301、302跳转跟随location
            curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
#if defined(USE_ARES)
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
#else
            // 禁用掉alarm信号，防止多线程中使用超时崩溃
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
#endif
            // 关掉CLOSE_WAIT
            curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1);
            curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, download_package);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, pnode);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
            curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, sets_progress_func);
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 3L);
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30L);
            curl_easy_setopt(curl, CURLOPT_RESUME_FROM, 0);
            res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
            if (res == CURLE_WRITE_ERROR)
            {
                printf("\nerror:failed writing received data to disk\n");
                pnode->error = true;
                break;
            }
            else if (res == CURLE_PARTIAL_FILE || res == CURLE_OPERATION_TIMEDOUT)
            {
                pnode->error = true;
                printf("\ndownload error code: %d, retry...\n", res);
                enter_spinlock();
                if (!file_info.re_bind)
                {
                    file_info.re_bind = 1;
                    i = URL_ITERATIONS - 9;
                }
                leave_spinlock();
            }
            else if (res == CURLE_OK)
            {
                pnode->error = false;
                break;
            }
            else
            {
                const char *err_string = curl_easy_strerror(res);
                printf("\ndownload error: %s\n\nurl = %s\n", err_string, pnode->url);
                pnode->error = true;
            }
        } // 非严重错误时自动重试8次
    } while (file_info.re_bind && i++ < URL_ITERATIONS);
    if (!pnode->error && total_size > 0)
    {
        update_status(pnode->tid, 1);
    }
    return (1);
}

/************************************************************************/
/* 获取要下载的远程文件的大小                                           */
/************************************************************************/
static bool
get_file_lenth(const char *url, int64_t *file_len)
{
    CURLcode res = CURLE_OK;
    dnld_params_t dnld_params;
    CURL *handle = curl_easy_init();
    memset(&dnld_params, 0, sizeof(dnld_params));
    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "gzip");
    curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(handle, CURLOPT_HEADER, 1); //只需要header头
    curl_easy_setopt(handle, CURLOPT_NOBODY, 1); //不需要body
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 20L);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 40L);
    curl_set_cookies(handle);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
    // 设置重定向的最大次数
    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 3L);
    // 设置301、302跳转跟随location
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, curl_header_parse);
    curl_easy_setopt(handle, CURLOPT_HEADERDATA, &dnld_params);

    if ((res = curl_easy_perform(handle)) == CURLE_OK)
    {
        res = curl_easy_getinfo(handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, file_len);
        printf("file_len %I64d\n", *file_len);
    }
    else
    {
        const char *err_string = curl_easy_strerror(res);
        printf("%s error: %s\n", __FUNCTION__, err_string);
        *file_len = 0;
    }
    curl_easy_cleanup(handle);
    return (res == CURLE_OK);
}

static bool
block_url()
{
    int i;
    bool res = false;
    char *moz_url[] = { // "faronics.com",
                        NULL
    };
    for (i = 0; moz_url[i]; i++)
    {
        if (strstr(file_info.url, moz_url[i]))
        {
            res = true;
            break;
        }
    }
    return res;
}

static bool
fill_file_name(const char *url)
{
    char code_names[MAX_PATH + 1] = { 0 };
    int len = 0;
    if (strcmp(file_info.remote_names, "a.zip") == 0)
    {
        if (get_name_from_url(url, file_info.remote_names))
        {
            return false;
        }
        _snprintf(code_names, MAX_PATH, "%s", file_info.remote_names);
        if (!url_decode_t(code_names))
        {
            return false;
        }
        printf("\ndiscode_names: %s\n", code_names);
        if (strcmp(code_names, file_info.remote_names) != 0)
        {
            _snprintf(file_info.remote_names, MAX_PATH, "%s", code_names);
        }
    }
    else if (strchr(file_info.remote_names, '%'))
    {
        _snprintf(code_names, MAX_PATH, "%s", file_info.remote_names);
        if (!url_decode_t(code_names))
        {
            return false;
        }
        printf("\ndiscode_names: %s\n", code_names);
        if (strcmp(code_names, file_info.remote_names) != 0)
        {
            _snprintf(file_info.remote_names, MAX_PATH, "%s", code_names);
        }
    }
    if ((len = (int) wcslen(file_info.names)) < 2)
    {
        len = MultiByteToWideChar(CP_UTF8, 0, file_info.remote_names, -1, file_info.names, MAX_PATH);
        if (!len)
        {
            printf("MultiByteToWideChar to file_info.names false\n");
            return false;
        }
    }
    else if (file_info.names[len - 1] == L'\\')
    {
        WCHAR tmp[MAX_PATH + 1] = { 0 };
        len = MultiByteToWideChar(CP_UTF8, 0, file_info.remote_names, -1, tmp, MAX_PATH);
        if (!len)
        {
            printf("MultiByteToWideChar to file_info.names false\n");
            return false;
        }
        wcsncat(file_info.names, tmp, MAX_PATH);
    }
    return true;
}

static bool
init_resume(const char *url, int64_t length)
{
    FILE *fp = NULL;
    int num = 0;
    bool res = true;
    sql_node s_node[MAX_THREAD];
    CURLSH *share = NULL;
    num = get_ranges(s_node);
    if (!num)
    {
        printf("get_ranges() return 0\n");
        return false;
    }
    if (!get_down_size(&downloaded_size))
    {
        printf("get_down_size() return false\n");
        return false;
    }
    do
    {
        int i = 0;
        curl_node m_node[MAX_THREAD];
        HANDLE m_handle[MAX_THREAD] = { 0 };
        if ((fp = _wfopen(file_info.names, L"rb+")) == NULL)
        {
            printf("fopen error in init_resume()!\n");
            res = false;
            break;
        }
        if ((share = curl_share_init()) == NULL)
        {
            printf("curl_share_init error in init_resume().\n");
            res = false;
            break;
        }
        total_size = length;
        downloaded_size -= num;
        file_info.thread_num = num;
        curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
        curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
        curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
        curl_share_setopt(share, CURLSHOPT_LOCKFUNC, lock_cb);
        curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, unlock_cb);
        for (i = 0; i < file_info.thread_num; i++)
        {
            m_node[i].fp = fp;
            m_node[i].startidx = s_node[i].startidx;
            m_node[i].endidx = s_node[i].endidx;
            m_node[i].share = share;
            m_node[i].tid = s_node[i].thread;
            m_node[i].url = url;
            m_node[i].error = false;
            m_handle[i] = (HANDLE) _beginthreadex(NULL, 0, run_thread, &m_node[i], 0, NULL);
            if (m_handle[i] == NULL)
            {
                printf("_beginthreadex false, error: %lu\n", GetLastError());
                res = false;
                break;
            }
        }
        for (i = 0; i < file_info.thread_num; i++)
        {
            if ((WaitForSingleObject(m_handle[i], INFINITE) == WAIT_OBJECT_0))
            {
                CloseHandle(m_handle[i]);
                m_handle[i] = NULL;
                if (m_node[i].error)
                {
                    res = false;
                }
            }
        }
    } while (0);
    if (fp)
    {
        fclose(fp);
    }
    if (share)
    {
        curl_share_cleanup(share);
    }
    return res;
}

static bool
md5_sum(void)
{
    bool res = false;
    char md5_str[MD5_DIGEST_LENGTH * 2 + 1] = { 0 };
    if (get_file_md5(file_info.names, md5_str) && stricmp(md5_str, file_info.md5) == 0)
    {
        printf("%S [md5: %s]\n", file_info.names, md5_str);
        res = true;
    }
    else
    {
        res = false;
        DeleteFileW(file_info.names);
        printf("package md5[%s] sum error! cause file [%s]\n", md5_str, file_info.md5);
    }
    return res;
}

static bool
resume_download(const char *url, int64_t length, LPCWSTR path)
{
    bool fn = false;
    do
    {
        int64_t size = 0;
        fn = init_sql_logs(path);
        if (!fn)
        {
            break;
        }
        fn = check_status(&size);
        if (!fn)
        {
            break;
        }
        if (size != length)
        {
            printf("file size different, not resume download.\n");
            break;
        }
        fn = init_resume(url, length);
        if (fn)
        {
            printf("\nresume download succed......\n");
        }
        else
        {
            printf("\nresume download failed......\n");
            DeleteFileW(file_info.names);
        }
    } while (0);
    clean_sql_logs();
    if (*path != '\0')
    {
        DeleteFileW(path);
    }
    return fn;
}

static bool
init_download(const char *url, int64_t length)
{
    int i = 0;
    FILE *fp = NULL;
    bool m_error = false;
    wchar_t sql_name[MAX_PATH] = { 0 };
    CURLSH *share = NULL;
    do
    {
        curl_node m_node[MAX_THREAD];
        HANDLE m_handle[MAX_THREAD] = { 0 };
        int64_t gap = 0;
        if (length == 0 || length >= INT64_MAX)
        {
            printf("get the file size error...\n");
            length = 0;
        }
        if (fill_file_name(url) && length)
        {
            _snwprintf(sql_name, MAX_PATH, L"%ls%ls", file_info.names, L".sinfo");
            if (PathFileExistsW(sql_name))
            {
                if (!PathFileExistsW(file_info.names))
                {
                    DeleteFileW(sql_name);
                } // 存在日志记录文件,准备续传
                else
                {
                    return resume_download(url, length, sql_name);
                }
            }
            else if (PathFileExistsW(file_info.names) && strlen(file_info.md5) > 1 && md5_sum())
            {
                *file_info.md5 = '\0';
                return true;
            }
        } // 长度未知时,不启用sql日志文件
        if (!length || init_sql_logs(sql_name))
        {
            fp = _wfopen(file_info.names, L"wb");
        }
        if (NULL == fp)
        {
            printf("fopen error!\n");
            m_error = true;
            break;
        } // 没有提前获取文件长度,不使用多线程下载
        if (!length || block_url())
        {
            memset(&m_node[0], 0, sizeof(curl_node));
            m_node[0].fp = fp;
            m_node[0].url = url;
            total_size = 0;
            downloaded_size = 0;
            printf("we download with single thread!\n");
            run_thread(&m_node[0]);
            if (m_node[0].error)
            {
                m_error = true;
            }
            break;
        }
        if (file_info.thread_num == 0)
        {
            file_info.thread_num = get_cpu_works();
        }

        gap = length / file_info.thread_num;
        total_size = length;
        downloaded_size = 0;

        if (file_info.thread_num > MAX_THREAD)
        {
            file_info.thread_num = MAX_THREAD;
        }
        share = curl_share_init();
        if (NULL == share)
        {
            printf("curl_share_init() error.\n");
            m_error = true;
            break;
        }
        else
        {
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
            curl_share_setopt(share, CURLSHOPT_LOCKFUNC, lock_cb);
            curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, unlock_cb);
        }
        for (i = 0; i < file_info.thread_num; i++)
        {
            m_node[i].startidx = i * gap;
            if (i == file_info.thread_num - 1)
            {
                m_node[i].endidx = length - 1;
            }
            else
            {
                m_node[i].endidx = m_node[i].startidx + gap - 1;
            }
            m_node[i].fp = fp;
            m_node[i].url = url;
            m_node[i].share = share;
            m_node[i].error = false;
            m_handle[i] = (HANDLE) _beginthreadex(NULL, 0, run_thread, &m_node[i], 0, &(m_node[i].tid));
            if (m_handle[i] == NULL)
            {
                printf("_beginthreadex false, error: %lu\n", GetLastError());
                m_error = true;
                break;
            }
            else if (!thread_insert(url, m_node[i].startidx, m_node[i].endidx, 0, total_size, m_node[i].tid, GetCurrentProcessId(), 0))
            {
                printf("thread_insert() false.\n");
                m_error = true;
                break;
            }
        }
        for (i = 0; i < file_info.thread_num; i++)
        {
            if ((WaitForSingleObject(m_handle[i], INFINITE) == WAIT_OBJECT_0))
            {
                CloseHandle(m_handle[i]);
                m_handle[i] = NULL;
                if (m_node[i].error)
                {
                    m_error = true;
                }
            }
        }
    } while (0);
    if (fp != NULL)
    {
        fclose(fp);
        clean_sql_logs();
    }
    if (share != NULL)
    {
        curl_share_cleanup(share);
    }
    if (m_error)
    {
        printf("download failed......\n");
        DeleteFileW(file_info.names);
        if (*sql_name != '\0')
        {
            DeleteFileW(sql_name);
        }
    }
    else
    {
        printf("\ndownload succed......\n");
        if (*sql_name != '\0')
        {
            DeleteFileW(sql_name);
        }
    }
    return (!m_error);
}

void
remove_files(LPCWSTR dir)
{
#define EXE_NUM 16
    int num;
    WCHAR *moz_processes[] = { L"breakpadinjector.dll",
                               L"crashreporter.exe",
                               L"crashreporter.ini",
                               L"firefox.exe.sig",
                               L"firefox.exe",
                               L"firefox.VisualElementsManifest.xml",
                               L"pingsender.exe",
                               L"plugin-container.exe.sig",
                               L"maintenanceservice.exe",
                               L"maintenanceservice_installer.exe",
                               L"minidump-analyzer.exe",
                               L"updater.exe",
                               L"updater.ini",
                               L"update-settings.ini",
                               L"xul.dll.sig" };
    WCHAR list[EXE_NUM][VALUE_LEN + 1];
    int i = sizeof(moz_processes) / sizeof(moz_processes[0]);
    for (num = 0; num < i; num++)
    {
        _snwprintf(list[num], VALUE_LEN, L"%ls\\%ls", dir, moz_processes[num]);
        DeleteFileW(list[num]);
    }
#undef EXE_NUM
}

HANDLE WINAPI
create_new(LPCWSTR wcmd, const LPCWSTR pcd, int flags, DWORD *opid)
{
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    DWORD dwCreat = 0;
    WCHAR my_cmd[MAX_PATH + 1] = { 0 };
    wcsncpy(my_cmd, wcmd, MAX_PATH);

    if (unknown_builds())
    {
        PathRemoveFileSpecW(my_cmd);
        remove_files(my_cmd);
        PathAppendW(my_cmd, L"Iceweasel.exe");
    }

    if (true)
    {
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
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

static bool
thunder_lookup(void)
{
    bool m_down = false;
    if (strlen(file_info.referer) > 1)
    {
        char cookies[COOKE_LEN + 1] = { 0 };
        parse_baidu_cookies(cookies, COOKE_LEN);
        m_down = thunder_download(file_info.url, file_info.referer, cookies);
    }
    else
    {
        m_down = thunder_download(file_info.url, "", "");
    }
    if (m_down)
    {
        printf("Call thunder download\n");
        if (file_info.cookie_handle > 0)
        {
            CloseHandle(file_info.cookie_handle);
        }
    }
    return m_down;
}

static void
msg_tips(void)
{
    HWND fx = NULL;
    char *lpmsg = NULL;
    WCHAR msg[MAX_MESSAGE+1] = {0};
    if (ini_read_string("update", "msg", &lpmsg, file_info.ini) &&
        MultiByteToWideChar(CP_UTF8, 0, lpmsg, -1, msg, MAX_MESSAGE) > 0)
    {
        fx = get_moz_hwnd();
        wstr_replace(msg, wcslen(msg), L"\\n", L"\n");
        MessageBoxW(fx, msg, L"Tips:", MB_OK | MB_SETFOREGROUND);
    }
    if (lpmsg)
    {
        free(lpmsg);
    }
}

static void
logs_update(bool res)
{
    char *str_time = NULL;
    uint64_t diff = 3600 * 24;
    uint64_t m_time1 = (uint64_t) time(NULL);
    uint64_t m_time2 = ini_read_uint64("update", "last_check", file_info.ini);
    if (m_time1 - m_time2 > diff)
    {
        char s_time[FILE_LEN] = { 0 };
        _ui64toa(m_time1, s_time, 10);
        if (!ini_write_string("update", "last_check", s_time, file_info.ini))
        {
            printf("ini_write_string return false.\n");
        }
    }
    if (res)
    {
        ini_write_string("update", "be_ready", "1", file_info.ini);
    }  
}

static void
update_task(void)
{
    bool   res = false;
    HANDLE mutex = NULL;
    HANDLE thread = NULL;
    WCHAR self[MAX_PATH + 1] = { 0 };
    WCHAR sz_clone[MAX_PATH + 1] = { 0 };
    fn_show show = { 0 };
    if (file_info.handle > 0)
    { // 删除老的版本
        WaitForSingleObject(file_info.handle, INFINITE);
        CloseHandle(file_info.handle);
        if (!DeleteFileW(file_info.del))
        {
            printf("%S DeleteFileW occurred: %lu.\n", file_info.del, GetLastError());
        }
        ExitProcess(0);
    }
    if (file_info.pid > 0)
    {
        // 杀死firefox进程
        HANDLE tmp = OpenProcess(PROCESS_TERMINATE, false, file_info.pid);
        if (NULL != tmp && TerminateProcess(tmp, (DWORD) -1) && set_ui_strings())
        {
            CloseHandle(tmp);
            mutex = CreateMutexW(NULL, FALSE, L"_upcheck_install_");
            if (ERROR_ALREADY_EXISTS == GetLastError())
            {
                printf("process with the same name exists, ExitProcess\n");
                ExitProcess(0);                
            }
            show.indeterminate = true;
            show.initstrings = false;
            thread = (HANDLE) _beginthreadex(NULL, 0, show_progress, &show, 0, NULL);
            {
                // 等待残留进程退出
                float percent = PROGRESS_PREPARE_SIZE;
                for (int i = 8; i > 0; --i)
                {
                    if (percent < PROGRESS_EXECUTE_SIZE)
                    {
                        percent += PROGRESS_FINISH_SIZE;
                        update_progress(percent);
                    }
                    Sleep(500);
                }
                uint64_t numb;
                GetModuleFileNameW(NULL, self, MAX_PATH);
                numb = (uint64_t) _time64(NULL);
                _snwprintf(sz_clone, MAX_PATH, L"%ls_%I64u%ls", self, numb, L".exe");
                DeleteFileW(sz_clone);
                if (_wrename(self, sz_clone))
                {
                    printf("_wrename Error occurred.\n");
                    res = false;
                    goto cleanup;
                }
            }
        }
    } // 从file_info.unzip_dir获得复制文件的源目录
    if (thread != NULL && file_info.extract)
    {
        if (update_thread(NULL))
        {
            LPCWSTR msg = L"Failed to copy file,\n"
                          L"The update file is located in the user download directory,\n"
                          L"You may need to manually unzip to the installation directory";
            MessageBoxW(NULL, msg, L"Warning:", MB_OK|MB_ICONWARNING);
            res = false;
            goto cleanup;
        }
        if (ini_write_string("update", "be_ready", NULL, file_info.ini))
        {
            WaitForSingleObject(thread, 300);
            quit_progress();
            // 准备更新自身
            WCHAR sz_cmdLine[MAX_PATH + 1];
            PROCESS_INFORMATION pi;
            STARTUPINFOW si;
            HANDLE h_self;
            if (!PathFileExistsW(self))
            {
                printf("we change back to original name\n");
                if (_wrename(sz_clone, self))
                {
                    printf("rename back false.\n");
                }
            }
            else
            {
                h_self = OpenProcess(SYNCHRONIZE, TRUE, GetCurrentProcessId());
                if (!h_self)
                {
                    printf("OpenProcess(%S) false\n", self);
                }
                _snwprintf(sz_cmdLine, MAX_PATH, L"%ls -h %zu -d %ls", self, (uintptr_t)h_self, sz_clone);
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);
                CreateProcessW(NULL, sz_cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
                CloseHandle(h_self);
                CloseHandle(pi.hProcess);
                res = true;
            }
        }
        else
        {
            printf("ini_write_string NULL return false.\n");
            res = false;
        }
    }
cleanup:   
    if (thread)
    {
        CloseHandle(thread);
        thread = NULL;
    } 
    if (mutex)
    {
        CloseHandle(mutex);
        mutex = NULL;
    }
    if (!res)
    {
        ExitProcess(255);
    }
}

static bool
curl_task(int64_t length)
{
    bool res = false;
    INIT_LOCK(&g_mutex);
    curl_global_init(CURL_GLOBAL_ALL);
    if (init_download(file_info.url, length))
    {
        res = true;
    }
    curl_global_cleanup();
    DESTROY_LOCK(&g_mutex);
    return res;
}

int
wmain(int argc, WCHAR **wargv)
{
    bool result = false;
	const HMODULE hlib = GetModuleHandleW(L"kernel32.dll");
	SetDllDirectoryW(L"");
	if (hlib)
	{
	    typedef BOOL (WINAPI * SSPM) (DWORD);
	    const SSPM fnSetSearchPathMode = (SSPM)GetProcAddress (hlib, "SetSearchPathMode");
	    if (fnSetSearchPathMode)
	    {
	  	    fnSetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);
	    }
	}    
#ifdef DEBUG_LOG
    init_logs();
#endif
    if (argc < 2 || _wcsicmp(wargv[1], L"--help") == 0 || _wcsicmp(wargv[1], L"--version") == 0)
    {
        printf("Usage: %s [-i URL] [-o SAVE_PATH] [-t THREAD_NUMS] [-r REBIND] [-e EXTRACT_PATH]\nversion: 1.0.6\n",
               "upcheck.exe");
        return -1;
    }
    if (true) // 初始化全局参数
    {
        memset(&file_info, 0, sizeof(file_info));
        if (!init_command_data())
        {
            return -1;
        }
    }
    if (file_info.use_thunder)
    {
        char  *command = NULL;
        char mbcs_command[VALUE_LEN] = {0};
        if (ini_read_string("player", "command", &command, file_info.ini))
        {   // 优先调用命令行参数
            char dl[URL_LEN] = {0};
            char *p1 = NULL,*p2 = NULL;
            const char *key = "%s";
            int len_t = (int)strlen(key);
            p1 = strstr(command, key);
            if (p1)
            {
                p1 += len_t;
                p2 = strstr(p1, key);
            }
            if (p1 && p2)
            {
                p2 += len_t;
                if (p2[1]=='"')
                {
                     p2[2] = '\0';
                }
                else
                {
                    p2[1] = '\0';
                }
                _snprintf(dl, URL_LEN, command, file_info.url, file_info.cookies);
            }
            else if (p1)
            {
                _snprintf(dl, URL_LEN, command, file_info.url);
            }
            else
            {
                _snprintf(dl, URL_LEN, command);
            }                
            free(command);
            printf("dl_command: %s\n", dl);
            if(exec_ppv(dl, NULL, 0))
            {
                return 0;
            }
            
        }
        if (thunder_lookup()) // 调用迅雷下载
        {
            return 0;
        } 
    }
    do
    {
        int64_t length = 0;
        if (file_info.up || file_info.handle > 0) // 执行升级任务
        {
            update_task();
            break;
        }
        if (strlen(file_info.ini) > 1) // 下载并解析ini文件
        {
            int   ups = -1;
            WCHAR names[MAX_PATH] = {0};
            if (get_name_self(names, MAX_PATH) && search_process(names))
            {
                printf("process with the same name exists, exit...\n");
                *file_info.ini = '\0';
                break;
            }            
            ups = init_resolver();
            if (ups == 0)
            {
                printf("init_resolver ok.\n");
            }
            else if (ups > 0)
            {
                printf("init_resolver return 1.\n");
                break;
            }
            else
            {
                printf("init_resolver return -1.\n");
                *file_info.ini = '\0';
                break;
            }
        }
        if (strlen(file_info.url) < 2) // 没有下载任务
        {
            printf("not url\n");
            break;
        }
        if (!get_file_lenth(file_info.url, &length)) // 获取远程文件大小
        {
            printf("get_file_lenth return false\n");
            *file_info.ini = '\0';
            break;
        }
        if ((result = curl_task(length)) == false) // 开始下载任务
        {
            break;
        }
        if (strlen(file_info.md5) > 1) // 核对文件md5值
        {
            result = md5_sum();
        }
        if (result && file_info.extract) // 解压缩升级包
        {
            if (extract7z(file_info.names, file_info.unzip_dir))
            {
                result = false;
            }
        }
        if (result && strlen(file_info.ini) > 1) // 弹出消息提示
        {
            msg_tips();
        }
    } while (0);
    if (file_info.cookie_handle > 0)
    {
        CloseHandle(file_info.cookie_handle);
    }
    if (!file_info.up && strlen(file_info.ini) > 1)
    {
        logs_update(result);
    }
    if (wcslen(file_info.process) > 1)
    {
        SetEnvironmentVariableW(L"LIBPORTABLE_UPCHECK_LAUNCHER_PROCESS", L"1");
        CloseHandle(create_new(file_info.process, NULL, 2, NULL));
    }
    return 0;
}
