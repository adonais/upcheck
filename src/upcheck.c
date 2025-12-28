#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>
#include <process.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include "upcheck.h"
#include "ini_parser.h"
#include "urlcode.h"
#include "extract7z.h"
#include "progressui.h"
#include "updates.h"
#include "xml.h"
#include "cookies.h"
#include "thunderagent.h"

#if DLL_INJECT
#include "setdll.h"
#endif

#ifndef EUAPI_LINK
#include "load_script.h"
#include "load_chrome.h"
#include "manger.h"
#include "integration.h"
#endif

#if !defined(EUAPI_LINK)
#if defined(_MSC_VER) && defined(_WIN64)
#pragma comment(linker, "/include:luaL_openlibs")
#endif
#endif

#define DOWN_NUM    10
#define SELECT_AUTO 999

typedef HRESULT (WINAPI *SHGetKnownFolderIDListPtr)(REFKNOWNFOLDERID rfid,
        DWORD            dwFlags,
        HANDLE           hToken,
        PIDLIST_ABSOLUTE *ppidl);

static int64_t downloaded_size = 0;
static int64_t total_size = 0;
static LOCK_MUTEXT g_mutex = {0};
static SHGetKnownFolderIDListPtr sSHGetKnownFolderIDListStub = NULL;
static char g_download_url[DOWN_NUM][URL_LEN] = {0};

file_info_t file_info = {0};

static HWND
get_moz_hwnd(int pid)
{
    HWND hwnd = NULL;
    bool found = false;
    DWORD process_id = 0;
    int i = 40;
    if (!pid)
    {
        pid = file_info.pid;
    }
    if ((hwnd = FindWindowW(L"MozillaWindowClass", NULL)) != NULL)
    {
        GetWindowThreadProcessId(hwnd, &process_id);
        if (process_id == pid)
        {
            found = true;
        }
    }
    while (!found && i--)
    {
        process_id = 0;
        if ((hwnd = FindWindowExW(NULL, hwnd, L"MozillaWindowClass", NULL)) != NULL)
        {
            GetWindowThreadProcessId(hwnd, &process_id);
        }
        if (process_id > 0 && process_id == pid)
        {
            found = true;
            break;
        }
        SleepEx(200, FALSE);
    }
    if (!found)
    {
        hwnd = NULL;
    }
    return hwnd;
}

static bool
get_download_dir(WCHAR *path)
{
    bool ret = true;
    HMODULE shell32 = NULL;
    ITEMIDLIST* pidlist = NULL;
    do
    {
        if ((shell32 = GetModuleHandleW(L"shell32.dll")) == NULL)
        {
            ret = false;
            break;
        }
        sSHGetKnownFolderIDListStub = (SHGetKnownFolderIDListPtr)GetProcAddress(shell32, "SHGetKnownFolderIDList");
        if (!sSHGetKnownFolderIDListStub)
        {
            if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL,SHGFP_TYPE_CURRENT, path)))
            {
                ret = false;
                break;
            }
            else
            {
                PathAppendW(path, L"Downloads");
            }
        }
        else
        {
            if(FAILED(SHGetKnownFolderIDList(&FOLDERID_Downloads, 0,NULL,&pidlist)))
            {
                ret = false;
                break;
            }
            if(FAILED(SHGetPathFromIDListW(pidlist, path)))
            {
                ret = false;
                break;
            }
        }
    } while(0);
    return ret;
}

/* 智能分析需要保持的文件名并建立目录 */
static void
path_parsing(LPCWSTR save_path)
{
    int len = 0;
    if (NULL == save_path || *save_path == 0)
    {
        return;
    }
    if (PathFindExtensionW(save_path)[0] == L'.')
    {   // 完整的文件路径
        if (save_path[1] == L':')
        {
            _snwprintf(file_info.names, MAX_PATH, L"%s", save_path);
        }
        else if (save_path[0] != L'.')
        {   // 只有文件名, 默认到下载目录
            WCHAR tmp_path[MAX_PATH + 1] = {0};
            if (get_download_dir(tmp_path))
            {
                if (*save_path != L'\\')
                {
                    wcsncat(tmp_path, L"\\", MAX_PATH);
                }
                wcsncat(tmp_path, save_path, MAX_PATH);
                _snwprintf(file_info.names, MAX_PATH, L"%s", tmp_path);
            }
        }
        return;
    }
    if (!exists_dir(save_path))
    {
        create_dir(save_path);
    }
    if ((len = _snwprintf(file_info.names, MAX_PATH, L"%s", save_path)) > 0 && len < MAX_PATH)
    {   // 加上目录符, 下载时自动加文件名
        len = (int)wcslen(file_info.names);
        if (file_info.names[len - 1] != L'\\')
        {
            wcsncat(file_info.names, L"\\", MAX_PATH);
        }
    }
}

static bool
init_command_data(const int args, const wchar_t **pv)
{
    bool ret = true;
    bool found = false;
    do
    {
        const int argn = args + 1;
        for (int i = 1; i < argn - 1; ++i)
        {
            if (_wcsicmp(pv[i], L"-i") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                WCHAR tmp[URL_LEN + 1] = { 0 };
                _snwprintf(tmp, URL_LEN, L"%s", pv[i + 1]);
                if (wcscmp(tmp, L"auto") == 0)
                {   // 自动分析ini文件下载
                    if (!ini_path_init())
                    {
                        ret = false;
                        break;
                    }
                    continue;
                }
                else if (!WideCharToMultiByte(CP_UTF8, 0, tmp, -1, file_info.url, sizeof(file_info.url), NULL, NULL))
                {   // 直接获得url参数, 转换成utf-8编码
                    ret = false;
                    break;
                }
            } // 下载目录
            else if (_wcsicmp(pv[i], L"-o") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                if (wcslen(pv[i + 1]) > 1)
                {
                    found = true;
                    path_parsing(pv[i + 1]);
                }
            } // 下载时线程数目
            else if (_wcsicmp(pv[i], L"-t") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.thread_num = _wtoi(pv[i + 1]);
            } // 断线重连
            else if (_wcsicmp(pv[i], L"-r") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.re_bind = _wtoi(pv[i + 1]);
            } // 杀死进程
            else if (_wcsicmp(pv[i], L"-k") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.pid = _wtoi(pv[i + 1]);
            } // 设置cookies
            else if (_wcsicmp(pv[i], L"-b") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                WideCharToMultiByte(CP_UTF8, 0, pv[i + 1], -1, file_info.cookiefile, MAX_PATH, NULL, NULL);
            }
            else if (_wcsicmp(pv[i], L"-cok") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                _snwprintf(file_info.cookie_tmp, MAX_PATH, L"%s", pv[i + 1]);
                get_first_line(&(file_info.pcook), pv[i + 1]);
            }
            else if (_wcsicmp(pv[i], L"-ref") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                if (file_info.url[0])
                {
                    WideCharToMultiByte(CP_UTF8, 0, pv[i + 1], -1, file_info.referer, MAX_PATH, NULL, NULL);
                #ifdef LOG_DEBUG
                    printf("referer = [%s]\n", file_info.referer);
                #endif
                }
            } // 解压目录
            else if (_wcsicmp(pv[i], L"-e") == 0)
            {
                file_info.extract = true;
                VERIFY(i + 1 < argn - 1);
                _snwprintf(file_info.unzip_dir, MAX_PATH, L"%s", pv[i + 1]);
            } // 更新完毕后启动的进程名
            else if (_wcsicmp(pv[i], L"-s") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                if (!ini_path_init())
                {
                    ret = false;
                    break;
                }
                _snwprintf(file_info.process, MAX_PATH, L"%s", pv[i + 1]);
            }
            else if (_wcsicmp(pv[i], L"-u") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.up = true;
            }
            else if (_wcsicmp(pv[i], L"-h") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.handle = (HANDLE)_wtoiz(pv[i + 1]);
            }
            else if (_wcsicmp(pv[i], L"-d") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                _snwprintf(file_info.del, MAX_PATH, L"%s", pv[i + 1]);
            }
        #ifndef EUAPI_LINK
            else if (_wcsicmp(pv[i], L"-m") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                // thunder
                file_info.use_thunder = _wtoi(pv[i + 1]);
                if (!file_info.use_thunder)
                {
                    file_info.use_thunder = SELECT_AUTO;
                }
            }
        #endif
            else if (_wcsicmp(pv[i], L"-dt") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.dt_local = (uint64_t)_wtoi64(pv[i + 1]);
            }
            else if (_wcsicmp(pv[i], L"-uri") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                ini_make_u8(pv[i + 1], file_info.ini_uri, _countof(file_info.ini_uri));
            }
            else if (_wcsicmp(pv[i], L"-hwnd") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.remote_hwnd = (HWND)_wtoiz(pv[i + 1]);
            }
            else if (_wcsicmp(pv[i], L"-param") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                _snwprintf(file_info.param, MAX_PATH, L"%s", pv[i + 1]);
            }
        }
        if (ret && !(found || file_info.up)) /* default download directory */
        {
            WCHAR path[MAX_PATH + 1] = {0};
            if (!get_download_dir(path))
            {
                break;
            }
            path_parsing(path);
        #ifdef LOG_DEBUG
            printf("download dir[%ls]\n", path);
        #endif
        }
        if (ret && file_info.ini[0])
        {
            char *ini_proxy = NULL;
            char *ini_usewd = NULL;
            if (ini_read_string("proxy", "addr", &ini_proxy, file_info.ini, true))
            {
                ini_read_string("proxy", "user", &ini_usewd, file_info.ini, true);
            }
            if (ini_proxy && ini_proxy[0])
            {
                _snprintf(file_info.ini_proxy, MAX_PATH, "%s", ini_proxy);
                if (ini_usewd && ini_usewd[0])
                {
                    _snprintf(file_info.ini_usewd, NAMES_LEN, "%s", ini_usewd);
                }
            }
            if (ini_proxy)
            {
                free(ini_proxy);
            }
            if (ini_usewd)
            {
                free(ini_usewd);
            }
        }
    } while(0);
    return ret;
}

static void
curl_set_cookies(CURL *curl)
{
    if (strstr(file_info.url, "sf.net") || strstr(file_info.url, "sourceforge.net"))
    {
        euapi_curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/8.16.0");
        euapi_curl_easy_setopt(curl, CURLOPT_COOKIE, "");
    }
    else if (file_info.referer[0] && file_info.cookiefile[0])
    {
        euapi_curl_easy_setopt(curl, CURLOPT_REFERER, file_info.referer);
        euapi_curl_easy_setopt(curl, CURLOPT_COOKIEFILE, file_info.cookiefile);
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
        if (p - u < MAX_PATH)
        {
            _snprintf(oname, p - u, "%s", u);
        }
        else
        {
            /* 没有从重定向url得到正确文件名 */
            _snprintf(oname, MAX_PATH, "%s", "a.zip");
        }
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

const void
strip_url_newline(void)
{
    if (file_info.url[strlen(file_info.url) - 2] == '\r')
    {
        file_info.url[strlen(file_info.url) - 2] = 0;
    }
    else if (file_info.url[strlen(file_info.url) - 1] == '\n')
    {
        file_info.url[strlen(file_info.url) - 1] = 0;
    }
}

size_t
curl_header_parse(void *hdr, size_t size, size_t nmemb, void *userdata)
{
    const size_t cb = size * nmemb;
    const char *hdr_str = hdr;
    const char *p = NULL;
    const char *cdtag = "Content-Disposition: ";
    const char *lentag = "Content-Length: ";
    const char *lctag = "Location: ";
    dnld_params_t *dnld_params = (dnld_params_t *) userdata;
    if (SELECT_AUTO != file_info.thread_num)
    {
        file_info.thread_num = 1;
    }
    /* Example: Ranges supports
     * Accept-Ranges: bytes
    */
    if (strcasestr(hdr_str, " 307"))
    {
        dnld_params->ret = 307;
    }
    if (strcasestr(hdr_str, "Accept-Ranges: bytes"))
    {
        file_info.thread_num = SELECT_AUTO;
        printf("this server Accept-Ranges: bytes\n");
    }
    else if (strcasestr(hdr_str, " 404"))
    {
        return 0;
    }
    if ((p = strcasestr(hdr_str, lctag)) != NULL && strcasestr(p, "dl.sourceforge.net") != NULL)
    {
        p += strlen(lctag);
        if (strncasecmp(p, file_info.url, strlen(file_info.url)))
        {
            char re[NAMES_LEN + 1] = {0};
            _snprintf(file_info.url, URL_LEN, "%s", p);
            strip_url_newline();
            if ((p = strstr(file_info.url, ".")) != NULL)
            {
                strncpy(re, file_info.url, p - file_info.url);
            }
            if (re[0])
            {
                str_replace(file_info.url, URL_LEN, re, "https://liquidtelecom");
            }
            printf("Redirecting to[%s]\n", file_info.url);
        }
    }
    do
    {
        int ret = 0;
        if (strncasecmp(hdr_str, cdtag, strlen(cdtag)) == 0)
        {
            printf("Found c-d: [%s]\n", hdr_str);
            ret = get_name_from_cd(hdr_str + strlen(cdtag), dnld_params->remote_fname);
            if (!ret)
            {
                break;
            }
            printf("ERR: bad remote name\n");
        }
        if (strncasecmp(hdr_str, lctag, strlen(lctag)) == 0)
        {
            ret = get_name_from_url(hdr_str + strlen(lctag), dnld_params->remote_fname);
            if (!ret)
            {
                break;
            }
            printf("ERR: bad url name\n");
        }
        if (strncasecmp(hdr_str, lentag, strlen(lentag)) == 0)
        {
            p = hdr_str + strlen(lentag);
            if (strlen(p) > 1)
            {
                _snprintf(dnld_params->file_len, UINT_LEN, "%s", &p[0]);
            }
        }
    } while (0);
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
    curl_node *node = (curl_node *) userdata;
    size_t written = 0;
    int64_t real_size = size * nmemb;
    enter_spinlock();
    do
    {
        if (!total_size)
        {
            written = fwrite(ptr, 1, (size_t)real_size, node->fp);
        }
        else if (fseek(node->fp, node->szdown, SEEK_SET) != 0)
        {
            printf("%s: fseek error!\n", __FUNCTION__);
            break;
        }
        else
        {
            written = fwrite(ptr, 1, (size_t)real_size, node->fp);
            node->szdown += written;
        #ifdef LOG_DEBUG
            printf("[thread: %u], node->szdown = %zd\n", node->tid, node->szdown);
        #endif
        }
    } while (0);
    downloaded_size += written;
    if (total_size > 0)
    {
        update_ranges(node->tid, node->szdown, downloaded_size);
    }
    leave_spinlock();
    return written;
}

static int
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

static unsigned WINAPI
run_thread(void *pdata)
{
    int i = 0;
    curl_node *pnode = (curl_node *) pdata;
    do
    {
        CURL *curl = euapi_curl_easy_init();
        if (curl)
        {
            CURLcode res = CURLE_OK;
            char *m_ranges = NULL;
            euapi_curl_easy_setopt(curl, CURLOPT_URL, pnode->url);
            euapi_curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
            if (total_size > 0)
            {
                if ((m_ranges = calloc(FILE_LEN, 1)) == NULL)
                {
                    break;
                }
                _snprintf(m_ranges, FILE_LEN, "%I64d-%I64d", pnode->szdown, pnode->endidx);
                euapi_curl_easy_setopt(curl, CURLOPT_RANGE, m_ranges);
                printf("\nthead: %u[%s] setup \n", pnode->tid, m_ranges);
            }
            if (m_ranges)
            {
                free(m_ranges);
            }
            curl_set_cookies(curl);
            euapi_curl_easy_setopt(curl, CURLOPT_SHARE, pnode->share);
            // 设置重定向的最大次数,301、302跳转跟随location
            euapi_curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 4);
            euapi_curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        #if defined(USE_ARES)
            euapi_curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
        #else
            // 禁用掉alarm信号，防止多线程中使用超时崩溃
            euapi_curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        #endif
            // 关掉CLOSE_WAIT
            euapi_curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1);
            euapi_curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, download_package);
            euapi_curl_easy_setopt(curl, CURLOPT_WRITEDATA, pnode);
            libcurl_set_ssl(curl);
            euapi_curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
        #if defined(APP_DEBUG)
            euapi_curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, sets_progress_func);
        #endif
        #if defined(LOG_DEBUG) || defined(APP_DEBUG)
            euapi_curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        #endif
            // 设置代理
            libcurl_set_proxy(curl);
            euapi_curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 3L);
            euapi_curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30L);
            euapi_curl_easy_setopt(curl, CURLOPT_RESUME_FROM, 0);
            res = euapi_curl_easy_perform(curl);
            euapi_curl_easy_cleanup(curl);
            if (res == CURLE_OK)
            {
                pnode->error = false;
                printf("\ndownload message: ok, %u thread exit\n", pnode->tid);
                break;
            }
            else // CURLE_PARTIAL_FILE, CURLE_OPERATION_TIMEDOUT
            {
                pnode->error = true;
                printf("\ndownload error: code[%d], retry...\n", res);
            }
        } // 非严重错误时自动重试8次
    } while (file_info.re_bind && ++i < URL_ITERATIONS);
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
get_file_lenth(const char *url, dnld_params_t *dnld_params)
{
    CURL *handle = NULL;
    CURLcode res = CURLE_FAILED_INIT;
    if ((handle = euapi_curl_easy_init()) != NULL)
    {
        euapi_curl_easy_setopt(handle, CURLOPT_URL, url);
        euapi_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
        euapi_curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");
        euapi_curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "HEAD");
        euapi_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, curl_header_parse);
        euapi_curl_easy_setopt(handle, CURLOPT_HEADERDATA, dnld_params);
        // 设置链接超时
        euapi_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 120L);
        euapi_curl_easy_setopt(handle, CURLOPT_TIMEOUT, 180L);
        // curl_set_cookies(handle);
        libcurl_set_ssl(handle);
        // 设置重定向的最大次数
        euapi_curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 4L);
        // 设置301、302跳转跟随location
        euapi_curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);
        //不需要body, 只需要header头
        euapi_curl_easy_setopt(handle, CURLOPT_NOBODY, 1);
        euapi_curl_easy_setopt(handle, CURLOPT_HEADER, 1);
        euapi_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
        // 设置代理
        libcurl_set_proxy(handle);
        if ((res = euapi_curl_easy_perform(handle)) == CURLE_OK)
        {
            if (dnld_params->file_len[0])
            {
                dnld_params->length = _atoi64(dnld_params->file_len);
            }
            else
            {
                dnld_params->length = 0;
            }
        }
        else
        {
            const char *err_string = euapi_curl_easy_strerror(res);
            printf("%s[%s] error: %s\n", __FUNCTION__, url, err_string);
            dnld_params->length = 0;
        }
        euapi_curl_easy_cleanup(handle);
    }
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
    sql_node s_node[MAX_THREAD] = {0};
    CURLSH *share = NULL;
    num = get_ranges(s_node);
    if (!num)
    {
        printf("get_ranges() return 0\n");
        return false;
    }
    else
    {
        printf("init_resume function, num = %d, szDown = %I64d\n", num, s_node[0].szdown);
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
        if ((share = euapi_curl_share_init()) == NULL)
        {
            printf("euapi_curl_share_init error in init_resume().\n");
            res = false;
            break;
        }
        total_size = length;
        downloaded_size -= num;
        file_info.thread_num = num;
        euapi_curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
        euapi_curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
        euapi_curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
        euapi_curl_share_setopt(share, CURLSHOPT_LOCKFUNC, lock_cb);
        euapi_curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, unlock_cb);
        for (i = 0; i < file_info.thread_num; i++)
        {
            m_node[i].fp = fp;
            m_node[i].startidx = s_node[i].startidx;
            m_node[i].endidx = s_node[i].endidx;
            m_node[i].szdown = s_node[i].szdown;
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
        euapi_curl_share_cleanup(share);
    }
    return res;
}

static bool
md5_sum(const bool mdel)
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
        if (mdel)
        {
            DeleteFileW(file_info.names);
        }
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
            printf("init_sql_logs return false.\n");
            break;
        }
        if (!get_down_size(&size))
        {
            printf("get_down_size return false.\n");
            break;
        }
        if (size == length)
        {
            printf("file size eaual, not resume download.\n");
            break;
        }
        if ((fn = init_resume(url, length)))
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
        if (fill_file_name(url))
        {
            _snwprintf(sql_name, MAX_PATH, L"%s%s", file_info.names, L".sinfo");
            if (PathFileExistsW(file_info.names) && strlen(file_info.md5) > 1 && md5_sum(false))
            {
                *file_info.md5 = '\0';
                return true;
            }
            else if (PathFileExistsW(sql_name) && length > 0)
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
        } // 长度未知时,不启用日志文件
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
            m_error = m_node[0].error;
            break;
        }
        if (file_info.thread_num == 0 || file_info.thread_num == SELECT_AUTO)
        {
            file_info.thread_num = get_cpu_works();
        }
        if (file_info.thread_num > MAX_THREAD)
        {
            file_info.thread_num = MAX_THREAD;
        }
        if ((share = euapi_curl_share_init()) == NULL)
        {
            printf("euapi_curl_share_init() error.\n");
            m_error = true;
            break;
        }
        if (true)
        {
            gap = length / file_info.thread_num;
            total_size = length;
            downloaded_size = 0;
            euapi_curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
            euapi_curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
            euapi_curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
            euapi_curl_share_setopt(share, CURLSHOPT_LOCKFUNC, lock_cb);
            euapi_curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, unlock_cb);
        }
        for (i = 0; i < file_info.thread_num; i++)
        {
            m_node[i].startidx = i * gap;
            if (i == file_info.thread_num - 1)
            {
                m_node[i].endidx = length;
            }
            else
            {
                m_node[i].endidx = m_node[i].startidx + gap - 1;
            }
            m_node[i].szdown = m_node[i].startidx;
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
            else if (!thread_insert(url, m_node[i].startidx, m_node[i].endidx, m_node[i].startidx, 0, m_node[i].tid, GetCurrentProcessId(), 0))
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
        euapi_curl_share_cleanup(share);
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

static bool
share_envent_set_url(void)
{
    bool ret = false;
    if (file_info.url[0])
    {
        HANDLE hmap = share_open(FILE_MAP_WRITE | FILE_MAP_READ, UPCHECK_LOCK_NAME);
        if (hmap)
        {
            char (*pmemory)[URL_LEN] = (char (*)[URL_LEN])share_map(hmap, sizeof(g_download_url), FILE_MAP_WRITE | FILE_MAP_READ);
            if (pmemory)
            {
                int pos = -1;
                for (int i = 0; i < DOWN_NUM; ++i)
                {
                    if (pmemory[i][0])
                    {
                        if (strcmp(file_info.url, pmemory[i]) == 0)
                        {
                            pos = -1;
                            break;
                        }
                    }
                    else if (pos < 0)
                    {
                        pos = i;
                    }
                }
                if (pos >= 0)
                {
                    strncpy(pmemory[pos], file_info.url, URL_LEN - 1);
                }
                share_unmap(pmemory);
                ret = (pos != -1);
            }
            share_close(hmap);
        }
    }
    return ret;
}

static void
share_envent_close_url(HANDLE *phandle)
{
    if (file_info.url[0])
    {
        HANDLE hmap = share_open(FILE_MAP_WRITE | FILE_MAP_READ, UPCHECK_LOCK_NAME);
        if (hmap)
        {
            char (*pmemory)[URL_LEN] = (char (*)[URL_LEN])share_map(hmap, sizeof(g_download_url), FILE_MAP_WRITE | FILE_MAP_READ);
            if (pmemory)
            {
                for (int i = 0; i < DOWN_NUM; ++i)
                {
                    if (pmemory[i][0] && strcmp(file_info.url, pmemory[i]) == 0)
                    {
                        memset(pmemory[i], 0, sizeof(pmemory[i]));
                    }
                }
                share_unmap(pmemory);
            }
            share_close(hmap);
        }
    }
    share_close(*phandle);
}

static bool
downloaded_lookup(HANDLE *pmapped)
{
    bool ret = false;
    size_t url_size = sizeof(g_download_url);
    if (file_info.url[0])
    {
        if ((*pmapped = share_create(NULL, PAGE_READWRITE, url_size, UPCHECK_LOCK_NAME)) == NULL)
        {
            printf("downloaded_lookup function, share_create return false\n");
            return false;
        }
        else if (ERROR_ALREADY_EXISTS == GetLastError())
        {
            ret = share_envent_set_url();
            printf("downloaded_lookup function, ret = %d\n", ret);
        }
        else
        {   // 建立共享内存, 保存下载链接
            LPVOID phandle = share_map(*pmapped, url_size, FILE_MAP_WRITE | FILE_MAP_READ);
            if (phandle)
            {
                strncpy(g_download_url[0], file_info.url, URL_LEN - 1);
                memcpy(phandle, g_download_url, url_size);
                share_unmap(phandle);
                ret = true;
                printf("downloaded_lookup function, share_create ok, copy data to phandle\n");
            }
        }
    }
    return ret;
}

static void
msg_tips(void)
{
#ifndef EUAPI_LINK
    HWND fx = NULL;
    char *lpmsg = NULL;
    WCHAR msg[MAX_MESSAGE+1] = {0};
    if (ini_read_string("update", "msg", &lpmsg, file_info.ini, true) &&
        MultiByteToWideChar(CP_UTF8, 0, lpmsg, -1, msg, MAX_MESSAGE) > 0)
    {
        fx = get_moz_hwnd(0);
        wstr_replace(msg, wcslen(msg), L"\\n", L"\n");
        MessageBoxW(fx, msg, L"Tips:", MB_OK | MB_SETFOREGROUND);
    }
    if (lpmsg)
    {
        free(lpmsg);
    }
#endif
}

static void
logs_update(const int ret)
{
    if (ret == UPCHECK_DONT_ERR || ret == UPCHECK_OK)
    {
        char *str_time = NULL;
        uint64_t diff = 3600 * 24;
        uint64_t m_time1 = (uint64_t) time(NULL);
        uint64_t m_time2 = ini_read_uint64("update", "last_check", file_info.ini, false);
        if (m_time1 - m_time2 > diff)
        {
            char s_time[FILE_LEN] = { 0 };
            _ui64toa(m_time1, s_time, 10);
            if (!ini_write_string("update", "last_check", s_time, file_info.ini))
            {
                printf("ini_write_string return false.\n");
            }
        }
        if (ret == UPCHECK_OK)
        {
            ini_write_string("update", "be_ready", "1", file_info.ini);
        }
    }
}

static bool
exist_process(LPCWSTR path, const DWORD pid)
{
    bool more;
    bool result = false;
    PROCESSENTRY32W pe32 = {sizeof(pe32)};
    WCHAR fullpath[MAX_PATH] = {0};
    HANDLE handle  = NULL;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hsnap == INVALID_HANDLE_VALUE)
    {
        return result;
    }
    more = Process32FirstW(hsnap, &pe32);
    while (more)
    {
        DWORD length = MAX_PATH;
        if (pe32.th32ProcessID > 0x4 && 
           (handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID)) != NULL &&
           (QueryFullProcessImageName(handle, 0, fullpath, &length)) &&
           (length > 0 && length < MAX_PATH) &&
           (_wcsicmp(fullpath, path) == 0))
        {
            if (!(pid > 0 && pe32.th32ProcessID == pid))
            {
                result = true;
                break;
            }
        }
        more = Process32NextW(hsnap, &pe32);
    }
    CloseHandle(hsnap);
    return result;
}

static void
update_self(LPCWSTR self, LPCWSTR sz_clone)
{
    HANDLE hself = NULL;
    if (PathFileExistsW(self) && (hself = OpenProcess(SYNCHRONIZE, TRUE, GetCurrentProcessId())) != NULL)
    {
        // 准备更新自身
        PROCESS_INFORMATION pi;
        STARTUPINFOW si = {sizeof(si)};
        WCHAR sz_cmdLine[BUFF_LEN] = {0};
        _snwprintf(sz_cmdLine, BUFF_LEN - 1, L"\"%s\" -h %zu -d \"%s\"", self, (uintptr_t)hself, sz_clone);
        CreateProcessW(NULL, sz_cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
        CloseHandle(hself);
        CloseHandle(pi.hProcess);
    }
}

static void
update_task(void)
{
    bool   res = true;
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
        #ifdef LOG_DEBUG
            printf("%S DeleteFileW occurred: %lu.\n", file_info.del, GetLastError());
        #endif
        }
        ExitProcess(0);
    }
    if (GetModuleFileNameW(NULL, self, MAX_PATH) > 0 && exist_process(self, GetCurrentProcessId()))
    {   // 可能同时启动了多个更新进程
        ExitProcess(0);
    }
    if (file_info.pid > 0)
    {
    #ifndef EUAPI_LINK
        HANDLE tmp = OpenProcess(PROCESS_TERMINATE, false, file_info.pid);
        if (tmp)
        {   // 结束firefox进程
            TerminateProcess(tmp, (DWORD) -1);
            CloseHandle(tmp);
        }
    #endif
        if (wcslen(file_info.process) > 1)
        {
            Sleep(500);
            if (exist_process(file_info.process, 0))
            {
                *file_info.process = 0;
                *file_info.ini = 0;
                goto cleanup;
            }
        }
        if (set_ui_strings())
        {
            uint64_t numb = (uint64_t) _time64(NULL);
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
                _snwprintf(sz_clone, MAX_PATH, L"%s_%I64u%s", self, numb, L".exe");
                if (PathFileExistsW(sz_clone))
                {
                    DeleteFileW(sz_clone);
                }
                if (*self && _wrename(self, sz_clone))
                {
                    printf("_wrename Error occurred.\n");
                    res = false;
                    goto cleanup;
                }
            }
        }
    }
    if (thread != NULL && file_info.extract)  // 从file_info.unzip_dir获得复制文件的源目录
    {
    #if EUAPI_LINK
        bool result = true;
    #else
        bool result = false;
    #endif
        if (update_thread(NULL))
        {
            LPCWSTR msg = L"Failed to copy file,\n"
                          L"The update file is located in the user download directory,\n"
                          L"You may need to manually unzip to the installation directory";
            quit_progress();
            MessageBoxW(NULL, msg, L"Warning:", MB_OK|MB_ICONWARNING|MB_SYSTEMMODAL);
            res = false;
        }
    #ifndef EUAPI_LINK
        result = ini_write_string("update", "be_ready", NULL, file_info.ini);
    #endif
        if (result)
        {
            WaitForSingleObject(thread, 300);
            quit_progress();
            update_self(self, sz_clone);
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
    if (!res)
    {
        if (*self && *sz_clone)
        {
            if (!PathFileExistsW(self) && _wrename(sz_clone, self))
            {
                printf("we change back to original name, but rename back failed.\n");
            }
            if (PathFileExistsW(sz_clone))
            {
                DeleteFileW(sz_clone);
            }
        }
        ExitProcess(255);
    }
}

static bool
curl_task(int64_t length)
{
    bool res = false;
    INIT_LOCK(&g_mutex);
    if (init_download(file_info.url, length))
    {
        res = true;
    }
#ifndef EUAPI_LINK
    delete_temp_cookie();
#endif
    DESTROY_LOCK(&g_mutex);
    return res;
}

int
wmain(int argc, wchar_t **argv)
{
    int argn = 0;
    int ret = 0;
    wchar_t **wargv = NULL;
    HANDLE mapped = NULL;
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
    if (!(wargv = CommandLineToArgvW(GetCommandLine(), &argn)))
    {
        return UPCKECK_API_ERR;
    }
#ifdef LOG_DEBUG
    init_logs();
#endif
    if (argn < 2 || _wcsicmp(wargv[1], L"--help") == 0 || _wcsicmp(wargv[1], L"--version") == 0)
    {
        printf("Usage: %s [-i URL] [-o SAVE_PATH] [-t THREAD_NUMS] [-r REBIND] [-e EXTRACT_PATH]\nversion: 1.6.0\n",
               "upcheck.exe");
        LocalFree(wargv);
        return UPCHECK_OK;
    }
#if DLL_INJECT
    if (argn == 3 && _wcsicmp(wargv[1], L"-fix") == 0)
    {
        Sleep(200);
        ret = inject_mozdll() ? 0 : 1;
        DeleteFileW(wargv[2]);
        LocalFree(wargv);
        return ret;
    }
    if (argn == 3 && _wcsicmp(wargv[1], L"-dll2") == 0)
    {
        Sleep(2000);
        ret = inject_mozdll() ? UPCHECK_OK : UPCHECK_INJECT_ERR;
        CloseHandle(create_new(NULL, NULL, NULL, 2, NULL, _wtoi(wargv[2])));
        LocalFree(wargv);
        return ret;
    }
    if (argn == 2 && _wcsicmp(wargv[1], L"-file") == 0)
    {
        LocalFree(wargv);
        return file_mozdll();
    }
    if (argn == 2 && _wcsicmp(wargv[1], L"-dll") == 0)
    {
        ret = inject_mozdll() ? UPCHECK_OK : UPCHECK_INJECT_ERR;
        LocalFree(wargv);
        return ret;
    }
#endif
#ifndef EUAPI_LINK
    if (argn == 2 && (_wcsicmp(wargv[1], L"-a2quit") == 0 || _wcsicmp(wargv[1], L"-collect") == 0))
    {
        if (libcurl_init(CURL_GLOBAL_DEFAULT) == 0)
        {
            if (_wcsicmp(wargv[1], L"-a2quit") == 0)
            {
                ret = select_downloader(true, false);
            }
            else
            {
                ret = select_downloader(false, true);
            }
            libcurl_destory();
        }
        LocalFree(wargv);
        return ret;
    }
    if (argn >= 5 && (_wcsicmp(wargv[1], L"-lua") == 0 || _wcsicmp(wargv[1], L"-msg") == 0))
    {
        intptr_t moz_hwnd = 0;
        if (_wcsicmp(wargv[1], L"-lua") == 0)
        {
            if ((moz_hwnd = (intptr_t)get_moz_hwnd(_wtoi(wargv[2]))) != 0)
            {
                WCHAR hwnd_str[NAMES_LEN] = {0};
                _snwprintf(hwnd_str, NAMES_LEN - 1, L"%zd", moz_hwnd);
                if (enviroment_variables_set(L"UPCHECK_MOZ_HWND", hwnd_str, VARIABLES_RESET))
                {
                    if (enviroment_variables_set(L"UPCHECK_MOZ_PID", wargv[2], VARIABLES_RESET) && argn - 3 < NAMES_LEN)
                    {
                        int i = 0;
                        WCHAR *parg[NAMES_LEN] = {NULL};
                        for (; i < argn - 3; ++i)
                        {
                            parg[i] = wargv[i + 3];
                        }
                        ret = lua_script_loader(parg, i);
                    }
                }
            }
        }
        else if (_wcsicmp(wargv[1], L"-msg") == 0)
        {
            if ((moz_hwnd = (intptr_t)get_moz_hwnd(_wtoi(wargv[2]))) != 0)
            {
                int msg = _wtoi(wargv[3]);
                int wm = _wtoi(wargv[4]);
                ret = (int)SendMessageW((HWND)moz_hwnd, msg, wm, 0);
            }
        }
        LocalFree(wargv);
        return ret;
    }
    if (argn == 4 && _wcsnicmp(wargv[1], L"-chrome-", 8) == 0)
    {
        ret = -1;
        if (_wcsicmp(wargv[1], L"-chrome-check") == 0)
        {
            ret = chrome_check(wargv[2], wargv[3], false);
        }
        else if (_wcsicmp(wargv[1], L"-chrome-uncheck") == 0)
        {
            ret = chrome_check(wargv[2], wargv[3], true);
        }
        else if (_wcsicmp(wargv[1], L"-chrome-install") == 0)
        {
            ret = chrome_install(wargv[2], wargv[3]);
            libcurl_destory();
        }
        LocalFree(wargv);
    #ifdef LOG_DEBUG
        printf("chrome return %d\n", ret);
    #endif
        return ret;
    }
    if (argn == 4 && _wcsnicmp(wargv[1], L"-integration-", 13) == 0)
    {
        ret = -1;
        if (_wcsicmp(wargv[1], L"-integration-check") == 0)
        {
            ret = integration_check(wargv[2], wargv[3], false);
        }
        else if (_wcsicmp(wargv[1], L"-integration-uncheck") == 0)
        {
            ret = integration_check(wargv[2], wargv[3], true);
        }
        else if (_wcsicmp(wargv[1], L"-integration-install") == 0)
        {
            ret = integration_install(wargv[2], wargv[3]);
            libcurl_destory();
        }
        LocalFree(wargv);
    #ifdef LOG_DEBUG
        printf("integration return %d\n", ret);
    #endif
        return ret;
    }
#endif
    if (argn) // 初始化全局参数
    {
        memset(&file_info, 0, sizeof(file_info));
        if (!init_command_data(argn, wargv))
        {
            printf("init_command_data failed\n");
            LocalFree(wargv);
            return UPCKECK_DATA_ERR;
        }
    }
    if (wargv)
    {   // 不需要wargv变量了
        LocalFree(wargv);
        wargv = NULL;
    }
    do
    {
        dnld_params_t dt = {0};
        if (file_info.up || file_info.handle > 0) // 执行升级任务
        {
            update_task();
            break;
        }
        if (libcurl_init(CURL_GLOBAL_DEFAULT) != 0)
        {
            *file_info.ini = '\0';
            *file_info.process = L'\0';
            ret = UPCHECK_CURL_ERR;
            printf("Can not load curl.dll\n");
            break;
        }
    #ifndef EUAPI_LINK
        if (file_info.use_thunder > 0)
        {
            if (UPCHECK_OK == select_downloader(false, false))
            {
                break;
            }
        }
    #endif
        if (strlen(file_info.ini) > 1 || strlen(file_info.ini_uri) > 0) // 下载并解析ini文件
        {
            ret = init_resolver();
            if (ret == 0)
            {
                printf("init_resolver ok.\n");
                if ((strstr(file_info.url, "sourceforge.net") || strstr(file_info.url, "github.com")) && (file_info.re_bind == 0))
                {
                    file_info.re_bind = 1;
                }
            }
            else if (ret > 0)
            {
                printf("init_resolver return 1.\n");
                ret = UPCHECK_DONT_ERR;
                break;
            }
            else
            {
                printf("init_resolver return -1.\n");
                *file_info.ini = '\0';
                ret = UPCHECK_RESOLVER_ERR;
                break;
            }
        }
        if (strlen(file_info.url) < 2) // 没有下载任务
        {
            printf("not url\n");
            ret = UPCHECK_URL_ERR;
            break;
        }
        if (!downloaded_lookup(&mapped))
        {
            *file_info.ini = '\0';
            *file_info.process = L'\0';
            ret = UPCHECK_READY_ERR;
            printf("Is it already being downloaded?\n");
            break;
        }
        if (!get_file_lenth(file_info.url, &dt)) // 获取远程文件大小
        {
            printf("get_file_lenth return false\n");
            *file_info.ini = '\0';
            ret = UPCHECK_LENTH_ERR;  //or UPCHECK_404_ERR
            if (dt.ret != 307)
            {
            #ifndef EUAPI_LINK
                delete_temp_cookie();
            #endif
                break;
            }
        }
        if (dt.length == 0 && file_info.thread_num >= 1)
        {
            file_info.thread_num = 0;
        }
        if (!curl_task(dt.length)) // 开始下载任务
        {
            ret = UPCHECK_TASK_ERR;
            break;
        }
        if (strlen(file_info.md5) > 1 && !md5_sum(true)) // 核对文件md5值
        {
            ret = UPCHECK_MD5_ERR;
            break;
        }
        if (file_info.extract && extract7z(file_info.names, file_info.unzip_dir, NULL, 0)) // 解压缩升级包
        {
            ret = UPCHECK_EXTRACT_ERR;
            break;
        }
        if (strlen(file_info.ini) > 1) // 弹出消息提示
        {
            msg_tips();
        }
        ret = UPCHECK_OK;
    } while (0);
    libcurl_destory();
#ifndef EUAPI_LINK
    close_cookie_handle();
    if (!file_info.up && strlen(file_info.ini) > 1)
    {
        logs_update(ret);
    }
#endif
    if (mapped)
    {
        if (ret == UPCHECK_READY_ERR)
        {
            share_close(mapped);
        }
        else
        {
            share_envent_close_url(&mapped);
        }
    }
    if (wcslen(file_info.process) > 1)
    {
        CloseHandle(create_new(file_info.process, file_info.param, NULL, 2, NULL, 0));
    }
    return ret;
}
