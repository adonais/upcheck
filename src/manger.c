#include <stdio.h>
#include <wchar.h>
#include <shlwapi.h>
#include <windows.h>
#include "ini_parser.h"
#include "spinlock.h"
#include "thunderagent.h"

#define RPC_BUFFER URL_LEN*2

static void
internal_file_path(char **pout, char **pfile)
{
    wchar_t *p = NULL;
    if (exists_dir(file_info.names))
    {
        if (pout && ((*pfile = ini_utf16_utf8(file_info.names, NULL)) != NULL))
        {
            *pout = path_add_quotes(*pfile);
            free(*pfile);
        }
        *pfile = NULL;
    }
    else if ((p = wcsrchr(file_info.names, L'.')) != NULL && (p = wcsrchr(file_info.names, L'\\')) != NULL)
    {
        wchar_t tmp[MAX_PATH+1] = {0};
        if (pout)
        {
            _snwprintf(tmp, p - file_info.names + 1, L"\"%s", file_info.names);
            wcsncat(tmp, L"\"", MAX_PATH);
            *pout = ini_utf16_utf8(tmp, NULL);
        }
        _snwprintf(tmp, MAX_PATH, L"\"%s\"", &p[1]);
        *pfile = ini_utf16_utf8(tmp, NULL);
    }
}

static bool
aria2_init_socket(CURL **pcurl, const struct curl_slist *headers, const char *rpc, const char *token, const char *id, const char *mothod, const char *url, const char *refer, const char *cookie)
{
    char *pstr = (char *)calloc(1, RPC_BUFFER);
    char *json_header = (char *)calloc(1, MAX_PATH);
    if (*pcurl)
    {
        euapi_curl_easy_reset(*pcurl);
    }
    else
    {
        *pcurl = euapi_curl_easy_init();
    }
    if (*pcurl && pstr && rpc && id && mothod && json_header)
    {
        const char *format = "{\"jsonrpc\": \"2.0\", \"id\": \"%s\", \"method\": \"%s\"";
        _snprintf(json_header, MAX_PATH - 1, format, id, mothod);
        if (url && refer)
        {   // rpc下载时使用配置文件指定目录
            char *file = NULL;
            internal_file_path(NULL, &file);
            if (token)
            {
                if (cookie)
                {
                    _snprintf(pstr, URL_LEN, "%s, \"params\": [\"token:%s\",[\"%s\"],{\"referer\":\"%s\",\"load-cookies\":\"%s\"", json_header, token, url, refer, cookie);
                }
                else
                {
                    _snprintf(pstr, URL_LEN, "%s, \"params\": [\"token:%s\",[\"%s\"],{\"referer\":\"%s\"", json_header, token, url, refer);
                }
            }
            else if (cookie)
            {
                _snprintf(pstr, RPC_BUFFER, "%s, \"params\": [[\"%s\"],{\"referer\":\"%s\",\"load-cookies\":\"%s\"", json_header, url, refer, cookie);
            }
            else
            {
                _snprintf(pstr, RPC_BUFFER, "%s, \"params\": [[\"%s\"],{\"referer\":\"%s\"", json_header, url, refer);
            }
            if (file)
            {   // 输出文件已经加了双引号
                strncat(pstr, ",\"out\":", RPC_BUFFER);
                strncat(pstr, file, RPC_BUFFER);
            }
            ini_safe_free(file);
            strncat(pstr, "}]}", RPC_BUFFER);
        }
        else if (token)
        {
            _snprintf(pstr, RPC_BUFFER, "%s, \"params\": [\"token:%s\"]}", json_header, token);
        }
        else
        {
            _snprintf(pstr, RPC_BUFFER, "%s}", json_header);
        }
        euapi_curl_easy_setopt(*pcurl, CURLOPT_URL, rpc);
        euapi_curl_easy_setopt(*pcurl, CURLOPT_HTTPHEADER, headers);
        euapi_curl_easy_setopt(*pcurl, CURLOPT_POSTFIELDS, pstr);
        euapi_curl_easy_setopt(*pcurl, CURLOPT_CONNECTTIMEOUT, 3L);
        euapi_curl_easy_setopt(*pcurl, CURLOPT_TIMEOUT, 6L);
        libcurl_set_ssl(*pcurl);
    #ifdef LOG_DEBUG
        printf("pstr = <%s>\n", pstr);
    #endif
        return true;
    }
    ini_safe_free(pstr);
    ini_safe_free(json_header);
    return false;
}

static bool
aria2_rpc_download(const char *aria2, const char *rpc, const char *token)
{
    CURLcode res = 1;
    CURL *curl = NULL;
    const bool remote_rpc = !aria2 ? true : false;
    struct curl_slist *headers = euapi_curl_slist_append(NULL, "Content-Type: application/json");
    if (headers && (remote_rpc || aria2_init_socket(&curl, headers, rpc, token, "test", "aria2.getVersion", NULL, NULL, NULL)))
    {
        char *cookie = file_info.cookiefile[0] ? file_info.cookiefile : NULL;
        if (cookie)
        {
            str_replace(cookie, MAX_PATH, "\\", "/");
        }
        if (remote_rpc)
        {
            res = 0;
        #ifdef LOG_DEBUG
            printf("remote_rpc starting ...\n");
        #endif
        }
        else
        {
            res = euapi_curl_easy_perform(curl);
        #ifdef LOG_DEBUG
            printf("Testing version here: res = %d\n", res);
        #endif
        }
        // 0x7, 主机链接不可达
        // 0x1c, 链接超时, 都代表Aria2c可能没启动, 尝试启动aria2 rpc
        if (res == 7L || res == 28L)
        {
            res = exec_ppv(aria2, NULL, 0) ? 0 : -1;
        #ifdef LOG_DEBUG
            printf("Start the [%s] process here: res = %d\n", aria2, res);
        #endif
            Sleep(1000);
        }
        if (!res)
        {
            res = aria2_init_socket(&curl, headers, rpc, token, "upcheck", "aria2.addUri", file_info.url, file_info.referer, cookie) ? 0 : 1;
            if (!res)
            {
                res = euapi_curl_easy_perform(curl);
            }
        }
    }
    if (curl)
    {
        euapi_curl_easy_cleanup(curl);
    }
    if (headers)
    {
        euapi_curl_slist_free_all(headers);
    }
#ifdef LOG_DEBUG
    printf("Function aria2_rpc_download: res = %d\n", res);
#endif
    return res == 0;
}

static bool
aria2_rpc_try(const char *rpc, const char *token, const char *id, const char *cmd)
{
    CURLcode res = 1;
    CURL *curl = NULL;
    if (rpc)
    {
        struct curl_slist *headers = euapi_curl_slist_append(NULL, "Content-Type: application/json");
        if (headers && aria2_init_socket(&curl, headers, rpc, token, id, cmd, NULL, NULL, NULL))
        {
            res = euapi_curl_easy_perform(curl);
            euapi_curl_easy_cleanup(curl);
        }
        if (headers)
        {
            euapi_curl_slist_free_all(headers);
        }
    }
    return res == 0;
}

static int
aria2_cmd_launch(const char *aria2, const int nohide)
{
    int ret = 1;
    char  *dl = NULL;
    if ((dl = (char *)calloc(1, RPC_BUFFER)) != NULL)
    {
        char *dir = NULL;
        char *file = NULL;
        internal_file_path(&dir, &file);
        if (file_info.cookiefile[0])
        {
            _snprintf(dl, RPC_BUFFER, "\"%s\" \"%s\" --no-conf --referer=\"%s\" --load-cookies=\"%s\"",
                     aria2, file_info.url, file_info.referer, file_info.cookiefile);
        }
        else
        {
            _snprintf(dl, RPC_BUFFER, "\"%s\" \"%s\" --no-conf --referer=\"%s\" --load-cookies=\"%s\"",
                     aria2, file_info.url, file_info.referer, file_info.cookiefile);
        }
        if (file)
        {
            strncat(dl, " --out=", RPC_BUFFER);
            strncat(dl, file, RPC_BUFFER);
        }
        if (dir)
        {
            strncat(dl, " --dir=", RPC_BUFFER);
            strncat(dl, dir, RPC_BUFFER);
        }
    #ifdef LOG_DEBUG
        printf("dl_command: [%s]\n", dl);
    #endif
        if (exec_ppv(dl, NULL, nohide ? 2 : 0))
        {
            ret = UPCHECK_OK;
        }
        free(dl);
        ini_safe_free(dir);
        ini_safe_free(file);
    }
    return ret;
}

void
close_cookie_handle(void)
{
    if (file_info.pcook)
    {
        free(file_info.pcook);
        file_info.pcook = NULL;
    }
    if (PathFileExistsW(file_info.cookie_tmp))
    {
        DeleteFileW(file_info.cookie_tmp);
    }
}

void
delete_temp_cookie(void)
{
    if (file_info.cookiefile[0])
    {
        WCHAR *tmp = ini_utf8_utf16(file_info.cookiefile, NULL);
        if (tmp && PathFileExistsW(tmp))
        {
            DeleteFileW(tmp);
        }
        ini_safe_free(tmp);
    }
}

int
select_downloader(const bool quit, const bool collect)
{
    char *aria2_path = NULL;
    char *aria2_arg = NULL;
    char *aria2_rpc = NULL;
    char *aria2_token = NULL;
    ini_cache ini = NULL;
    bool use_rpc = false;
    bool use_aria = false;
    bool use_thunder = false;
    int ret = UPCHECK_TASK_ERR;
    int nohide = 0;
    if (!quit)
    {
        CoInitialize(NULL);
    }
    do
    {
        if (!ini_path_init())
        {
            ret = UPCHECK_INI_ERR;
            break;
        }
        if ((ini = iniparser_create_cache(file_info.ini, false, true)) == NULL)
        {
            ret = UPCHECK_INI_ERR;
            break;
        }
        if (inicache_read_string("aria2", "path", &aria2_path, &ini) && utf8_path_exist(&aria2_path))
        {   // 本地RPC,获取路径, 当没有启动时尝试帮助启动
            char *arg = NULL;
            use_aria = true;
            if (inicache_read_string("aria2", "rpc", &aria2_rpc, &ini))
            {
                use_rpc = true;
                inicache_read_string("aria2", "secret", &aria2_token, &ini);
            }
            if (!quit && !collect)
            {
                if (use_rpc && inicache_read_string("aria2", "arg", &arg, &ini))
                {
                    if ((aria2_arg = (char *)calloc(1, BUFF_LEN)))
                    {
                        _snprintf(aria2_arg, BUFF_LEN - 1, "%s %s", aria2_path, arg);
                    }
                }
                if (!use_rpc)
                {
                    // 使用aria2命令行下载时才产生作用
                    nohide = inicache_read_int("aria2", "nohide", &ini);
                }
            }
            ini_safe_free(arg);
        }
        else if (inicache_read_string("aria2", "rpc", &aria2_rpc, &ini))
        {   // 远程RPC, 是否存在token
            inicache_read_string("aria2", "secret", &aria2_token, &ini);
            if (aria2_rpc_try(aria2_rpc, aria2_token, "test", "aria2.getVersion"))
            {
                use_rpc = true;
            }
        }
        if (quit)
        {
            ret = use_rpc ? (aria2_rpc_try(aria2_rpc, aria2_token, "quit", "aria2.forceShutdown") ? 0 : 1) : UPCHECK_OK;
        #ifdef LOG_DEBUG
            printf("aria2.forceShutdown, ret = %d\n", ret);
        #endif
            break;
        }
        if (thunder_lookup())
        {
            use_thunder = true;
        }
        if (collect)
        {
            ret = 0x1;
            if (use_thunder)
            {
                ret |= 0x2;
            }
            if (use_aria)
            {
                ret |= 0x4;
            }
            if (use_rpc)
            {
                ret |= 0x8;
            }
        #ifdef LOG_DEBUG
            printf("collect run, ret = 0x%x\n", ret);
        #endif
            break;
        }
        if (!(use_aria || use_rpc || use_thunder))
        {
            break;
        }
        switch (file_info.use_thunder)
        {
            case 1:
            {
                if (use_rpc)
                {
                    aria2_rpc_download(aria2_arg ? aria2_arg : aria2_path, aria2_rpc, aria2_token);
                    ret = UPCHECK_OK;
                }
                break;
            }
            case 2:
            {
                if (use_aria)
                {
                    aria2_cmd_launch(aria2_path, nohide);
                    ret = UPCHECK_OK;
                }
                break;
            }
            case 3:
            {   // 指定了下载器, 不管成功或失败都将返回零
                if (use_thunder)
                {
                    thunder_download(file_info.url, file_info.referer, file_info.pcook);
                    ret = UPCHECK_OK;
                }
                break;
            }
            case 999:
            {   // 调用顺序aria2-rpc, aria2-cmd, thunder, upcheck
                if (use_rpc && aria2_rpc_download(aria2_arg ? aria2_arg : aria2_path, aria2_rpc, aria2_token))
                {
                    ret = UPCHECK_OK;
                }
                else if (use_aria && aria2_cmd_launch(aria2_path, nohide) == 0)
                {
                    ret = UPCHECK_OK;
                }
                else if (use_thunder && thunder_download(file_info.url, file_info.referer, file_info.pcook))
                {
                    delete_temp_cookie();
                    ret = UPCHECK_OK;
                }
                break;
            }
            default:
            {
                break;
            }
        }
    } while(0);
    ini_safe_free(aria2_path);
    ini_safe_free(aria2_arg);
    ini_safe_free(aria2_rpc);
    ini_safe_free(aria2_token);
    iniparser_destroy_cache(&ini);
    if (!quit)
    {
        *file_info.ini = '\0';
        CoUninitialize();
    }
    return ret;
}
