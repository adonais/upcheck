#include <stdio.h>
#include <wchar.h>
#include <shlwapi.h>
#include <windows.h>
#include "ini_parser.h"
#include "spinlock.h"
#include "thunderagent.h"

#define RPC_BUFFER (URL_LEN * 2)

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
        const char *json_tail = "}";
        _snprintf(json_header, MAX_PATH - 1, format, id, mothod);
        if (url && refer && cookie)
        {
            if (token)
            {
                _snprintf(pstr, URL_LEN, "%s, \"params\": [\"token:%s\",[\"%s\"],{\"referer\":\"%s\",\"load-cookies\":\"%s\"}]%s", json_header, token, url, refer, cookie, json_tail);
            }
            else
            {
                _snprintf(pstr, RPC_BUFFER, "%s, \"params\": [[\"%s\"],{\"referer\":\"%s\",\"load-cookies\":\"%s\"}]%s",
                          json_header, url, refer, cookie, json_tail);
            }
        }
        else if (token)
        {
            _snprintf(pstr, RPC_BUFFER, "%s, \"params\": [\"token:%s\"]%s", json_header, token, json_tail);
        }
        else
        {
            _snprintf(pstr, RPC_BUFFER, "%s%s", json_header, json_tail);
        }
        euapi_curl_easy_setopt(*pcurl, CURLOPT_URL, rpc);
        euapi_curl_easy_setopt(*pcurl, CURLOPT_HTTPHEADER, headers);
        euapi_curl_easy_setopt(*pcurl, CURLOPT_POSTFIELDS, pstr);
        euapi_curl_easy_setopt(*pcurl, CURLOPT_CONNECTTIMEOUT, 2L);
        libcurl_set_ssl(*pcurl);
        return true;
    }
    ini_safe_free(pstr);
    ini_safe_free(json_header);
    return false;
}

static bool
aria2_rpc_lookup(const char *aria2, const char *rpc, const char *token)
{
    CURLcode res = 1;
    CURL *curl = NULL;
    struct curl_slist *headers = euapi_curl_slist_append(NULL, "Content-Type: application/json");
    if (headers && aria2_init_socket(&curl, headers, rpc, token, "test", "aria2.getVersion", NULL, NULL, NULL))
    {
        res = euapi_curl_easy_perform(curl);
        str_replace(file_info.cookiefile, MAX_PATH, "\\", "/");
        // 0x7, aria2c可能没启动, 尝试启动aria2 rpc
        if (res == 7L && exec_ppv(aria2, NULL, 0))
        {
            Sleep(1000);
            if (aria2_init_socket(&curl, headers, rpc, token, "upcheck", "aria2.addUri", file_info.url, file_info.referer, file_info.cookiefile))
            {
                res = euapi_curl_easy_perform(curl);
            }
        }
        else if (res == 0 && aria2_init_socket(&curl, headers, rpc, token, "upcheck", "aria2.addUri", file_info.url, file_info.referer, file_info.cookiefile))
        {
            res = euapi_curl_easy_perform(curl);
        }
        euapi_curl_easy_cleanup(curl);
    }
    if (headers)
    {
        euapi_curl_slist_free_all(headers);
    }
    return res == 0;
}

static int
close_aria2_rpc(const char *rpc, const char *token)
{
    CURLcode res = 1;
    CURL *curl = NULL;
    if (rpc)
    {
        struct curl_slist *headers = euapi_curl_slist_append(NULL, "Content-Type: application/json");
        if (headers && aria2_init_socket(&curl, headers, rpc, token, "quit", "aria2.forceShutdown", NULL, NULL, NULL))
        {
            res = euapi_curl_easy_perform(curl);
            euapi_curl_easy_cleanup(curl);
        }
        if (headers)
        {
            euapi_curl_slist_free_all(headers);
        }
    }
    return res;
}

static int
launch_aria2_cmd(const char *aria2, const int nohide)
{
    int ret = 1;
    char  *dl = NULL;
    char *outdir = NULL;
    if (exists_dir(file_info.names))
    {
        outdir = ini_utf16_utf8(file_info.names, NULL);
    }
    if ((dl = (char *)calloc(1, RPC_BUFFER)) != NULL)
    {
        _snprintf(dl, RPC_BUFFER, "\"%s\" \"%s\" --no-conf --referer=\"%s\" --load-cookies=\"%s\"",
                 aria2, file_info.url, file_info.referer, file_info.cookiefile);
        if (outdir)
        {
            strncat(dl, " --dir=", RPC_BUFFER);
            strncat(dl, outdir, RPC_BUFFER);
        }
        printf("dl_command: [%s]\n", dl);
        if (exec_ppv(dl, NULL, nohide ? 2 : 0))
        {
            ret = UPCHECK_OK;
        }
    }
    ini_safe_free(dl);
    ini_safe_free(outdir);
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
select_downloader(const bool quit)
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
        {
            use_aria = true;
            if (inicache_read_string("aria2", "rpc", &aria2_rpc, &ini))
            {
                use_rpc = true;
                inicache_read_string("aria2", "secret", &aria2_token, &ini);
            }
            if (use_rpc && inicache_read_string("aria2", "arg", &aria2_arg, &ini) && strlen(aria2_path) < URL_LEN)
            {
                if (!(aria2_path = (char *)realloc(aria2_path, URL_LEN)))
                {
                    break;
                }
                strncat(aria2_path, " ", URL_LEN - 1);
                strncat(aria2_path, aria2_arg, URL_LEN - 1);
            }
            nohide = inicache_read_int("aria2", "nohide", &ini);
        }
        if (quit)
        {
            ret = use_rpc ? close_aria2_rpc(aria2_rpc, aria2_token) : UPCHECK_OK;
            break;
        }
        if (thunder_lookup())
        {
            use_thunder = true;
        }
        if (!(use_aria || use_rpc || use_thunder))
        {
            break;
        }
        switch (file_info.use_thunder)
        {
            case 1:
            {   // 指定了下载器, 不管成功或失败都将返回零
                if (use_thunder)
                {
                    thunder_download(file_info.url, file_info.referer, file_info.pcook);
                    ret = UPCHECK_OK;
                }
                break;
            }
            case 2:
            {
                if (use_rpc)
                {
                    aria2_rpc_lookup(aria2_path, aria2_rpc, aria2_token);
                    ret = UPCHECK_OK;
                }
                break;
            }
            case 3:
            {
                if (use_aria)
                {
                    launch_aria2_cmd(aria2_path, nohide);
                    ret = UPCHECK_OK;
                }
                break;
            }
            case 999:
            {
                if (use_rpc && aria2_rpc_lookup(aria2_path, aria2_rpc, aria2_token))
                {
                    ret = UPCHECK_OK;
                }
                else if (use_thunder && thunder_download(file_info.url, file_info.referer, file_info.pcook))
                {
                    delete_temp_cookie();
                    ret = UPCHECK_OK;
                }
                else if (use_aria)
                {
                    ret = launch_aria2_cmd(aria2_path, nohide);
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
