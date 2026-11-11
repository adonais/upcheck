#include "spinlock.h"
#include "ini_parser.h"
#include "curl/curl.h"

#define RPC_BUFFER URL_LEN*2

static void
internal_file_path(char **pout, char **pfile)
{
    char *p = NULL;
    path_undo_quotes(file_info.names);
    if (exists_dir(file_info.names))
    {
        if (pout && ((*pfile = strdup(file_info.names)) != NULL))
        {
            *pout = path_add_quotes(*pfile);
            free(*pfile);
        }
        *pfile = NULL;
    }
    else if ((p = strrchr(file_info.names, '.')) != NULL && (p = strrchr(file_info.names, '/')) != NULL && (p - file_info.names + 1 < MAX_PATH))
    {
        char tmp[MAX_PATH + 2] = {0};
        if (pout)
        {
            snprintf(tmp, p - file_info.names + 2, "\"%s", file_info.names);
            if (tmp[strlen(tmp) - 1] != '"')
            {
                wp_strncat(tmp, "\"", MAX_PATH);
            }
            *pout = strdup(tmp);
        }
        snprintf(tmp, MAX_PATH, "\"%s", &p[1]);
        if (tmp[strlen(tmp) - 1] != '"')
        {
            wp_strncat(tmp, "\"", MAX_PATH);
        }
        *pfile = strdup(tmp);
    }
}

static size_t read_cb(char *dest, size_t size, size_t nmemb, void *userp)
{
    int *pt = (int *)userp;
    size_t buffer_size = size * nmemb;
    if (pt)
    {
        *pt += (int)buffer_size;
        if (*pt > 0 && strstr(dest, "\"error\":") == NULL)
        {
            return buffer_size;
        }
    }
    return 0;
}

static bool
aria2_init_socket(CURL **pcurl, const struct curl_slist *headers, const char *rpc, const char *token,
    const char *id, const char *mothod, const char *url, const char *refer, const char *cookie, int *pt)
{
    char *pstr = (char *)calloc(RPC_BUFFER, 1);
    char *json_header = (char *)calloc(MAX_PATH, 1);
    if (*pcurl)
    {
        curl_easy_reset(*pcurl);
    }
    else
    {
        *pcurl = curl_easy_init();
    }
    if (*pcurl && pstr && rpc && id && mothod && json_header)
    {
        const char *format = "{\"jsonrpc\": \"2.0\", \"id\": \"%s\", \"method\": \"%s\"";
        snprintf(json_header, MAX_PATH, format, id, mothod);
        if (url && refer)
        {   // rpc下载时使用配置文件指定目录
            char *file = NULL;
            internal_file_path(NULL, &file);
            if (token)
            {
                if (cookie)
                {
                    snprintf(pstr, URL_LEN, "%s, \"params\": [\"token:%s\",[\"%s\"],{\"referer\":\"%s\",\"load-cookies\":\"%s\"", json_header, token, url, refer, cookie);
                }
                else
                {
                    snprintf(pstr, URL_LEN, "%s, \"params\": [\"token:%s\",[\"%s\"],{\"referer\":\"%s\"", json_header, token, url, refer);
                }
            }
            else if (cookie)
            {
                snprintf(pstr, RPC_BUFFER, "%s, \"params\": [[\"%s\"],{\"referer\":\"%s\",\"load-cookies\":\"%s\"", json_header, url, refer, cookie);
            }
            else
            {
                snprintf(pstr, RPC_BUFFER, "%s, \"params\": [[\"%s\"],{\"referer\":\"%s\"", json_header, url, refer);
            }
            if (file)
            {   // 输出文件已经加了双引号
                wp_strncat(pstr, ",\"out\":", RPC_BUFFER);
                wp_strncat(pstr, file, RPC_BUFFER);
            }
            ini_safe_free(file);
            wp_strncat(pstr, "}]}", RPC_BUFFER);
        }
        else if (token)
        {
            snprintf(pstr, RPC_BUFFER, "%s, \"params\": [\"token:%s\"]}", json_header, token);
        }
        else
        {
            snprintf(pstr, RPC_BUFFER, "%s}", json_header);
        }
        curl_easy_setopt(*pcurl, CURLOPT_URL, rpc);
        curl_easy_setopt(*pcurl, CURLOPT_POST, 1L);
        curl_easy_setopt(*pcurl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(*pcurl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(*pcurl, CURLOPT_POSTFIELDS, pstr);
        curl_easy_setopt(*pcurl, CURLOPT_CONNECTTIMEOUT, 3L);
        curl_easy_setopt(*pcurl, CURLOPT_TIMEOUT, 6L);
        curl_easy_setopt(*pcurl, CURLOPT_WRITEFUNCTION, read_cb);
        curl_easy_setopt(*pcurl, CURLOPT_WRITEDATA, pt);
        curl_easy_setopt(*pcurl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_AUTO_CLIENT_CERT | CURLSSLOPT_NO_REVOKE);
        curl_easy_setopt(*pcurl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
    #if APP_DEBUG
        printf("pstr = <%s>，rpc = [%s]\n", pstr, rpc);
    #endif
        return true;
    }
    ini_safe_free(pstr);
    ini_safe_free(json_header);

    return false;
}

static bool
aria2_rpc_download(const char *aria2_path, const char *aria2_arg, const char *rpc, const char *token)
{
    int wt = 0;
    CURLcode res = 1;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    const char *aria2 = aria2_arg ? aria2_arg : aria2_path;
    const bool remote_rpc = !aria2 ? true : false;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    // headers = curl_slist_append(headers, "Accept: application/json");
    if (headers && (remote_rpc || aria2_init_socket(&curl, headers, rpc, token, "test", "aria2.getVersion", NULL, NULL, NULL, &wt)))
    {
        char *cookie = file_info.cookiefile[0] ? file_info.cookiefile : NULL;
        if (remote_rpc)
        {
            res = 0;
            printf("remote_rpc starting ...\n");
        }
        else if (curl)
        {
            res = curl_easy_perform(curl);
            printf("Testing version here: res = %d\n", res);
        }
        // 0x7, 主机链接不可达
        // 0x1c, 链接超时, 都代表Aria2c可能没启动, 尝试启动aria2 rpc
        // wt 如果没有接受到数据？某些代理可能导致res = 0
        if (res == 7L || res == 28L || wt == 0)
        {
            res = exec_ppv(aria2_path, aria2, 0);
        #if APP_DEBUG
            printf("Start the [%s] process here: res = %d\n", aria2, res);
        #endif
            sleep_ms(1000);
        }
        if (!res)
        {
            wt = 0;
            res = aria2_init_socket(&curl, headers, rpc, token, "upcheck", "aria2.addUri", file_info.url, file_info.referer, cookie, &wt) ? 0 : 1;
            if (!res)
            {
                res = curl_easy_perform(curl);
                if (!wt)
                {
                    res = 255;
                }
            }
        }
    }
    if (curl)
    {
        curl_easy_cleanup(curl);
    }
    if (headers)
    {
        curl_slist_free_all(headers);
    }
    printf("\nFunction aria2_rpc_download: res = %d\n", res);
    return res == 0;
}

static bool
aria2_rpc_try(const char *rpc, const char *token, const char *id, const char *cmd)
{
    CURLcode res = 1;
    CURL *curl = NULL;
    if (rpc)
    {
        int wt = 0;
        struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
        if (headers && aria2_init_socket(&curl, headers, rpc, token, id, cmd, NULL, NULL, NULL, &wt))
        {
            res = curl_easy_perform(curl);
            if (!wt)
            {
                res = 255;
            }
            curl_easy_cleanup(curl);
        }
        if (headers)
        {
            curl_slist_free_all(headers);
        }
    }
    return (res == 0);
}

static int
aria2_cmd_launch(const char *aria2, const char *arg, const int nohide)
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
            snprintf(dl, RPC_BUFFER, "\"%s\" \"%s\" --no-conf %s --referer=\"%s\" --load-cookies=\"%s\"",
                    aria2, file_info.url, arg, file_info.referer, file_info.cookiefile);
        }
        else
        {
            snprintf(dl, RPC_BUFFER, "\"%s\" \"%s\" --no-conf %s --referer=\"%s\" --load-cookies=\"%s\"",
                    aria2, file_info.url, arg, file_info.referer, file_info.cookiefile);
        }
        if (file)
        {
            wp_strncat(dl, " --out=", RPC_BUFFER);
            wp_strncat(dl, file, RPC_BUFFER);
        }
        if (dir)
        {
            wp_strncat(dl, " --dir=", RPC_BUFFER);
            wp_strncat(dl, dir, RPC_BUFFER);
        }
    #if APP_DEBUG
        printf("dl_command: [%s], nohide = [%s]\n", dl, nohide ? "true" : "false");
    #endif
        if (exec_ppv(aria2, dl, nohide ? 2 : 0) == 0)
        {
            ret = UPCHECK_OK;
        }
        free(dl);
        ini_safe_free(dir);
        ini_safe_free(file);
    }
    return ret;
}

int
select_downloader(const bool quit, const bool collect)
{
    char *arg = NULL;
    char *aria2_path = NULL;
    char *aria2_arg = NULL;
    char *aria2_rpc = NULL;
    char *aria2_token = NULL;
    ini_cache ini = NULL;
    bool use_rpc = false;
    bool use_aria = false;
    int ret = UPCHECK_TASK_ERR;
    int nohide = 0;
    do
    {
        if (!init_portable_path())
        {
            ret = UPCHECK_INI_ERR;
            printf("init_portable_path failed\n");
            break;
        }
        if ((ini = iniparser_create_cache(file_info.ini, false, true)) == NULL)
        {
            ret = UPCHECK_INI_ERR;
            printf("iniparser_create_cache\n");
            break;
        }
        if (inicache_read_string("aria2", "path", &aria2_path, &ini) && path_clone(&aria2_path) && which_path_exist("aria2c", aria2_path, BUFF_LEN))
        {   // 本地RPC,获取路径, 当没有启动时尝试帮助启动
            use_aria = true;
        #if APP_DEBUG
            printf("aria2_path = [%s]\n", aria2_path);
        #endif
            if (inicache_read_string("aria2", "rpc", &aria2_rpc, &ini))
            {
                use_rpc = true;
                inicache_read_string("aria2", "secret", &aria2_token, &ini);
            }
            if (!quit && !collect)
            {
                if (inicache_read_string("aria2", "arg", &arg, &ini) && use_rpc)
                {
                    if ((aria2_arg = (char *)calloc(1, BUFF_LEN)))
                    {
                        snprintf(aria2_arg, BUFF_LEN, "%s \"%s\"", aria2_path, arg);
                    }
                }
                // 读取nohide参数, 当aria2命令行下载时才产生作用
                nohide = inicache_read_int("aria2", "nohide", &ini);
            }
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
        #ifdef APP_DEBUG
            printf("aria2.forceShutdown, ret = %d\n", ret);
        #endif
            break;
        }
        if (collect)
        {
            ret = 0x1;
            if (use_aria)
            {
                ret |= 0x4;
            }
            if (use_rpc)
            {
                ret |= 0x8;
            }
            printf("collect run, ret = 0x%x\n", ret);
            break;
        }
        if (!(use_aria || use_rpc))
        {
            break;
        }
    #if APP_DEBUG
        printf("file_info.use_thunder = %d, use_aria = %d, use_rpc = %d\n", file_info.use_thunder, use_aria, use_rpc);
    #endif
        switch (file_info.use_thunder)
        {
            case 1:
            {
                if (use_rpc)
                {
                    ret = aria2_rpc_download(aria2_path, aria2_arg, aria2_rpc, aria2_token);
                }
                break;
            }
            case 2:
            {
                if (use_aria)
                {
                    ret = aria2_cmd_launch(aria2_path, arg ? arg : "", nohide);
                }
                break;
            }
            case 999:
            {   // 调用顺序aria2-rpc, aria2-cmd, thunder, upcheck
                if (use_rpc && aria2_rpc_download(aria2_path, aria2_arg, aria2_rpc, aria2_token))
                {
                    ret = UPCHECK_OK;
                }
                else if (use_aria && aria2_cmd_launch(aria2_path, arg ? arg : "", nohide) == 0)
                {
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
    ini_safe_free(arg);
    iniparser_destroy_cache(&ini);
    if (!quit)
    {
        *file_info.ini = '\0';
    }
    return ret;
}
