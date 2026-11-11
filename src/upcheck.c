#include "spinlock.h"
#include "upcheck.h"
#include "urlcode.h"
#include "cookies.h"
#include "load_script.h"
#include "load_chrome.h"
#include "manger.h"
#include "json_paser.h"
#include "extractxz.h"
#include "xml.h"
#include <pthread.h>

#define DOWN_NUM    10
#define SELECT_AUTO 999
#define MMAP_DATA_SIZE (DOWN_NUM * URL_LEN)

static int64_t downloaded_size = 0;
static int64_t total_size = 0;

file_info_t file_info = {0};

static char* ns_user_dir_lookup(const char* type)
{
    FILE* file;
    char* home_dir;
    char* config_home;
    char* config_file;
    char buffer[512];
    char* user_dir;
    char* p;
    char* d;
    int len;
    int relative;

    home_dir = getenv("HOME");

    if (!home_dir) {
        goto error;
    }

    config_home = getenv("XDG_CONFIG_HOME");
    if (!config_home || config_home[0] == 0) {
        config_file = (char*)malloc(strlen(home_dir) + strlen("/.config/user-dirs.dirs") + 1);
        if (!config_file) {
            goto error;
        }
        strcpy(config_file, home_dir);
        strcat(config_file, "/.config/user-dirs.dirs");
    } else {
        config_file = (char*)malloc(strlen(config_home) + strlen("/user-dirs.dirs") + 1);
        if (!config_file) {
            goto error;
        }

        strcpy(config_file, config_home);
        strcat(config_file, "/user-dirs.dirs");
    }

    file = fopen(config_file, "r");
    free(config_file);
    if (!file) {
        user_dir = (char*)malloc(strlen(home_dir) + strlen("/Downloads") + 1);
        if (!user_dir) {
            goto error;
        }
        strcpy(user_dir, home_dir);
        strcat(user_dir, "/Downloads");
        return user_dir;
    }

    user_dir = NULL;
    while (fgets(buffer, sizeof(buffer), file)) {
        /* Remove newline at end */
        len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = 0;
        }

        p = buffer;
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (strncmp(p, "XDG_", 4) != 0) {
            continue;
        }
        p += 4;
        if (strncmp(p, type, strlen(type)) != 0) {
            continue;
        }
        p += strlen(type);
        if (strncmp(p, "_DIR", 4) != 0) {
            continue;
        }
        p += 4;

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (*p != '=') {
            continue;
        }
        p++;

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (*p != '"') {
            continue;
        }
        p++;

        relative = 0;
        if (strncmp(p, "$HOME/", 6) == 0) {
            p += 6;
            relative = 1;
        } else if (*p != '/') {
            continue;
        }

        if (relative) {
            user_dir = (char*)malloc(strlen(home_dir) + 1 + strlen(p) + 1);
            if (!user_dir) {
                goto error2;
            }

            strcpy(user_dir, home_dir);
            strcat(user_dir, "/");
        } else {
            user_dir = (char*)malloc(strlen(p) + 1);
            if (!user_dir) {
                goto error2;
            }

            *user_dir = 0;
        }

        d = user_dir + strlen(user_dir);
        while (*p && *p != '"') {
            if ((*p == '\\') && (*(p + 1) != 0)) {
                p++;
            }
            *d++ = *p++;
        }
        *d = 0;
    }
error2:
    fclose(file);
    if (user_dir) {
        return user_dir;
    }

error:
    return NULL;
}

static bool
get_download_dir(char *path)
{
    int n = 0;
    char *down = ns_user_dir_lookup("DOWNLOAD");
    if (down) {
        n = snprintf(path, MAX_PATH, "%s", down);
        free(down);
    }
    return (n > 0 && n < MAX_PATH);
}

/* 智能分析需要保持的文件名并建立目录 */
static void
path_parsing(const char *save_path)
{
    int len = 0;
    char *down = NULL;
    if (NULL == save_path || *save_path == 0)
    {
        return;
    }
    if (strrchr(save_path, '.'))
    {   // 完整的文件路径
        if (save_path[0] == '/' || (save_path[0] == '"' && save_path[1] == '/'))
        {
            snprintf(file_info.names, MAX_PATH, "%s", save_path);
        }
        else if (save_path[0] != '.')
        {   // 只有文件名, 默认到下载目录
            down = ns_user_dir_lookup("DOWNLOAD");
            if (down)
            {
                snprintf(file_info.names, MAX_PATH, "%s/%s", down, save_path);
            }
        }
        else if ((down = realpath(save_path, NULL)) != NULL)
        {
            snprintf(file_info.names, MAX_PATH, "%s", down);
        }
    }
    else
    {
        if (!exists_dir(save_path))
        {
            create_dir(save_path, 0755);
        }
        if ((len = snprintf(file_info.names, MAX_PATH, "%s", save_path)) > 0 && len < MAX_PATH)
        {   // 加上目录符, 下载时自动加文件名
            len = (int)strlen(file_info.names);
            if (file_info.names[len - 1] != '/')
            {
                wp_strncat(file_info.names, "/", MAX_PATH);
            }
        }
    }
    if (down)
    {
        free(down);
    }
}

static bool
init_command_data(const int args, const char **pv)
{
    bool ret = true;
    bool found = false;
    do
    {
        int n = 0;
        const int argn = args + 1;
        for (int i = 1; i < argn - 1; ++i)
        {
            if (strcasecmp(pv[i], "-i") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                n = snprintf(file_info.url, URL_LEN, "%s", pv[i + 1]);
                if (!(n > 0 && n < URL_LEN))
                {
                    printf("file_info.url error\n");
                    ret = false;
                    break;
                }
                path_undo_quotes(file_info.url);
            } // 下载目录
            else if (strcasecmp(pv[i], "-o") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                if (strlen(pv[i + 1]) > 1)
                {
                    char path[MAX_PATH] = {0};
                    snprintf(path, MAX_PATH, "%s", pv[i + 1]);
                    found = true;
                    path_parsing(path_undo_quotes(path));
                }
            } // 下载时线程数目
            else if (strcasecmp(pv[i], "-t") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.thread_num = atoi(pv[i + 1]);
            } // 断线重连
            else if (strcasecmp(pv[i], "-r") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.re_bind = atoi(pv[i + 1]);
            } // 杀死进程
            else if (strcasecmp(pv[i], "-k") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.pid = atoi(pv[i + 1]);
            } // 设置cookies
            else if (strcasecmp(pv[i], "-b") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                if (pv[i + 1][0] != 0)
                {
                    n = snprintf(file_info.cookiefile, MAX_PATH, "%s", pv[i + 1]);
                    if (!(n > 0 && n < MAX_PATH))
                    {
                        printf("file_info.cookiefile error\n");
                        ret = false;
                        break;
                    }
                    path_undo_quotes(file_info.cookiefile);
                }
            }
            else if (strcasecmp(pv[i], "-cok") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                if (pv[i + 1][0] != 0)
                {
                    n = snprintf(file_info.cookie_tmp, MAX_PATH, "%s", pv[i + 1]);
                    if (!(n > 0 && n < MAX_PATH))
                    {
                        printf("file_info.cookie_tmp error\n");
                        ret = false;
                        break;
                    }
                    path_undo_quotes(file_info.cookie_tmp);
                    get_first_line(&(file_info.pcook), file_info.cookie_tmp);
                }
            }
            else if (strcasecmp(pv[i], "-ref") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                if (pv[i + 1][0] != 0)
                {
                    n = snprintf(file_info.referer, MAX_PATH, "%s", pv[i + 1]);
                    if (!(n >= 0 && n < MAX_PATH))
                    {
                        printf("file_info.referer error\n");
                        ret = false;
                        break;
                    }
                    path_undo_quotes(file_info.referer);
                    printf("referer = [%s]\n", file_info.referer);
                }
            } // 解压目录
            else if (strcasecmp(pv[i], "-e") == 0)
            {
                file_info.extract = true;
                VERIFY(i + 1 < argn - 1);
                n = snprintf(file_info.unzip_dir, MAX_PATH, "%s", pv[i + 1]);
                if (!(n > 0 && n < MAX_PATH))
                {
                    printf("file_info.unzip_dir error\n");
                    ret = false;
                    break;
                }
                path_undo_quotes(file_info.unzip_dir);
            } // 更新完毕后启动的进程名
            else if (strcasecmp(pv[i], "-s") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                n = snprintf(file_info.process, MAX_PATH, "%s", pv[i + 1]);
                if (!(n > 0 && n < MAX_PATH))
                {
                    printf("file_info.process error\n");
                    ret = false;
                    break;
                }
                path_undo_quotes(file_info.process);
            }
            else if (strcasecmp(pv[i], "-d") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                n = snprintf(file_info.del, MAX_PATH, "%s", pv[i + 1]);
                if (!(n > 0 && n < MAX_PATH))
                {
                    printf("file_info.del error\n");
                    ret = false;
                    break;
                }
                path_undo_quotes(file_info.del);
            }
            else if (strcasecmp(pv[i], "-m") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                // thunder
                file_info.use_thunder = atoi(pv[i + 1]);
                if (!file_info.use_thunder)
                {
                    file_info.use_thunder = SELECT_AUTO;
                }
            }
            else if (strcasecmp(pv[i], "-dt") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                file_info.dt_local = (uint64_t)strtoll(pv[i + 1], NULL, 10);
            }
            else if (strcasecmp(pv[i], "-uri") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                n = snprintf(file_info.ini_uri, MAX_PATH, "%s", pv[i + 1]);
                if (!(n > 0 && n < MAX_PATH))
                {
                    printf("file_info.ini_uri error\n");
                    ret = false;
                    break;
                }
                path_undo_quotes(file_info.ini_uri);
            }
            else if (strcasecmp(pv[i], "-param") == 0)
            {
                VERIFY(i + 1 < argn - 1);
                n = snprintf(file_info.param, MAX_PATH, "%s", pv[i + 1]);
                if (!(n > 0 && n < MAX_PATH))
                {
                    printf("file_info.param error\n");
                    ret = false;
                    break;
                }
                path_undo_quotes(file_info.param);
            }
        }
        if (ret && !found) /* default download directory */
        {
            char path[MAX_PATH + 1] = {0};
            if (!get_download_dir(path))
            {
                break;
            }
            path_parsing(path_undo_quotes(path));
        #ifdef APP_DEBUG
            printf("download dir[%s]\n", path);
        #endif
        }
    } while(0);
    return ret;
}

static void
curl_set_cookies(CURL *curl)
{
    if (strstr(file_info.url, "sf.net") || strstr(file_info.url, "sourceforge.net"))
    {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/8.17.0");
        curl_easy_setopt(curl, CURLOPT_COOKIE, "");
    }
    else if (file_info.referer[0] && file_info.cookiefile[0])
    {
        curl_easy_setopt(curl, CURLOPT_REFERER, file_info.referer);
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, file_info.cookiefile);
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
        if (p - u < MAX_PATH - 1)
        {
            snprintf(oname, p - u + 1, "%s", u);
        }
        else
        {
            /* 没有从重定向url得到正确文件名 */
            snprintf(oname, MAX_PATH, "%s", "a.zip");
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
    const char *etag = "Etag: ";
    dnld_params_t *dnld_params = (dnld_params_t *) userdata;
    if (strcasestr(hdr_str, " 307"))
    {
        dnld_params->ret = 307;
    }
    /* Example: Ranges supports
     * Accept-Ranges: bytes
    */
    if (strcasestr(hdr_str, "Accept-Ranges: bytes"))
    {
        if (!(file_info.thread_num > 0 && file_info.thread_num < SELECT_AUTO))
        {
            file_info.thread_num = SELECT_AUTO;
        }
        file_info.ranges = true;
        printf("\nthis server Accept-Ranges: bytes, file_info.thread_num = %d\n", file_info.thread_num);
    }
    else if (strcasestr(hdr_str, " 404"))
    {
        return 0;
    }
    if ((p = strcasestr(hdr_str, etag)) != NULL)
    {
        size_t len = 0;
        p += strlen(etag);
        if (*p == '"')
        {
            ++p;
        }
        snprintf(file_info.etag, NAMES_LEN, "%s", p);
        if ((len = strlen(file_info.etag)) > 1)
        {
            if (file_info.etag[len - 1] == '\n')
            {
                file_info.etag[len - 1] = 0;
                len = strlen(file_info.etag);
            }
            if (file_info.etag[len - 1] == '\r')
            {
                file_info.etag[len - 1] = 0;
                len = strlen(file_info.etag);
            }
            if (file_info.etag[len - 1] == '"')
            {
                file_info.etag[len - 1] = 0;
            }
            printf("file_info.etag[%s]\n", file_info.etag);
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
                snprintf(dnld_params->file_len, UINT_LEN, "%s", &p[0]);
            }
        }
    } while (0);
    if (strlen(dnld_params->remote_fname) > 1)
    {
        snprintf(file_info.remote_names, MAX_PATH, "%s", dnld_params->remote_fname);
    }
    else
    {
        snprintf(file_info.remote_names, MAX_PATH, "%s", "a.zip");
    }
    printf("file_info.remote_names = [%s]\n", file_info.remote_names);
    return cb;
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

static int sets_progress_func(void *ptr, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
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

static void *run_thread(void *pdata)
{
    int i = 0;
    curl_node *pnode = (curl_node *) pdata;
    pnode->tid = (uint32_t)pthread_self();
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
                if ((m_ranges = calloc(FILE_LEN, 1)) == NULL)
                {
                    break;
                }
                snprintf(m_ranges, FILE_LEN, "%ld-%ld", pnode->szdown, pnode->endidx);
                curl_easy_setopt(curl, CURLOPT_RANGE, m_ranges);
                printf("\nthead: %u[%s] setup \n", pnode->tid, m_ranges);
            }
            if (m_ranges)
            {
                free(m_ranges);
            }
            curl_set_cookies(curl);
            curl_easy_setopt(curl, CURLOPT_SHARE, pnode->share);
            // 设置重定向的最大次数,301、302跳转跟随location
            curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 4L);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
            // 关掉CLOSE_WAIT
            curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, download_package);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, pnode);
            init_curl_ssl(curl);
        #if defined(APP_DEBUG)
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        #endif
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 3L);
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30L);
            curl_easy_setopt(curl, CURLOPT_RESUME_FROM, 0L);
            res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
            if (res == CURLE_OK)
            {
                pnode->error = false;
                printf("\ndownload message: ok, %u thread exit\n", pnode->tid);
                break;
            }
            else if (res == CURLE_COULDNT_CONNECT || res == CURLE_HTTP2_STREAM)
            {
                pnode->error = true;
                printf("\ndownload error: code[%d], retry[%s]\n", res, file_info.re_bind ? "true": "false");
            }
            else // CURLE_PARTIAL_FILE, CURLE_OPERATION_TIMEDOUT
            {
                pnode->error = true;
                printf("\ndownload error: code[%d]\n", res);
                break;
            }
        } // 非严重错误时自动重试8次
    } while (file_info.re_bind && ++i < URL_ITERATIONS);
    if (!pnode->error && total_size > 0)
    {
        update_status(pnode->tid, 1);
    }
    return NULL;
}

/************************************************************************/
/* 获取要下载的远程文件的大小                                           */
/************************************************************************/
static int
get_file_size(const char *url, dnld_params_t *dnld_params)
{
    CURL *handle = NULL;
    CURLcode res = CURLE_FAILED_INIT;
    if ((handle = curl_easy_init()) != NULL)
    {
        curl_easy_setopt(handle, CURLOPT_URL, url);
        curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "HEAD");
        curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, curl_header_parse);
        curl_easy_setopt(handle, CURLOPT_HEADERDATA, dnld_params);
        // 设置链接超时
        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 60L);
        curl_easy_setopt(handle, CURLOPT_TIMEOUT, 120L);
        // curl_set_cookies(handle);
        init_curl_ssl(handle);
        // 设置重定向的最大次数
        curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 4L);
        // 设置301、302跳转跟随location
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
        //不需要body, 只需要header头
        curl_easy_setopt(handle, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(handle, CURLOPT_HEADER, 1L);
        curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
        if ((res = curl_easy_perform(handle)) == CURLE_OK)
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
            const char *err_string = curl_easy_strerror(res);
            printf("%s[%s] error[%d]: %s\n", __FUNCTION__, url, res, err_string);
            dnld_params->length = 0;
        }
        curl_easy_cleanup(handle);
        printf("dnld_params->length = %ld\n", dnld_params->length);
    }
    return res;
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
        sprintf(code_names, "%s", file_info.remote_names);
        if (!url_decode_t(code_names))
        {
            return false;
        }
        printf("\ndiscode_names1: %s\n", code_names);
        if (strcmp(code_names, file_info.remote_names) != 0)
        {
            snprintf(file_info.remote_names, MAX_PATH, "%s", code_names);
        }
        path_undo_quotes(file_info.remote_names);
    }
    else if (strchr(file_info.remote_names, '%'))
    {
        sprintf(code_names, "%s", file_info.remote_names);
        if (!url_decode_t(code_names))
        {
            return false;
        }
        printf("\ndiscode_names2: %s\n", code_names);
        if (strcmp(code_names, file_info.remote_names) != 0)
        {
            snprintf(file_info.remote_names, MAX_PATH, "%s", code_names);
        }
        path_undo_quotes(file_info.remote_names);
    }
    if ((len = (int) strlen(file_info.names)) < 2)
    {
        len = snprintf(file_info.names, MAX_PATH, "%s", path_undo_quotes(file_info.remote_names));
        if (!(len > 0 && len < MAX_PATH))
        {
            printf("Copy to file_info.names false\n");
            return false;
        }
    }
    else if (file_info.names[len - 1] == '/')
    {
        wp_strncat(file_info.names, path_undo_quotes(file_info.remote_names), MAX_PATH);
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
        printf("init_resume function, num = %d, szDown = %ld\n", num, s_node[0].szdown);
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
        pthread_t m_handle[MAX_THREAD] = {0};
        if ((fp = fopen(file_info.names, "r+")) == NULL)
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
        for (i = 0; i < file_info.thread_num; ++i)
        {
            m_node[i].fp = fp;
            m_node[i].startidx = s_node[i].startidx;
            m_node[i].endidx = s_node[i].endidx;
            m_node[i].szdown = s_node[i].szdown;
            m_node[i].share = share;
            m_node[i].tid = s_node[i].thread;
            m_node[i].url = url;
            m_node[i].error = false;
            if (pthread_create(&m_handle[i], NULL, run_thread, &m_node[i]) != 0)
            {
                printf("pthread_create false, error[%d]\n", i);
                res = false;
                break;
            }
        }
        for (i = 0; i < file_info.thread_num; ++i)
        {
            if ((pthread_join(m_handle[i], NULL) == 0))
            {
                m_handle[i] = 0;
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
md5_sum(const bool mdel)
{
    bool res = false;
    char md5_str[MD5_DIGEST_LENGTH * 2 + 1] = { 0 };
    if (get_file_md5(file_info.names, md5_str) && strcasecmp(md5_str, file_info.md5) == 0)
    {
        printf("%s [md5: %s]\n", file_info.names, md5_str);
        res = true;
    }
    else
    {
        if (mdel)
        {
            delete_file(file_info.names);
        }
        printf("package md5[%s] sum error! cause file [%s]\n", md5_str, file_info.md5);
    }
    return res;
}

static bool
resume_download(const char *url, int64_t length, const char *path)
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
            delete_file(file_info.names);
        }
    } while (0);
    clean_sql_logs();
    if (*path != '\0')
    {
        delete_file(path);
    }
    return fn;
}

static bool
init_download(const char *url, int64_t length)
{
    int i = 0;
    FILE *fp = NULL;
    bool m_error = false;
    char sql_name[MAX_PATH] = { 0 };
    CURLSH *share = NULL;
    do
    {
        curl_node m_node[MAX_THREAD];
        pthread_t m_handle[MAX_THREAD] = { 0 };
        int64_t gap = 0;
        if (length == 0 || length >= INT64_MAX)
        {
            printf("get the file size error...\n");
            length = 0;
        }
        if (fill_file_name(url))
        {
            snprintf(sql_name, MAX_PATH, "%s.sinfo", path_undo_quotes(file_info.names));
            if (exists_file(file_info.names) && strlen(file_info.md5) > 1 && md5_sum(false))
            {
                *file_info.md5 = '\0';
                return true;
            }
            else if (exists_file(sql_name) && length > 0)
            {
                if (!exists_file(file_info.names))
                {
                    delete_file(sql_name);
                }
                else if (!file_info.ranges || get_etag_different(sql_name))
                {
                    delete_file(sql_name);
                    delete_file(file_info.names);
                    printf("Not ranges or Etag different, file_info.ranges = %d\n", file_info.ranges);
                }
                else
                {   // 存在日志记录文件,准备续传
                    return resume_download(url, length, path_undo_quotes(sql_name));
                }
            }
        } // 长度未知时,不启用日志文件
        if (!length || init_sql_logs(path_undo_quotes(sql_name)))
        {
            fp = fopen(path_undo_quotes(file_info.names), "wb");
        }
        if (NULL == fp)
        {
            printf("fopen[%s] error!\n", file_info.names);
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
        if (!file_info.ranges)
        {
            file_info.thread_num = 1;
        }
        else if (file_info.thread_num == 0 || file_info.thread_num == SELECT_AUTO)
        {
            file_info.thread_num = sysconf(_SC_NPROCESSORS_ONLN);
        }
        if (file_info.thread_num > MAX_THREAD)
        {
            file_info.thread_num = MAX_THREAD;
        }
        if ((share = curl_share_init()) == NULL)
        {
            printf("curl_share_init() error.\n");
            m_error = true;
            break;
        }
        if (true)
        {
            gap = length / file_info.thread_num;
            total_size = length;
            downloaded_size = 0;
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
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
            if (pthread_create(&m_handle[i], NULL, run_thread, &m_node[i]) != 0)
            {
                printf("pthread_create false, error[%d]\n", i);
                m_error = true;
                break;
            }
            else if (!thread_insert(url, file_info.etag, m_node[i].startidx, m_node[i].endidx, m_node[i].startidx, 0, (uint32_t)m_handle[i], (uint32_t)getpid(), 0))
            {
                printf("thread_insert() false.\n");
                m_error = true;
                break;
            }
        }
        for (i = 0; i < file_info.thread_num; i++)
        {
            if ((pthread_join(m_handle[i], NULL) == 0))
            {
                m_handle[i] = 0;
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
        delete_file(file_info.names);
        if (*sql_name != '\0')
        {
            delete_file(sql_name);
        }
    }
    else
    {
        printf("\ndownload succed......\n");
        if (*sql_name != '\0')
        {
            delete_file(sql_name);
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
        int fd = shm_open(UPCHECK_LOCK_NAME, O_RDWR, 0666);
        if (fd > 0)
        {
            char (*pmemory)[URL_LEN] = (char (*)[URL_LEN])mmap(NULL, MMAP_DATA_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
            if (pmemory)
            {
                int pos = -1;
                for (int i = 0; i < DOWN_NUM; ++i)
                {
                    if (pmemory[i][0])
                    {
                        if (strcasecmp(file_info.url, pmemory[i]) == 0)
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
                munmap(pmemory, MMAP_DATA_SIZE);
                ret = (pos != -1) || (!duplicate_process_run());
            }
            close(fd);
        }
    }
    return ret;
}

static void
share_envent_close_url(void)
{
    if (file_info.url[0])
    {
        int fd = shm_open(UPCHECK_LOCK_NAME, O_RDWR, 0666);
        if (fd > 0)
        {
            int k = 0;
            char (*pmemory)[URL_LEN] = (char (*)[URL_LEN])mmap(NULL, MMAP_DATA_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
            if (pmemory)
            {
                for (int i = 0; i < DOWN_NUM; ++i)
                {
                    if (pmemory[i][0] && strcasecmp(file_info.url, pmemory[i]) == 0)
                    {
                        memset(pmemory[i], 0, URL_LEN);
                    }
                    if (pmemory[i][0])
                    {
                        ++k;
                    }
                }
                munmap(pmemory, MMAP_DATA_SIZE);
            }
            close(fd);
            if (!k || !duplicate_process_run())
            {   // 没有数据后, 关闭共享内存
                if (shm_unlink(UPCHECK_LOCK_NAME) == 0)
                {
                    printf("After no data is available, close the shared memory\n");
                }
            }
        }
    }
}

static bool
downloaded_lookup(void)
{
    bool ret = false;
    if (file_info.url[0])
    {
        int fd = -1;
        if ((fd = shm_open(UPCHECK_LOCK_NAME, O_CREAT | O_EXCL | O_RDWR, 0666)) < 0)
        {
            if (EEXIST == errno)
            {
                ret = share_envent_set_url();
                printf("shared_mem_exist, we run share_envent_set_url(), ret = %d\n", ret);
            }
            else
            {
                printf("downloaded_lookup function, share_create return false\n");
            }
        }
        else if (ftruncate(fd,  MMAP_DATA_SIZE) == 0)
        {   // 建立共享内存, 保存下载链接
            void *add_r = mmap(NULL, MMAP_DATA_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
            if (add_r)
            {
                char download_url[DOWN_NUM][URL_LEN] = {0};
                strncpy(download_url[0], file_info.url, URL_LEN - 1);
                memcpy(add_r, download_url, MMAP_DATA_SIZE);
                munmap(add_r,  MMAP_DATA_SIZE);
                ret = true;
                printf("downloaded_lookup function, share_create ok, copy data to shared_mem_addr\n");
            }
        }
        if (fd)
        {
            close(fd);
        }
    }
    return ret;
}

static bool
curl_task(int64_t length)
{
    bool res = false;
    if (init_download(file_info.url, length))
    {
        res = true;
    }
    delete_cookie_file();
    return res;
}

int
main(int argc, char **argv)
{
    int ret = 0;
    if (argc < 2 || strcasecmp(argv[1], "--help") == 0 || strcasecmp(argv[1], "--version") == 0)
    {
        printf("Usage: %s [-i URL] [-o SAVE_PATH] [-t THREAD_NUMS] [-r REBIND] [-e EXTRACT_PATH]\nversion: 1.6.0\n", "upcheck");
        return UPCHECK_OK;
    }
#if defined(LOG_DEBUG)
    init_logs();
#endif
    if (argc >= 2 && (strcasecmp(argv[1], "-a2quit") == 0 || strcasecmp(argv[1], "-collect") == 0))
    {
        if (argc == 4 && strcasecmp(argv[2], "-param") == 0)
        {
            snprintf(file_info.param, MAX_PATH, "%s", argv[3]);
        }
        if (*file_info.param)
        {
            setenv("UPCHECK_MOZ_CHROME", file_info.param, 1);
        #if APP_DEBUG
            printf("We setenv UPCHECK_MOZ_CHROME = [%s]\n", file_info.param);
        #endif
        }
        if (curl_global_init(CURL_GLOBAL_DEFAULT) == 0)
        {
            if (strcasecmp(argv[1], "-a2quit") == 0)
            {
                ret = select_downloader(true, false);
            }
            else
            {
                ret = select_downloader(false, true);
            }
            curl_global_cleanup();
        }
        return ret;
    }
    if (argc == 4 && strncasecmp(argv[1], "-chrome-", 8) == 0)
    {
        ret = -1;
        if (strcasecmp(argv[1], "-chrome-check") == 0)
        {
            ret = chrome_check(argv[2], argv[3], false);
        }
        else if (strcasecmp(argv[1], "-chrome-uncheck") == 0)
        {
            ret = chrome_check(argv[2], argv[3], true);
        }
        else if (strcasecmp(argv[1], "-chrome-install") == 0)
        {
            ret = chrome_install(argv[2], argv[3], MOZ_CHROME);
        }
    #ifdef APP_DEBUG
        printf("chrome return %d\n", ret);
    #endif
        return ret;
    }
    if (argc == 4 && strncasecmp(argv[1], "-mousegestures-", 15) == 0)
    {
        ret = -1;
        if (strcasecmp(argv[1], "-mousegestures-uncheck") == 0)
        {
            ret = chrome_uncheck(argv[2], argv[3], MOZ_MOUSEGESTURES);
        }
        else if (strcasecmp(argv[1], "-mousegestures-install") == 0)
        {
            ret = chrome_install(argv[2], argv[3], MOZ_MOUSEGESTURES);
        }
    #ifdef APP_DEBUG
        printf("mousegestures return %d\n", ret);
    #endif
        return ret;
    }
    if (argc == 4 && strncasecmp(argv[1], "-multiline-", 11) == 0)
    {
        ret = -1;
        if (strcasecmp(argv[1], "-multiline-uncheck") == 0)
        {
            ret = chrome_uncheck(argv[2], argv[3], MOZ_MULTILINES);
        }
        else if (strcasecmp(argv[1], "-multiline-install") == 0)
        {
            ret = chrome_install(argv[2], argv[3], MOZ_MULTILINES);
        }
    #ifdef APP_DEBUG
        printf("multiline return %d\n", ret);
    #endif
        return ret;
    }
    if (argc == 4 && strncasecmp(argv[1], "-ucaddons-", 10) == 0)
    {
        ret = -1;
        if (strcasecmp(argv[1], "-ucaddons-uncheck") == 0)
        {
            ret = chrome_uncheck(argv[2], argv[3], MOZ_UCADDONS);
        }
        else if (strcasecmp(argv[1], "-ucaddons-install") == 0)
        {
            ret = chrome_install(argv[2], argv[3], MOZ_UCADDONS);
        }
    #ifdef APP_DEBUG
        printf("ucaddons return %d\n", ret);
    #endif
        return ret;
    }
    if (argc == 4 && strncasecmp(argv[1], "-integration-", 13) == 0)
    {
        ret = -1;
        if (strcasecmp(argv[1], "-integration-uncheck") == 0)
        {
            ret = chrome_uncheck(argv[2], argv[3], MOZ_DOWNLOADUPCHECK);
        }
        else if (strcasecmp(argv[1], "-integration-install") == 0)
        {
            ret = chrome_install(argv[2], argv[3], MOZ_DOWNLOADUPCHECK);
        }
    #ifdef APP_DEBUG
        printf("integration return %d\n", ret);
    #endif
        return ret;
    }
    if (argc == 4 && strncasecmp(argv[1], "-tabhover-", 10) == 0)
    {
        ret = -1;
        if (strcasecmp(argv[1], "-tabhover-uncheck") == 0)
        {
            ret = chrome_uncheck(argv[2], argv[3], MOZ_ONTABACTIVATE);
        }
        else if (strcasecmp(argv[1], "-tabhover-install") == 0)
        {
            ret = chrome_install(argv[2], argv[3], MOZ_ONTABACTIVATE);
        }
    #ifdef APP_DEBUG
        printf("tabhover return %d\n", ret);
    #endif
        return ret;
    }
    if (argc == 4 && strncasecmp(argv[1], "-tabrclick-", 11) == 0)
    {
        ret = -1;
        if (strcasecmp(argv[1], "-tabrclick-uncheck") == 0)
        {
            ret = chrome_uncheck(argv[2], argv[3], MOZ_ONTABRIGHTCLICK);
        }
        else if (strcasecmp(argv[1], "-tabrclick-install") == 0)
        {
            ret = chrome_install(argv[2], argv[3], MOZ_ONTABRIGHTCLICK);
        }
    #ifdef APP_DEBUG
        printf("tabrclick return %d\n", ret);
    #endif
        return ret;
    }
    if (argc == 4 && strncasecmp(argv[1], "-tabrswitch-", 11) == 0)
    {
        ret = -1;
        if (strcasecmp(argv[1], "-tabrswitch-uncheck") == 0)
        {
            ret = chrome_uncheck(argv[2], argv[3], MOZ_ONTABRIGHTCLICK);
        }
        else if (strcasecmp(argv[1], "-tabrswitch-install") == 0)
        {
            ret = chrome_install(argv[2], argv[3], MOZ_ONTABRIGHTSWITCH);
        }
    #ifdef APP_DEBUG
        printf("tabrswitch return %d\n", ret);
    #endif
        return ret;
    }
    if (argc == 4 && strcasecmp(argv[1], "-ubo-check") == 0)
    {
        return fn_ubo(argv[2], (uint32_t)atoi(argv[3]));
    }
    if (argc >= 5 && (strcasecmp(argv[1], "-lua") == 0 || strcasecmp(argv[1], "-msg") == 0))
    {
        if (strcasecmp(argv[1], "-lua") == 0)
        {
            if (enviroment_variables_set("UPCHECK_MOZ_PID", argv[2], VARIABLES_RESET) && argc - 3 < NAMES_LEN)
            {
                int i = 0;
                char *parg[NAMES_LEN] = {NULL};
                for (; i < argc - 3; ++i)
                {
                    parg[i] = argv[i + 3];
                }
                ret = lua_script_loader(parg, i);
            }
        }
        return ret;
    }
    if (argc > 1) // 初始化全局参数
    {
        memset(&file_info, 0, sizeof(file_info));
        if (!init_command_data(argc, (const char **)argv))
        {
            printf("init_command_data failed\n");
            return UPCKECK_DATA_ERR;
        }
    }
    do
    {
        dnld_params_t dt = {0};
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0)
        {
            *file_info.ini = '\0';
            *file_info.process = L'\0';
            ret = UPCHECK_CURL_ERR;
            printf("curl_global_init failed\n");
            break;
        }
        if (file_info.use_thunder > 0 && file_info.use_thunder != 0x4)
        {
            if (*file_info.param)
            {
                setenv("UPCHECK_MOZ_CHROME", file_info.param, 1);
            #if APP_DEBUG
                printf("SetEnv UPCHECK_MOZ_CHROME=[%s]\n", file_info.param);
            #endif
            }
            if (UPCHECK_OK == select_downloader(false, false))
            {
                break;
            }
            if (file_info.use_thunder != 999)
            {
                break;
            }
        }
        if (strlen(file_info.url) < 2) // 没有下载任务
        {
            ret = UPCHECK_URL_ERR;
            break;
        }
        if (!downloaded_lookup())
        {
            *file_info.ini = '\0';
            *file_info.process = L'\0';
            ret = UPCHECK_READY_ERR;
            printf("Is it already being downloaded?\n");
            break;
        }
        if ((ret = get_file_size(file_info.url, &dt)) != 0) // 获取远程文件大小
        {
            *file_info.ini = '\0';
            if (dt.ret != 307 && ret != 0x3)
            {
                delete_cookie_file();
                ret = UPCHECK_LENTH_ERR;  //or UPCHECK_404_ERR
                printf("get_file_size return false\n");
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
            printf("curl_task return false, dt.length = %zd\n", dt.length);
            break;
        }
        if (strlen(file_info.md5) > 1 && !md5_sum(true)) // 核对文件md5值
        {
            ret = UPCHECK_MD5_ERR;
            break;
        }
        if (file_info.extract && extract_tar_xz(file_info.names, NULL, 0, file_info.unzip_dir)) // 解压缩升级包
        {
            ret = UPCHECK_EXTRACT_ERR;
            break;
        }
        ret = UPCHECK_OK;
    } while (0);
    curl_global_cleanup();
    close_cookie_handle(ret != UPCHECK_READY_ERR);
    if (ret != UPCHECK_READY_ERR)
    {
        share_envent_close_url();
    }
    return ret;
}
