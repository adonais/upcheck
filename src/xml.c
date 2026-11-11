#include <elf.h>
#include "ini_parser.h"
#include "spinlock.h"
#include "xml.h"

#define INFO_LEN 32

size_t
write_data_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
    xml_buffer *pbuf = (xml_buffer *)stream;
    size_t written = size * nmemb;
    pbuf->str = realloc(pbuf->str, (size_t)pbuf->cur + written);
    memcpy(pbuf->str + pbuf->cur, ptr, written);
    pbuf->cur += (int)written;
    return (size_t)written;
}

void
init_curl_ssl(CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_AUTO_CLIENT_CERT | CURLSSLOPT_NO_REVOKE);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
}

int
init_process(const char *url, curl_write_callback write_data, void *userdata)
{
    CURLcode res = 1;
    CURL *curl_handle = curl_easy_init();
    if (curl_handle)
    {
        curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        curl_easy_setopt(curl_handle, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, userdata);
        curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 3L);
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        init_curl_ssl(curl_handle);
        curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 45L);
        curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 180L);
    #if APP_DEBUG
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0L);
    #endif
        res = curl_easy_perform(curl_handle);
        if (res != CURLE_OK)
        {
            printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl_handle);
    }
    return res;
}

int
xml_query_ice(xml_buffer *pbuf, const bool upgrade)
{

    int res = -1;
    uint64_t dt_remote = 0;
    uint64_t dt_locale = 0;
    char info[INFO_LEN + 1] = {0};
    char *url = NULL;
    char *c_md5 = NULL;
    char *pini = NULL;
    ini_cache ini_handler = NULL;
    int bits = sizeof(void *);
    if (bits == 8)
    {
        printf("is_64bits\n");
        strncpy(info, "linux64", INFO_LEN);
    }
    else if (bits == 4)
    {
        printf("is_32bits\n");
        strncpy(info, "linux32", INFO_LEN);
    }
    else
    {
        printf("unknown platform\n");
        return res;
    }
    do
    {
        if (!(ini_handler = iniparser_create_cache(pbuf->str, pbuf->cur, false)))
        {
            printf("iniparser_create_cache return false\n");
            break;
        }
        if ((pini = init_file_strings("application.ini", NULL)) == NULL)
        {
            printf("init_file_strings application.ini return false\n");
            break;
        }
        if ((dt_locale = ini_read_uint64("App", "BuildID", pini, true)) > 0)
        {
            dt_remote = inicache_read_uint64("updates", info, &ini_handler);
        }
        if (dt_locale >= dt_remote)
        {
            printf("dt_locale(%lu) >= dt_remote(%lu), do not update\n", dt_locale, dt_remote);
            res = 1;
            break;
        }
        if (upgrade)
        {
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
            printf("dt_locale = %lu, dt_remote = %lu, c_md5 = %s, app_url = %s\n", dt_locale, dt_remote, c_md5, url);
        }
        res = 0;
    }while(0);
    ini_safe_free(c_md5);
    ini_safe_free(url);
    ini_safe_free(pini);
    iniparser_destroy_cache(&ini_handler);
    return res;
}
