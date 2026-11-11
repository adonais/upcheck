#ifndef _XML_CODE_
#define _XML_CODE_

#include <curl/curl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _xml_buffer
{
    int cur;
    char *str;
}xml_buffer;

extern void init_curl_ssl(CURL *curl);
extern int xml_query_ice(xml_buffer *pbuf, const bool upgrade);
extern size_t write_data_callback(char *ptr, size_t size, size_t nmemb, void *stream);
extern int init_process(const char *url, curl_write_callback write_data, void *userdata);

#ifdef __cplusplus
}
#endif

#endif
