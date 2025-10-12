#ifndef _XML_CODE_
#define _XML_CODE_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _xml_buffer
{
    int cur;
    char *str;
}xml_buffer;

extern size_t write_data_callback(void *ptr, size_t size, size_t nmemb, void *stream);
extern int init_process(const char *url, curl_write_callback write_data, void *userdata);
extern int ini_query_ice(xml_buffer *pbuf, const bool upgrade);
extern int init_resolver(void);

#ifdef __cplusplus
}
#endif

#endif
