#ifndef __NET_H__
#define __NET_H__

#include <curl/curl.h>
#include "spinlock.h"

#define MAX_THREAD 32
#define FILE_LEN 138
#define UINT_LEN 66
#define URL_ITERATIONS 11235

#ifdef _MSC_VER
#define strcasestr  StrStrIA
#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#define fseek _fseeki64
#endif

#define ABORT(...) (fprintf(stderr, __VA_ARGS__), exit(-1))
#define VERIFY(x) (void)((x) || (ABORT("failed assert(%s): %s:%d\n", #x, __FILE__, __LINE__), 0))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _curl_node
{
    FILE *fp;
    int64_t startidx;
    int64_t endidx;
    CURLSH *share;
    uint32_t tid;
    const char *url;
    bool error;
} curl_node;

typedef struct _dnld_params_t
{
    char remote_fname[MAX_PATH+1];
} dnld_params_t;

#ifdef __cplusplus
}
#endif

#endif
