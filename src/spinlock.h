#ifndef __SPIN_LOCK__
#define __SPIN_LOCK__

#include <stdbool.h>
#include <stdint.h>
#include <curl/curl.h>
#ifdef __GNUC__
#include <pthread.h>
#endif
#include <windows.h>

#ifdef __GNUC__
#define LOCK_MUTEXT pthread_mutex_t
#define INIT_LOCK(x) pthread_mutex_init(x, NULL)
#define DO_LOCK(x) pthread_mutex_lock(x)
#define DO_UNLOCK(x) pthread_mutex_unlock(x)
#define DESTROY_LOCK(x) pthread_mutex_destroy(x)
#else
#define LOCK_MUTEXT CRITICAL_SECTION
#define INIT_LOCK(x) InitializeCriticalSection(x)
#define DO_LOCK(x) EnterCriticalSection(x)
#define DO_UNLOCK(x) LeaveCriticalSection(x)
#define DESTROY_LOCK(x) DeleteCriticalSection(x)
#endif

#define MAX_MESSAGE 1024
#define BUFSIZE     1024*16
#define BUFF_MAX    1024*100
#define MD5_LEN     64
#define NAMES_LEN   64
#define VALUE_LEN   128
#define COOKE_LEN   512
#define URL_LEN     1024
#define MD5_DIGEST_LENGTH 16

#define SYS_MALLOC(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define SYS_FREE(x) (HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, (x)), (x = NULL))

#if EUAPI_LINK
#define EUAPI_CERT CURLSSLOPT_NATIVE_CA
#else
#define EUAPI_CERT CURLSSLOPT_AUTO_CLIENT_CERT
#endif

#ifdef __cplusplus
extern "C" {
#endif
typedef struct _file_info_t
{
    HANDLE   handle;
    HANDLE   cookie_handle;
    WCHAR    names[MAX_PATH+1];
    WCHAR    process[MAX_PATH+1];
    WCHAR    param[MAX_PATH+1];
    WCHAR    unzip_dir[MAX_PATH+1];
    WCHAR    del[VALUE_LEN+1];
    HWND     remote_hwnd;
    void     *sql;
    uint32_t pid;
    uint64_t dt_local;
    int      thread_num;
    char     remote_names[MAX_PATH+1];
    char     ini_uri[MAX_PATH+1];
    char     referer[VALUE_LEN+1];
    char     cookies[COOKE_LEN+1];
    char     md5[MD5_LEN+1];
    char     ini[MAX_PATH+1];
    char     url[URL_LEN+1];
    char     ini_proxy[MAX_PATH+1];
    char     ini_usewd[NAMES_LEN+1];
    bool     use_thunder;
    bool     extract;
    bool     re_bind;
    bool     up;
} file_info_t;

typedef struct _sql_node
{
    int64_t    startidx;
    int64_t    endidx;
    uint32_t   thread;
} sql_node;

typedef enum _sys_flag
{
    VARIABLES_NULL,
    VARIABLES_APPEND,
    VARIABLES_RESET
} sys_flag;

typedef const char* (*ptr_curl_easy_strerror)(CURLcode);
typedef CURL* (*ptr_curl_easy_init)(void);
typedef CURLcode (*ptr_curl_global_init)(long flags);
typedef CURLSH* (*ptr_curl_share_init)(void);
typedef CURLSHcode (*ptr_curl_share_setopt)(CURLSH *share, CURLSHoption option, ...);
typedef CURLSHcode (*ptr_curl_share_cleanup)(CURLSH *share);
typedef CURLcode (*ptr_curl_easy_setopt)(CURL*, CURLoption, ...);
typedef CURLcode (*ptr_curl_easy_perform)(CURL*);
typedef void (*ptr_curl_easy_cleanup)(CURL*);
typedef void (*ptr_curl_global_cleanup)(void);
typedef void (*ptr_curl_slist_free_all)(struct curl_slist *);
typedef struct curl_slist* (*ptr_curl_slist_append)(struct curl_slist *, const char *);
typedef CURLcode (*ptr_curl_easy_getinfo)(CURL *data, CURLINFO info, ...);

extern file_info_t file_info;

// for curl
extern ptr_curl_easy_strerror euapi_curl_easy_strerror;
extern ptr_curl_easy_setopt euapi_curl_easy_setopt;
extern ptr_curl_easy_perform euapi_curl_easy_perform;
extern ptr_curl_easy_getinfo euapi_curl_easy_getinfo;
extern ptr_curl_slist_append euapi_curl_slist_append;
extern ptr_curl_slist_free_all euapi_curl_slist_free_all;
extern ptr_curl_share_init euapi_curl_share_init;
extern ptr_curl_share_setopt euapi_curl_share_setopt;
extern ptr_curl_share_cleanup euapi_curl_share_cleanup;
extern ptr_curl_global_init euapi_curl_global_init;
extern ptr_curl_easy_init euapi_curl_easy_init;
extern ptr_curl_global_cleanup euapi_curl_global_cleanup;
extern ptr_curl_easy_cleanup euapi_curl_easy_cleanup;
extern CURLcode libcurl_init(long flags);
extern void libcurl_destory(void);

extern void libcurl_set_proxy(CURL *curl);
extern int  get_cpu_works(void);
extern bool get_file_md5(LPCWSTR path, char* md5_str);
extern bool path_combine(LPWSTR lpfile, int len);
extern void wchr_replace(LPWSTR path);
extern bool create_dir(LPCWSTR dir);
extern bool exists_dir(LPCWSTR path);
extern void __cdecl logmsg(const char *format, ...);
extern void init_logs(void);
extern void enter_spinlock(void);
extern void leave_spinlock(void);
extern bool init_file_strings(LPCWSTR names, char *out_path);
extern bool find_local_str(char *result, int len);
extern bool merge_file(LPCWSTR path1,LPCWSTR path2,LPCWSTR name);
extern bool get_files_lenth(LPCWSTR path, int64_t *psize);
extern bool  exec_ppv(LPCSTR wcmd, LPCSTR pcd, int flags);
extern bool  get_name_self(LPWSTR lpstrName, DWORD wlen);
extern bool  search_process(LPCWSTR names);
extern char* url_decode(const char *input);
extern uint64_t ini_read_uint64(const char *sec, const char *key, const char *ini);
extern WCHAR* get_process_path(WCHAR *path, const int len);
extern const uint32_t get_os_version(void);

extern HANDLE share_create(HANDLE handle, uint32_t dw_protect, size_t size, LPCTSTR name);
extern HANDLE share_open(uint32_t dw_access, LPCTSTR name);
extern LPVOID share_map(HANDLE hmap, size_t bytes, uint32_t dw_access);
extern void share_unmap(LPVOID memory);
extern void share_close(HANDLE handle);
extern bool enviroment_variables_set(LPCWSTR szname, LPCWSTR sz_newval, sys_flag dw_flag);

#ifdef __cplusplus
}
#endif

#endif
