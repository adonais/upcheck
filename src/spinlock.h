#ifndef __SPIN_LOCK__
#define __SPIN_LOCK__

#include <stdbool.h>
#include <stdint.h>
#include <curl/curl.h>
#ifdef __GNUC__
#include <pthread.h>
#endif
#include <windows.h>
#include <errno.h>

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

#define MAX_MESSAGE 1024*4
#define BUFSIZE     1024*8
#define BUFF_MAX    0x2000000
#define MD5_LEN     64
#define NAMES_LEN   64
#define VALUE_LEN   128
#define COOKE_LEN   512
#define BUFF_LEN    1024
#define URL_LEN     1024*2
#define MD5_DIGEST_LENGTH 16

#if EUAPI_LINK
#define EUAPI_CERT CURLSSLOPT_NATIVE_CA
#else
#define EUAPI_CERT CURLSSLOPT_AUTO_CLIENT_CERT
#endif

#if defined(LOG_DEBUG)
#define printf logmsg
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    UPCHECK_INJECT_ERR = -12,
    UPCHECK_404_ERR = -11,
    UPCHECK_EXTRACT_ERR = -10,
    UPCHECK_MD5_ERR = -9,
    UPCHECK_TASK_ERR = -8,
    UPCHECK_LENTH_ERR = -7,
    UPCHECK_RESOLVER_ERR = -6,
    UPCHECK_INI_ERR = -5,
    UPCKECK_DATA_ERR = -4,
    UPCHECK_URL_ERR = -3,
    UPCHECK_CURL_ERR = -2,
    UPCKECK_API_ERR = -1,
    UPCHECK_OK = 0,
    UPCHECK_DONT_ERR = 1,
    UPCHECK_READY_ERR = 2
};

typedef int (*copy_file_ptr)(LPCWSTR filepath);

typedef struct _file_info_t
{
    HANDLE   handle;
    WCHAR    cookie_tmp[MAX_PATH+1];
    WCHAR    names[MAX_PATH+1];
    WCHAR    process[MAX_PATH+1];
    WCHAR    param[MAX_PATH+1];
    WCHAR    unzip_dir[MAX_PATH+1];
    WCHAR    del[MAX_PATH+1];
    HWND     remote_hwnd;
    void     *sql;
    uint32_t pid;
    uint64_t dt_local;
    int      thread_num;
    int      use_thunder;
    char     *pcook;
    char     remote_names[MAX_PATH+1];
    char     ini_uri[MAX_PATH+1];
    char     referer[MAX_PATH+1];
    char     cookiefile[MAX_PATH+1];
    char     md5[MD5_LEN+1];
    char     ini[MAX_PATH+1];
    char     url[URL_LEN+1];
    char     ini_proxy[MAX_PATH+1];
    char     ini_usewd[NAMES_LEN+1];
    char     etag[NAMES_LEN];
    bool     extract;
    bool     re_bind;
    bool     up;
    bool     ranges;
} file_info_t;

typedef struct _sql_node
{
    int64_t    startidx;
    int64_t    endidx;
    int64_t    szdown;
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
typedef void (*ptr_curl_easy_reset)(CURL *handle);

extern file_info_t file_info;

// for curl
extern ptr_curl_easy_reset euapi_curl_easy_reset;
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
extern void libcurl_set_ssl(CURL *curl);
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
extern bool find_local_str(char *result, int len);
extern bool  exec_ppv(LPCSTR wcmd, LPCSTR pcd, int flags);
extern bool  search_process(LPCWSTR names);
extern char* url_decode(const char *input);
extern wchar_t *u16_dec_path(const wchar_t *path);
extern WCHAR* init_file_strings(LPCWSTR names, size_t *psize);
extern WCHAR* get_process_path(WCHAR *path, const int len);
extern const uint32_t get_os_version(void);
extern char* str_replace(char *in, const size_t in_size, const char *pattern, const char *by);
extern char *check_memstr(char *full_data, int full_data_len, const char *substr);

extern HANDLE share_create(HANDLE handle, uint32_t dw_protect, size_t size, LPCTSTR name);
extern HANDLE share_open(uint32_t dw_access, LPCTSTR name);
extern LPVOID share_map(HANDLE hmap, size_t bytes, uint32_t dw_access);
extern void share_unmap(LPVOID memory);
extern void share_close(HANDLE handle);
extern bool enviroment_variables_set(LPCWSTR szname, LPCWSTR sz_newval, sys_flag dw_flag);

extern WCHAR *path_utf16_clone(const WCHAR *path);
extern WCHAR *path_utf8_utf16(const char *path);
extern BOOL move_file_wrapper(const WCHAR *srcfile, const WCHAR *dst, uint32_t flags);

extern HANDLE create_new(LPCWSTR wcmd, LPCWSTR param, const LPCWSTR pcd, int flags, DWORD *opid, const int attached);
extern LPWSTR wstr_replace(LPWSTR, size_t, LPCWSTR, LPCWSTR);
extern void erase_dir(LPCWSTR parent);
extern int do_file_copy(LPCWSTR parent, copy_file_ptr fnback, const bool recurs);
extern wchar_t *strpath_copy(wchar_t *s1, const wchar_t *s2);
extern const WCHAR *get_file_name(LPCWSTR path);
extern bool getw_cwd(LPWSTR lpstrName, DWORD wlen);
extern size_t get_first_line(char **lineptr, const WCHAR *path);
extern bool utf8_path_exist(char **pstr);
extern bool ini_path_init(void);
extern char *path_add_quotes(const char *path);

extern int find_user_local(void);
extern errno_t wp_strncat(char *dst, const char *src, size_t number);
extern errno_t wp_wcsncat(wchar_t *dst, const wchar_t *src, size_t number);

#ifdef __cplusplus
}
#endif

#endif
