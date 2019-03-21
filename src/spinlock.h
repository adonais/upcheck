#ifndef __SPIN_LOCK__
#define __SPIN_LOCK__

#include <stdbool.h>
#include <stdint.h>
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
#define MD5_LEN     32
#define NAMES_LEN   64
#define VALUE_LEN   128
#define COOKE_LEN   512
#define URL_LEN     1024
#define MD5_DIGEST_LENGTH 16

#if defined(NDEBUG)
#define printf(...) ((void)0)
#elif defined(DEBUG_LOG)
#define printf logmsg
#endif

#define SYS_MALLOC(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define SYS_FREE(x) (HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, (x)), (x = NULL))

#ifdef __cplusplus
extern "C" {   
#endif
typedef struct _file_info_t
{
    HANDLE handle;
    HANDLE cookie_handle;
    WCHAR  names[MAX_PATH+1];
    WCHAR  process[MAX_PATH+1];
    WCHAR  unzip_dir[MAX_PATH+1];
    WCHAR  del[VALUE_LEN+1];
    WCHAR  ini[VALUE_LEN+1];
    char   referer[VALUE_LEN+1];
    char   remote_names[MAX_PATH+1];
    char   cookies[COOKE_LEN+1];
    char   md5[MD5_LEN+1];
    char   url[URL_LEN+1];
    int    thread_num;
    void   *sql;
    bool   use_thunder;
    bool   extract;
    bool   re_bind;
    DWORD  pid;
    bool   up;
} file_info_t;

typedef struct _sql_node
{
    int64_t    startidx;
    int64_t    endidx;
    uint32_t   thread;
} sql_node;

extern int __argc;
extern WCHAR **__wargv;
extern int  WINAPI get_cpu_works(void);
extern int  read(int fd, void *buffer, unsigned int count);
extern bool WINAPI get_file_md5(LPCWSTR path, char* md5_str);
extern bool WINAPI path_combine(LPWSTR lpfile, int len);
extern void WINAPI wchr_replace(LPWSTR path);
extern bool WINAPI create_dir(LPCWSTR dir);
extern bool WINAPI exists_dir(LPCWSTR path);
extern void __cdecl logmsg(const char *format, ...);
extern void WINAPI init_logs(void);
extern void WINAPI enter_spinlock(void);
extern void WINAPI leave_spinLock(void);
extern bool WINAPI read_appkey(LPCWSTR, LPCWSTR, LPWSTR, DWORD, LPCWSTR);
extern uint64_t WINAPI read_appint(LPCWSTR cat,LPCWSTR name, LPCWSTR ini);
extern bool WINAPI init_file_strings(LPCWSTR names, WCHAR *out_path);
extern bool WINAPI find_local_str(char *result, int len);
extern bool WINAPI merge_file(LPCWSTR path1,LPCWSTR path2,LPCWSTR name);
extern bool WINAPI get_files_lenth(LPCWSTR path, int64_t *psize);
extern wchar_t* WINAPI utf8_to_utf16(const char *filename);
extern char* WINAPI utf16_to_utf8(const wchar_t *filename);

#ifdef __cplusplus
}
#endif

#endif
