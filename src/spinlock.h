#ifndef __SPIN_LOCK__
#define __SPIN_LOCK__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>

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
#define PID_LEN 8
#define PROC_PATH_LEN 512

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#if defined(__linux__)
#define _atoi64(val) strtoll(val, NULL, 10)
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

typedef int (*copy_file_ptr)(const char *filepath);

typedef struct _file_info_t
{
    char     cookie_tmp[MAX_PATH+1];
    char     names[MAX_PATH+1];
    char     process[MAX_PATH+1];
    char     param[MAX_PATH+1];
    char     unzip_dir[MAX_PATH+1];
    char     del[MAX_PATH+1];
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

extern file_info_t file_info;

#ifdef LOG_DEBUG
extern void init_logs(void);
extern void __cdecl logmsg(const char * format, ...);
#endif
extern void enter_spinlock(void);
extern void leave_spinlock(void);
extern void sleep_ms(int milliseconds);
extern bool exists_dir(const char *path);
extern bool exists_file(const char *path);
extern bool get_file_md5(const char *filename, char *md5_str);
extern int  delete_file(const char *path);
extern int create_dir(const char *path, mode_t mode);
extern int create_file(const char *path, mode_t mode);
extern int wp_strncat(char *dst, const char *src, size_t number);
extern int exec_ppv(const char *command, const char *command_list, int flags);
extern size_t get_first_line(char **lineptr, const char *path);
extern char *strcasestr(const char *haystack, const char *needle);
extern char *check_memstr(char *full_data, int full_data_len, const char *substr);
extern void delete_cookie_file(void);
extern void close_cookie_handle(bool mdel);
extern bool duplicate_process_run(void);
extern char *get_process_path(char *path, size_t len);
extern char *url_decode(const char *input);
extern char *path_clone(char **path);
extern char *path_utf8_clone(const char *path);
extern char *path_add_quotes(const char *path);
extern char *path_undo_quotes(char *path);
extern char *init_file_strings(const char *names, size_t *psize);
extern bool init_portable_path(void);
extern bool strip_file_spec(char *path);
extern bool which_path_exist(const char *name, char *pout, size_t out_len);
extern bool enviroment_variables_set(const char *szname, const char *sz_newval, sys_flag dw_flag);

#ifdef __cplusplus
}
#endif

#endif
