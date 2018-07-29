#ifndef _COOKIES_CODE_
#define _COOKIES_CODE_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int  __stdcall dump_cookies(const wchar_t *sql_path);
extern int  __stdcall parse_baidu_cookies(char *cookies, int len);
extern void __stdcall clean_sql_logs(void);
extern bool __stdcall init_sql_logs(const wchar_t *logs);
extern bool __stdcall check_status(int64_t *psize);
extern int  __stdcall get_ranges(sql_node *node);
extern bool __stdcall get_down_size(int64_t *psize);
extern bool __stdcall thread_insert(const char*, int64_t, int64_t, int64_t, int64_t, uint32_t, uint32_t, int);
extern bool __stdcall update_ranges(uint32_t thread, int64_t begin, int64_t size);
extern bool __stdcall update_status(uint32_t thread, int status);

#ifdef __cplusplus
}
#endif

#endif
