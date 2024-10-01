#ifndef _COOKIES_CODE_
#define _COOKIES_CODE_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int  dump_cookies(const wchar_t *sql_path);
extern int  parse_baidu_cookies(char *cookies, int len);
extern void clean_sql_logs(void);
extern bool init_sql_logs(const wchar_t *logs);
extern int  get_ranges(sql_node *node);
extern bool get_down_size(int64_t *psize);
extern bool thread_insert(const char*, int64_t, int64_t, int64_t, int64_t, uint32_t, uint32_t, int);
extern bool update_ranges(uint32_t thread, int64_t begin, int64_t size);
extern bool update_status(uint32_t thread, int status);

#ifdef __cplusplus
}
#endif

#endif
