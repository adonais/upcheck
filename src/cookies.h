#ifndef _COOKIES_CODE_
#define _COOKIES_CODE_

#ifdef __cplusplus
extern "C" {
#endif

extern int __stdcall dump_cookies(const wchar_t *sql_path);
extern int __stdcall parse_baidu_cookies(char *cookies, int len);

#ifdef __cplusplus
}
#endif

#endif
