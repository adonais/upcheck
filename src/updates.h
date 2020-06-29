#ifndef _UPDATES_CODE_
#define _UPDATES_CODE_

#ifdef __cplusplus
extern "C" {
#endif

extern LPWSTR WINAPI wstr_replace(LPWSTR, size_t, LPCWSTR, LPCWSTR);
extern int WINAPI update_thread(void *p);
extern bool WINAPI unknown_builds(void);

#ifdef __cplusplus
}
#endif

#endif
