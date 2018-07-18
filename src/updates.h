#ifndef _UPDATES_CODE_
#define _UPDATES_CODE_

#ifdef __cplusplus
extern "C" {
#endif

extern LPWSTR WINAPI wstr_replace(LPWSTR, size_t, LPCWSTR, LPCWSTR);
extern unsigned WINAPI update_thread(void *p);

#ifdef __cplusplus
}
#endif

#endif
