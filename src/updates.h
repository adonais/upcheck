#ifndef _UPDATES_CODE_
#define _UPDATES_CODE_

#ifdef __cplusplus
extern "C" {
#endif

extern LPWSTR wstr_replace(LPWSTR, size_t, LPCWSTR, LPCWSTR);
extern int update_thread(void *p);
extern bool unknown_builds(void);

#ifdef __cplusplus
}
#endif

#endif
