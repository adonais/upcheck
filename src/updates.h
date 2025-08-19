#ifndef _UPDATES_CODE_
#define _UPDATES_CODE_

#ifdef __cplusplus
extern "C" {
#endif

extern LPWSTR wstr_replace(LPWSTR, size_t, LPCWSTR, LPCWSTR);
extern void erase_dir(LPCWSTR parent);
extern int update_thread(void *p);

#ifdef __cplusplus
}
#endif

#endif
