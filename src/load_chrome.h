#ifndef _LOAD_CHROME_H_
#define _LOAD_CHROME_H_

#ifdef __cplusplus
extern "C" {
#endif

int chrome_check(const wchar_t *bin, const wchar_t *chrome, const bool uncheck);
int chrome_install(const wchar_t *bin, const wchar_t *chrome);

#ifdef __cplusplus
}
#endif

#endif  // _LOAD_CHROME_H_
