#ifndef _DOWN_INTEGRATION_H_
#define _DOWN_INTEGRATION_H_

#ifdef __cplusplus
extern "C" {
#endif

int integration_check(const wchar_t *bin, const wchar_t *chrome, const bool uncheck);
int integration_install(const wchar_t *bin, const wchar_t *chrome);

#ifdef __cplusplus
}
#endif

#endif  // _DOWN_INTEGRATION_H_
