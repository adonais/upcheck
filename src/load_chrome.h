#ifndef _LOAD_CHROME_H_
#define _LOAD_CHROME_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    MOZ_CHROME = 0,
    MOZ_MOUSEGESTURES,
    MOZ_UCADDONS,
    MOZ_DOWNLOADUPCHECK,
    MOZ_ONTABACTIVATE,
    MOZ_ONTABRIGHTCLICK
} mozscr;

int  chrome_uncheck(const wchar_t *bin, const wchar_t *profd, mozscr srcid);
int  chrome_check(const wchar_t *bin, const wchar_t *profd, const bool uncheck);
int  chrome_install(const wchar_t *bin, const wchar_t *profd, mozscr srcid);
bool chrome_faster(const char *ini, char **purl);

#ifdef __cplusplus
}
#endif

#endif  // _LOAD_CHROME_H_
