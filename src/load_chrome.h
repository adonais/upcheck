#ifndef _LOAD_CHROME_H_
#define _LOAD_CHROME_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    MOZ_CHROME = 0,
    MOZ_MOUSEGESTURES,
    MOZ_MULTILINES,
    MOZ_UCADDONS,
    MOZ_DOWNLOADUPCHECK,
    MOZ_ONTABACTIVATE,
    MOZ_ONTABRIGHTCLICK,
    MOZ_ONTABRIGHTSWITCH
} mozscr;

int  chrome_uncheck(const char *bin, const char *profd, mozscr srcid);
int  chrome_check(const char *bin, const char *chrome, const bool uncheck);
int  chrome_install(const char *bin, const char *chrome, mozscr srcid);
bool chrome_faster(const char *ini, char **purl);

#ifdef __cplusplus
}
#endif

#endif  // _LOAD_CHROME_H_
