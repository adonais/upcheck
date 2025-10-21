#ifndef _MANGER_H_
#define _MANGER_H_

#define SELECT_AUTO 999

#ifdef __cplusplus
extern "C" {
#endif

extern int select_downloader(const bool quit);
extern void close_cookie_handle(void);
extern void delete_temp_cookie(void);

#ifdef __cplusplus
}
#endif

#endif
