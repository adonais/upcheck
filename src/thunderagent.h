#ifndef _THUNDER_AGENT_
#define _THUNDER_AGENT_

#if defined(__cplusplus)
extern "C" {
#endif

extern int thunder_lookup(void);
extern int thunder_download(char *b_url, char *b_refer, char *b_cookies);

#if defined(__cplusplus)
}
#endif

#endif  /* _THUNDER_AGENT_ */
