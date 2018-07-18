#ifndef _PROGRESS_UI_H_
#define _PROGRESS_UI_H_

typedef struct _fn_show
{
  bool indeterminate;
  bool initstrings;
}fn_show;

#ifdef __cplusplus
extern "C" {
#endif

// Called on the main thread at startup
extern unsigned WINAPI show_progress(void *p);

extern bool WINAPI set_ui_strings(void);

// May be called from any thread
extern void WINAPI quit_progress();

// May be called from any thread: progress is a number between 0 and 100
extern void WINAPI update_progress(float progress);

#ifdef __cplusplus
}
#endif

#endif  // _PROGRESS_UI_H_
