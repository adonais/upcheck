/*
** FFI C library loader.
** Copyright (C) 2005-2026 Mike Pall. See Copyright Notice in luajit.h
*/
#define _CRT_RAND_S

#include "lj_obj.h"

#if LJ_HASFFI

#include "lj_gc.h"
#include "lj_err.h"
#include "lj_tab.h"
#include "lj_str.h"
#include "lj_udata.h"
#include "lj_ctype.h"
#include "lj_cconv.h"
#include "lj_cdata.h"
#include "lj_clib.h"
#include "lj_strfmt.h"

/* -- OS-specific functions ----------------------------------------------- */

#if LJ_TARGET_DLOPEN

#include <dlfcn.h>
#include <stdio.h>

#if defined(RTLD_DEFAULT) && !defined(NO_RTLD_DEFAULT)
#define CLIB_DEFHANDLE	RTLD_DEFAULT
#elif LJ_TARGET_OSX || LJ_TARGET_BSD
#define CLIB_DEFHANDLE	((void *)(intptr_t)-2)
#else
#define CLIB_DEFHANDLE	NULL
#endif

LJ_NORET LJ_NOINLINE static void clib_error_(lua_State *L)
{
  lj_err_callermsg(L, dlerror());
}

#define clib_error(L, fmt, name)	clib_error_(L)

#if LJ_TARGET_CYGWIN
#define CLIB_SOPREFIX	"cyg"
#else
#define CLIB_SOPREFIX	"lib"
#endif

#if LJ_TARGET_OSX
#define CLIB_SOEXT	"%s.dylib"
#elif LJ_TARGET_CYGWIN
#define CLIB_SOEXT	"%s.dll"
#else
#define CLIB_SOEXT	"%s.so"
#endif

static const char *clib_extname(lua_State *L, const char *name)
{
  if (!strchr(name, '/')
#if LJ_TARGET_CYGWIN
      && !strchr(name, '\\')
#endif
     ) {
    if (!strchr(name, '.')) {
      name = lj_strfmt_pushf(L, CLIB_SOEXT, name);
      L->top--;
#if LJ_TARGET_CYGWIN
    } else {
      return name;
#endif
    }
    if (!(name[0] == CLIB_SOPREFIX[0] && name[1] == CLIB_SOPREFIX[1] &&
	  name[2] == CLIB_SOPREFIX[2])) {
      name = lj_strfmt_pushf(L, CLIB_SOPREFIX "%s", name);
      L->top--;
    }
  }
  return name;
}

/* Check for a recognized ld script line. */
static const char *clib_check_lds(lua_State *L, const char *buf)
{
  const char *p, *e;
  if ((!strncmp(buf, "GROUP", 5) || !strncmp(buf, "INPUT", 5)) &&
      (p = strchr(buf, '('))) {
    while (*++p == ' ') ;
    for (e = p; *e && *e != ' ' && *e != ')'; e++) ;
    return strdata(lj_str_new(L, p, e-p));
  }
  return NULL;
}

/* Quick and dirty solution to resolve shared library name from ld script. */
static const char *clib_resolve_lds(lua_State *L, const char *name)
{
  wchar_t *wname = NULL;
  FILE *fp = NULL;
  const char *p = NULL;
#ifdef _WIN32
  wname = lj_utf8_utf16(name, NULL);
  fp = wname ? _wfopen(wname, L"r") : NULL;
#else
  fp = fopen(name, "r");
#endif
  if (fp) {
    char buf[256];
    if (fgets(buf, sizeof(buf), fp)) {
      if (!strncmp(buf, "/* GNU ld script", 16)) {  /* ld script magic? */
        while (fgets(buf, sizeof(buf), fp)) {  /* Check all lines. */
          p = clib_check_lds(L, buf);
          if (p) break;
        }
      } else {  /* Otherwise check only the first line. */
        p = clib_check_lds(L, buf);
      }
    }
    fclose(fp);
  }
  if (wname)
  {
    free(wname);
  }
  return p;
}

static void *clib_loadlib(lua_State *L, const char *name, int global)
{
  void *h = dlopen(clib_extname(L, name),
		   RTLD_LAZY | (global?RTLD_GLOBAL:RTLD_LOCAL));
  if (!h) {
    const char *e, *err = dlerror();
    if (err && *err == '/' && (e = strchr(err, ':')) &&
	(name = clib_resolve_lds(L, strdata(lj_str_new(L, err, e-err))))) {
      h = dlopen(name, RTLD_LAZY | (global?RTLD_GLOBAL:RTLD_LOCAL));
      if (h) return h;
      err = dlerror();
    }
    if (!err) err = "dlopen failed";
    lj_err_callermsg(L, err);
  }
  return h;
}

static void clib_unloadlib(CLibrary *cl)
{
  if (cl->handle && cl->handle != CLIB_DEFHANDLE)
    dlclose(cl->handle);
}

static void *clib_getsym(CLibrary *cl, const char *name)
{
  void *p = dlsym(cl->handle, name);
  return p;
}

#elif LJ_TARGET_WINDOWS

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS	4
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT	2
BOOL WINAPI GetModuleHandleExA(DWORD, LPCSTR, HMODULE*);
#endif

#define CLIB_DEFHANDLE	((void *)-1)

/* Default libraries. */
enum {
  CLIB_HANDLE_EXE,
#if !LJ_TARGET_UWP
  CLIB_HANDLE_DLL,
  CLIB_HANDLE_CRT,
  CLIB_HANDLE_KERNEL32,
  CLIB_HANDLE_USER32,
  CLIB_HANDLE_GDI32,
#endif
  CLIB_HANDLE_MAX
};

static void *clib_def_handle[CLIB_HANDLE_MAX];

LJ_NORET LJ_NOINLINE static void clib_error(lua_State *L, const char *fmt,
					    const char *name)
{
  DWORD err = GetLastError();
#if LJ_TARGET_XBOXONE
  wchar_t wbuf[128];
  char buf[128*2];
  if (!FormatMessageW(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_SYSTEM,
		      NULL, err, 0, wbuf, sizeof(wbuf)/sizeof(wchar_t), NULL) ||
      !WideCharToMultiByte(CP_ACP, 0, wbuf, 128, buf, 128*2, NULL, NULL))
#else
  char buf[128];
  if (!FormatMessageA(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_SYSTEM,
		      NULL, err, 0, buf, sizeof(buf), NULL))
#endif
    buf[0] = '\0';
  lj_err_callermsg(L, lj_strfmt_pushf(L, fmt, name, buf));
}

static int clib_needext(const char *s)
{
  while (*s) {
    if (*s == '/' || *s == '\\' || *s == '.') return 0;
    s++;
  }
  return 1;
}

static const char *clib_extname(lua_State *L, const char *name)
{
  if (clib_needext(name)) {
    name = lj_strfmt_pushf(L, "%s.dll", name);
    L->top--;
  }
  return name;
}

static void *clib_loadlib(lua_State *L, const char *name, int global)
{
  DWORD oldwerr = GetLastError();
  void *h = LJ_WIN_LOADLIBA(clib_extname(L, name));
  if (!h) clib_error(L, "cannot load module " LUA_QS ": %s", name);
  SetLastError(oldwerr);
  UNUSED(global);
  return h;
}

static void clib_unloadlib(CLibrary *cl)
{
  if (cl->handle == CLIB_DEFHANDLE) {
#if !LJ_TARGET_UWP
    MSize i;
    for (i = CLIB_HANDLE_KERNEL32; i < CLIB_HANDLE_MAX; i++) {
      void *h = clib_def_handle[i];
      if (h) {
	clib_def_handle[i] = NULL;
	FreeLibrary((HINSTANCE)h);
      }
    }
#endif
  } else if (cl->handle) {
    FreeLibrary((HINSTANCE)cl->handle);
  }
}

#if LJ_TARGET_UWP
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#endif

#ifdef CRT_STATIC
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include <malloc.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utime.h>
#include <share.h>
#include <math.h>
#include <float.h>
#include <sys/timeb.h>
#include <time.h>
#include <conio.h>
#include <direct.h>
#include <process.h>
#include <locale.h>
#include <iso646.h>
#include <wchar.h>
#include <uchar.h>
#include <complex.h>
#include <fenv.h>
#include <setjmp.h>
#include <inttypes.h>
#include <mbstring.h>
#include <mbctype.h>
#include <corecrt.h>

#define CRT_MAP_CASE(func_) if ((!p) && strcmp((#func_), (name)) == 0) ((p) = (func_))
#define CRT_MAP_INIT()                                             \
    do {                                                           \
        CRT_MAP_CASE(abort);                                       \
        CRT_MAP_CASE(abs);                                         \
        CRT_MAP_CASE(_abs64);                                      \
        CRT_MAP_CASE(access);                                      \
        CRT_MAP_CASE(_access);                                     \
        CRT_MAP_CASE(_access_s);                                   \
        CRT_MAP_CASE(acos);                                        \
        CRT_MAP_CASE(acosf);                                       \
        CRT_MAP_CASE(acosh);                                       \
        CRT_MAP_CASE(acoshf);                                      \
        CRT_MAP_CASE(acoshl);                                      \
        CRT_MAP_CASE(acosl);                                       \
        CRT_MAP_CASE(_aligned_free);                               \
        CRT_MAP_CASE(_aligned_malloc);                             \
        CRT_MAP_CASE(_aligned_msize);                              \
        CRT_MAP_CASE(_aligned_offset_malloc);                      \
        CRT_MAP_CASE(_aligned_offset_realloc);                     \
        CRT_MAP_CASE(_aligned_offset_recalloc);                    \
        CRT_MAP_CASE(_aligned_realloc);                            \
        CRT_MAP_CASE(_aligned_recalloc);                           \
        CRT_MAP_CASE(asctime);                                     \
        CRT_MAP_CASE(asctime_s);                                   \
        CRT_MAP_CASE(asin);                                        \
        CRT_MAP_CASE(asinf);                                       \
        CRT_MAP_CASE(asinh);                                       \
        CRT_MAP_CASE(asinhf);                                      \
        CRT_MAP_CASE(asinhl);                                      \
        CRT_MAP_CASE(asinl);                                       \
        CRT_MAP_CASE(atan);                                        \
        CRT_MAP_CASE(atan2);                                       \
        CRT_MAP_CASE(atan2f);                                      \
        CRT_MAP_CASE(atan2l);                                      \
        CRT_MAP_CASE(atanf);                                       \
        CRT_MAP_CASE(atanh);                                       \
        CRT_MAP_CASE(atanhf);                                      \
        CRT_MAP_CASE(atanhl);                                      \
        CRT_MAP_CASE(atanl);                                       \
        CRT_MAP_CASE(atexit);                                      \
        CRT_MAP_CASE(_atodbl);                                     \
        CRT_MAP_CASE(_atodbl_l);                                   \
        CRT_MAP_CASE(atof);                                        \
        CRT_MAP_CASE(_atof_l);                                     \
        CRT_MAP_CASE(_atoflt);                                     \
        CRT_MAP_CASE(_atoflt_l);                                   \
        CRT_MAP_CASE(atoi);                                        \
        CRT_MAP_CASE(_atoi_l);                                     \
        CRT_MAP_CASE(_atoi64);                                     \
        CRT_MAP_CASE(_atoi64_l);                                   \
        CRT_MAP_CASE(atol);                                        \
        CRT_MAP_CASE(_atol_l);                                     \
        CRT_MAP_CASE(_atoldbl);                                    \
        CRT_MAP_CASE(_atoldbl_l);                                  \
        CRT_MAP_CASE(atoll);                                       \
        CRT_MAP_CASE(_atoll_l);                                    \
        CRT_MAP_CASE(_beginthread);                                \
        CRT_MAP_CASE(_beginthreadex);                              \
        CRT_MAP_CASE(bsearch);                                     \
        CRT_MAP_CASE(bsearch_s);                                   \
        CRT_MAP_CASE(btowc);                                       \
        CRT_MAP_CASE(_byteswap_uint64);                            \
        CRT_MAP_CASE(_byteswap_ulong);                             \
        CRT_MAP_CASE(_byteswap_ushort);                            \
        CRT_MAP_CASE(_c_exit);                                     \
        CRT_MAP_CASE(c16rtomb);                                    \
        CRT_MAP_CASE(c32rtomb);                                    \
        CRT_MAP_CASE(_cabs);                                       \
        CRT_MAP_CASE(cabs);                                        \
        CRT_MAP_CASE(cabsf);                                       \
        CRT_MAP_CASE(cabsl);                                       \
        CRT_MAP_CASE(cacos);                                       \
        CRT_MAP_CASE(cacosf);                                      \
        CRT_MAP_CASE(cacosh);                                      \
        CRT_MAP_CASE(cacoshf);                                     \
        CRT_MAP_CASE(cacoshl);                                     \
        CRT_MAP_CASE(cacosl);                                      \
        CRT_MAP_CASE(_callnewh);                                   \
        CRT_MAP_CASE(calloc);                                      \
        CRT_MAP_CASE(carg);                                        \
        CRT_MAP_CASE(cargf);                                       \
        CRT_MAP_CASE(cargl);                                       \
        CRT_MAP_CASE(casin);                                       \
        CRT_MAP_CASE(casinf);                                      \
        CRT_MAP_CASE(casinh);                                      \
        CRT_MAP_CASE(casinhf);                                     \
        CRT_MAP_CASE(casinhl);                                     \
        CRT_MAP_CASE(casinl);                                      \
        CRT_MAP_CASE(catan);                                       \
        CRT_MAP_CASE(catanf);                                      \
        CRT_MAP_CASE(catanh);                                      \
        CRT_MAP_CASE(catanhf);                                     \
        CRT_MAP_CASE(catanhl);                                     \
        CRT_MAP_CASE(catanl);                                      \
        CRT_MAP_CASE(cbrt);                                        \
        CRT_MAP_CASE(cbrtf);                                       \
        CRT_MAP_CASE(cbrtl);                                       \
        CRT_MAP_CASE(ccos);                                        \
        CRT_MAP_CASE(ccosf);                                       \
        CRT_MAP_CASE(ccosh);                                       \
        CRT_MAP_CASE(ccoshf);                                      \
        CRT_MAP_CASE(ccoshl);                                      \
        CRT_MAP_CASE(ccosl);                                       \
        CRT_MAP_CASE(ceil);                                        \
        CRT_MAP_CASE(ceilf);                                       \
        CRT_MAP_CASE(ceill);                                       \
        CRT_MAP_CASE(_cexit);                                      \
        CRT_MAP_CASE(cexp);                                        \
        CRT_MAP_CASE(cexpf);                                       \
        CRT_MAP_CASE(cexpl);                                       \
        CRT_MAP_CASE(cgets);                                       \
        CRT_MAP_CASE(_cgets_s);                                    \
        CRT_MAP_CASE(_cgetws_s);                                   \
        CRT_MAP_CASE(chdir);                                       \
        CRT_MAP_CASE(_chdir);                                      \
        CRT_MAP_CASE(_chdrive);                                    \
        CRT_MAP_CASE(_chgsign);                                    \
        CRT_MAP_CASE(_chgsignf);                                   \
        CRT_MAP_CASE(_chgsignl);                                   \
        CRT_MAP_CASE(chmod);                                       \
        CRT_MAP_CASE(_chmod);                                      \
        CRT_MAP_CASE(chsize);                                      \
        CRT_MAP_CASE(_chsize);                                     \
        CRT_MAP_CASE(_chsize_s);                                   \
        CRT_MAP_CASE(cimag);                                       \
        CRT_MAP_CASE(cimagf);                                      \
        CRT_MAP_CASE(cimagl);                                      \
        CRT_MAP_CASE(_clear87);                                    \
        CRT_MAP_CASE(clearerr);                                    \
        CRT_MAP_CASE(clearerr_s);                                  \
        CRT_MAP_CASE(_clearfp);                                    \
        CRT_MAP_CASE(clock);                                       \
        CRT_MAP_CASE(clog);                                        \
        CRT_MAP_CASE(clog10);                                      \
        CRT_MAP_CASE(clog10f);                                     \
        CRT_MAP_CASE(clog10l);                                     \
        CRT_MAP_CASE(clogf);                                       \
        CRT_MAP_CASE(clogl);                                       \
        CRT_MAP_CASE(close);                                       \
        CRT_MAP_CASE(_close);                                      \
        CRT_MAP_CASE(_commit);                                     \
        CRT_MAP_CASE(_configthreadlocale);                         \
        CRT_MAP_CASE(conj);                                        \
        CRT_MAP_CASE(conjf);                                       \
        CRT_MAP_CASE(conjl);                                       \
        CRT_MAP_CASE(_controlfp);                                  \
        CRT_MAP_CASE(_controlfp_s);                                \
        CRT_MAP_CASE(copysign);                                    \
        CRT_MAP_CASE(_copysign);                                   \
        CRT_MAP_CASE(copysignf);                                   \
        CRT_MAP_CASE(_copysignf);                                  \
        CRT_MAP_CASE(copysignl);                                   \
        CRT_MAP_CASE(_copysignl);                                  \
        CRT_MAP_CASE(cos);                                         \
        CRT_MAP_CASE(cosf);                                        \
        CRT_MAP_CASE(cosh);                                        \
        CRT_MAP_CASE(coshf);                                       \
        CRT_MAP_CASE(coshl);                                       \
        CRT_MAP_CASE(cosl);                                        \
        CRT_MAP_CASE(cpow);                                        \
        CRT_MAP_CASE(cpowf);                                       \
        CRT_MAP_CASE(cpowl);                                       \
        CRT_MAP_CASE(cprintf);                                     \
        CRT_MAP_CASE(_cprintf);                                    \
        CRT_MAP_CASE(_cprintf_l);                                  \
        CRT_MAP_CASE(_cprintf_p);                                  \
        CRT_MAP_CASE(_cprintf_p_l);                                \
        CRT_MAP_CASE(_cprintf_s);                                  \
        CRT_MAP_CASE(_cprintf_s_l);                                \
        CRT_MAP_CASE(cproj);                                       \
        CRT_MAP_CASE(cprojf);                                      \
        CRT_MAP_CASE(cprojl);                                      \
        CRT_MAP_CASE(cputs);                                       \
        CRT_MAP_CASE(_cputs);                                      \
        CRT_MAP_CASE(_cputws);                                     \
        CRT_MAP_CASE(creal);                                       \
        CRT_MAP_CASE(crealf);                                      \
        CRT_MAP_CASE(creall);                                      \
        CRT_MAP_CASE(creat);                                       \
        CRT_MAP_CASE(_creat);                                      \
        CRT_MAP_CASE(_create_locale);                              \
        CRT_MAP_CASE(cscanf);                                      \
        CRT_MAP_CASE(_cscanf);                                     \
        CRT_MAP_CASE(_cscanf_l);                                   \
        CRT_MAP_CASE(_cscanf_s);                                   \
        CRT_MAP_CASE(_cscanf_s_l);                                 \
        CRT_MAP_CASE(csin);                                        \
        CRT_MAP_CASE(csinf);                                       \
        CRT_MAP_CASE(csinh);                                       \
        CRT_MAP_CASE(csinhf);                                      \
        CRT_MAP_CASE(csinhl);                                      \
        CRT_MAP_CASE(csinl);                                       \
        CRT_MAP_CASE(csqrt);                                       \
        CRT_MAP_CASE(csqrtf);                                      \
        CRT_MAP_CASE(csqrtl);                                      \
        CRT_MAP_CASE(ctan);                                        \
        CRT_MAP_CASE(ctanf);                                       \
        CRT_MAP_CASE(ctanh);                                       \
        CRT_MAP_CASE(ctanhf);                                      \
        CRT_MAP_CASE(ctanhl);                                      \
        CRT_MAP_CASE(ctanl);                                       \
        CRT_MAP_CASE(ctime);                                       \
        CRT_MAP_CASE(ctime_s);                                     \
        CRT_MAP_CASE(_ctime32);                                    \
        CRT_MAP_CASE(_ctime32_s);                                  \
        CRT_MAP_CASE(_ctime64);                                    \
        CRT_MAP_CASE(_ctime64_s);                                  \
        CRT_MAP_CASE(_cwait);                                      \
        CRT_MAP_CASE(cwait);                                       \
        CRT_MAP_CASE(_cwprintf);                                   \
        CRT_MAP_CASE(_cwprintf_l);                                 \
        CRT_MAP_CASE(_cwprintf_p);                                 \
        CRT_MAP_CASE(_cwprintf_p_l);                               \
        CRT_MAP_CASE(_cwprintf_s);                                 \
        CRT_MAP_CASE(_cwprintf_s_l);                               \
        CRT_MAP_CASE(_cwscanf);                                    \
        CRT_MAP_CASE(_cwscanf_l);                                  \
        CRT_MAP_CASE(_cwscanf_s);                                  \
        CRT_MAP_CASE(_cwscanf_s_l);                                \
        CRT_MAP_CASE(difftime);                                    \
        CRT_MAP_CASE(_difftime32);                                 \
        CRT_MAP_CASE(_difftime64);                                 \
        CRT_MAP_CASE(div);                                         \
        CRT_MAP_CASE(_dup);                                        \
        CRT_MAP_CASE(dup);                                         \
        CRT_MAP_CASE(_dup2);                                       \
        CRT_MAP_CASE(dup2);                                        \
        CRT_MAP_CASE(_dupenv_s);                                   \
        CRT_MAP_CASE(_ecvt);                                       \
        CRT_MAP_CASE(ecvt);                                        \
        CRT_MAP_CASE(_ecvt_s);                                     \
        CRT_MAP_CASE(_endthread);                                  \
        CRT_MAP_CASE(_endthreadex);                                \
        CRT_MAP_CASE(eof);                                         \
        CRT_MAP_CASE(_eof);                                        \
        CRT_MAP_CASE(erf);                                         \
        CRT_MAP_CASE(erfc);                                        \
        CRT_MAP_CASE(erfcf);                                       \
        CRT_MAP_CASE(erfcl);                                       \
        CRT_MAP_CASE(erff);                                        \
        CRT_MAP_CASE(erfl);                                        \
        CRT_MAP_CASE(execl);                                       \
        CRT_MAP_CASE(_execl);                                      \
        CRT_MAP_CASE(execle);                                      \
        CRT_MAP_CASE(_execle);                                     \
        CRT_MAP_CASE(execlp);                                      \
        CRT_MAP_CASE(_execlp);                                     \
        CRT_MAP_CASE(execlpe);                                     \
        CRT_MAP_CASE(_execlpe);                                    \
        CRT_MAP_CASE(execv);                                       \
        CRT_MAP_CASE(_execv);                                      \
        CRT_MAP_CASE(execve);                                      \
        CRT_MAP_CASE(_execve);                                     \
        CRT_MAP_CASE(execvp);                                      \
        CRT_MAP_CASE(_execvp);                                     \
        CRT_MAP_CASE(execvpe);                                     \
        CRT_MAP_CASE(_execvpe);                                    \
        CRT_MAP_CASE(exit);                                        \
        CRT_MAP_CASE(_Exit);                                       \
        CRT_MAP_CASE(_exit);                                       \
        CRT_MAP_CASE(exp);                                         \
        CRT_MAP_CASE(exp2);                                        \
        CRT_MAP_CASE(exp2f);                                       \
        CRT_MAP_CASE(exp2l);                                       \
        CRT_MAP_CASE(_expand);                                     \
        CRT_MAP_CASE(expf);                                        \
        CRT_MAP_CASE(expm1);                                       \
        CRT_MAP_CASE(expm1f);                                      \
        CRT_MAP_CASE(expm1l);                                      \
        CRT_MAP_CASE(fabs);                                        \
        CRT_MAP_CASE(fabsf);                                       \
        CRT_MAP_CASE(fclose);                                      \
        CRT_MAP_CASE(_fclose_nolock);                              \
        CRT_MAP_CASE(_fcloseall);                                  \
        CRT_MAP_CASE(fcloseall);                                   \
        CRT_MAP_CASE(_fcvt);                                       \
        CRT_MAP_CASE(fcvt);                                        \
        CRT_MAP_CASE(_fcvt_s);                                     \
        CRT_MAP_CASE(fdim);                                        \
        CRT_MAP_CASE(fdimf);                                       \
        CRT_MAP_CASE(fdiml);                                       \
        CRT_MAP_CASE(fdopen);                                      \
        CRT_MAP_CASE(_fdopen);                                     \
        CRT_MAP_CASE(fegetenv);                                    \
        CRT_MAP_CASE(fegetexceptflag);                             \
        CRT_MAP_CASE(fegetround);                                  \
        CRT_MAP_CASE(feholdexcept);                                \
        CRT_MAP_CASE(feof);                                        \
        CRT_MAP_CASE(feraiseexcept);                               \
        CRT_MAP_CASE(ferror);                                      \
        CRT_MAP_CASE(fesetenv);                                    \
        CRT_MAP_CASE(fesetexceptflag);                             \
        CRT_MAP_CASE(fesetround);                                  \
        CRT_MAP_CASE(fetestexcept);                                \
        CRT_MAP_CASE(feupdateenv);                                 \
        CRT_MAP_CASE(fflush);                                      \
        CRT_MAP_CASE(_fflush_nolock);                              \
        CRT_MAP_CASE(fgetc);                                       \
        CRT_MAP_CASE(_fgetc_nolock);                               \
        CRT_MAP_CASE(fgetchar);                                    \
        CRT_MAP_CASE(_fgetchar);                                   \
        CRT_MAP_CASE(fgetpos);                                     \
        CRT_MAP_CASE(fgets);                                       \
        CRT_MAP_CASE(fgetwc);                                      \
        CRT_MAP_CASE(_fgetwc_nolock);                              \
        CRT_MAP_CASE(_fgetwchar);                                  \
        CRT_MAP_CASE(fgetws);                                      \
        CRT_MAP_CASE(filelength);                                  \
        CRT_MAP_CASE(_filelength);                                 \
        CRT_MAP_CASE(_filelengthi64);                              \
        CRT_MAP_CASE(fileno);                                      \
        CRT_MAP_CASE(_fileno);                                     \
        CRT_MAP_CASE(_findclose);                                  \
        CRT_MAP_CASE(_findfirst);                                  \
        CRT_MAP_CASE(_findfirst32);                                \
        CRT_MAP_CASE(_findfirst32i64);                             \
        CRT_MAP_CASE(_findfirst64);                                \
        CRT_MAP_CASE(_findfirst64i32);                             \
        CRT_MAP_CASE(_findfirsti64);                               \
        CRT_MAP_CASE(_findnext);                                   \
        CRT_MAP_CASE(_findnext32);                                 \
        CRT_MAP_CASE(_findnext32i64);                              \
        CRT_MAP_CASE(_findnext64);                                 \
        CRT_MAP_CASE(_findnext64i32);                              \
        CRT_MAP_CASE(_findnexti64);                                \
        CRT_MAP_CASE(_finite);                                     \
        CRT_MAP_CASE(floor);                                       \
        CRT_MAP_CASE(floorf);                                      \
        CRT_MAP_CASE(floorl);                                      \
        CRT_MAP_CASE(flushall);                                    \
        CRT_MAP_CASE(_flushall);                                   \
        CRT_MAP_CASE(fma);                                         \
        CRT_MAP_CASE(fmaf);                                        \
        CRT_MAP_CASE(fmal);                                        \
        CRT_MAP_CASE(fmax);                                        \
        CRT_MAP_CASE(fmaxf);                                       \
        CRT_MAP_CASE(fmaxl);                                       \
        CRT_MAP_CASE(fmin);                                        \
        CRT_MAP_CASE(fminf);                                       \
        CRT_MAP_CASE(fminl);                                       \
        CRT_MAP_CASE(fmod);                                        \
        CRT_MAP_CASE(fmodf);                                       \
        CRT_MAP_CASE(fopen);                                       \
        CRT_MAP_CASE(fopen_s);                                     \
        CRT_MAP_CASE(_fpclass);                                    \
        CRT_MAP_CASE(_fpreset);                                    \
        CRT_MAP_CASE(fprintf);                                     \
        CRT_MAP_CASE(_fprintf_l);                                  \
        CRT_MAP_CASE(_fprintf_p);                                  \
        CRT_MAP_CASE(_fprintf_p_l);                                \
        CRT_MAP_CASE(fprintf_s);                                   \
        CRT_MAP_CASE(_fprintf_s_l);                                \
        CRT_MAP_CASE(fputc);                                       \
        CRT_MAP_CASE(_fputc_nolock);                               \
        CRT_MAP_CASE(fputchar);                                    \
        CRT_MAP_CASE(_fputchar);                                   \
        CRT_MAP_CASE(fputs);                                       \
        CRT_MAP_CASE(fputwc);                                      \
        CRT_MAP_CASE(_fputwc_nolock);                              \
        CRT_MAP_CASE(_fputwchar);                                  \
        CRT_MAP_CASE(fputws);                                      \
        CRT_MAP_CASE(fread);                                       \
        CRT_MAP_CASE(_fread_nolock);                               \
        CRT_MAP_CASE(_fread_nolock_s);                             \
        CRT_MAP_CASE(fread_s);                                     \
        CRT_MAP_CASE(free);                                        \
        CRT_MAP_CASE(_free_locale);                                \
        CRT_MAP_CASE(_freea);                                      \
        CRT_MAP_CASE(freopen);                                     \
        CRT_MAP_CASE(freopen_s);                                   \
        CRT_MAP_CASE(frexp);                                       \
        CRT_MAP_CASE(fscanf);                                      \
        CRT_MAP_CASE(_fscanf_l);                                   \
        CRT_MAP_CASE(fscanf_s);                                    \
        CRT_MAP_CASE(_fscanf_s_l);                                 \
        CRT_MAP_CASE(fseek);                                       \
        CRT_MAP_CASE(_fseek_nolock);                               \
        CRT_MAP_CASE(_fseeki64);                                   \
        CRT_MAP_CASE(_fseeki64_nolock);                            \
        CRT_MAP_CASE(fsetpos);                                     \
        CRT_MAP_CASE(_fsopen);                                     \
        CRT_MAP_CASE(_fstat);                                      \
        CRT_MAP_CASE(_fstat32);                                    \
        CRT_MAP_CASE(_fstat32i64);                                 \
        CRT_MAP_CASE(_fstat64);                                    \
        CRT_MAP_CASE(_fstat64i32);                                 \
        CRT_MAP_CASE(_fstati64);                                   \
        CRT_MAP_CASE(ftell);                                       \
        CRT_MAP_CASE(_ftell_nolock);                               \
        CRT_MAP_CASE(_ftelli64);                                   \
        CRT_MAP_CASE(_ftelli64_nolock);                            \
        CRT_MAP_CASE(_ftime);                                      \
        CRT_MAP_CASE(_ftime_s);                                    \
        CRT_MAP_CASE(_ftime32);                                    \
        CRT_MAP_CASE(_ftime32_s);                                  \
        CRT_MAP_CASE(_ftime64);                                    \
        CRT_MAP_CASE(_ftime64_s);                                  \
        CRT_MAP_CASE(_fullpath);                                   \
        CRT_MAP_CASE(_futime);                                     \
        CRT_MAP_CASE(_futime32);                                   \
        CRT_MAP_CASE(_futime64);                                   \
        CRT_MAP_CASE(fwide);                                       \
        CRT_MAP_CASE(fwprintf);                                    \
        CRT_MAP_CASE(_fwprintf_l);                                 \
        CRT_MAP_CASE(_fwprintf_p);                                 \
        CRT_MAP_CASE(_fwprintf_p_l);                               \
        CRT_MAP_CASE(fwprintf_s);                                  \
        CRT_MAP_CASE(_fwprintf_s_l);                               \
        CRT_MAP_CASE(fwrite);                                      \
        CRT_MAP_CASE(_fwrite_nolock);                              \
        CRT_MAP_CASE(fwscanf);                                     \
        CRT_MAP_CASE(_fwscanf_l);                                  \
        CRT_MAP_CASE(fwscanf_s);                                   \
        CRT_MAP_CASE(_fwscanf_s_l);                                \
        CRT_MAP_CASE(gcvt);                                        \
        CRT_MAP_CASE(_gcvt);                                       \
        CRT_MAP_CASE(_gcvt_s);                                     \
        CRT_MAP_CASE(_get_current_locale);                         \
        CRT_MAP_CASE(_get_daylight);                               \
        CRT_MAP_CASE(_get_doserrno);                               \
        CRT_MAP_CASE(_get_dstbias);                                \
        CRT_MAP_CASE(_get_errno);                                  \
        CRT_MAP_CASE(_get_fmode);                                  \
        CRT_MAP_CASE(_get_heap_handle);                            \
        CRT_MAP_CASE(_get_invalid_parameter_handler);              \
        CRT_MAP_CASE(_get_osfhandle);                              \
        CRT_MAP_CASE(_get_pgmptr);                                 \
        CRT_MAP_CASE(_get_printf_count_output);                    \
        CRT_MAP_CASE(_get_thread_local_invalid_parameter_handler); \
        CRT_MAP_CASE(_get_timezone);                               \
        CRT_MAP_CASE(_get_tzname);                                 \
        CRT_MAP_CASE(_get_wpgmptr);                                \
        CRT_MAP_CASE(getc);                                        \
        CRT_MAP_CASE(_getc_nolock);                                \
        CRT_MAP_CASE(getch);                                       \
        CRT_MAP_CASE(_getch);                                      \
        CRT_MAP_CASE(_getch_nolock);                               \
        CRT_MAP_CASE(getchar);                                     \
        CRT_MAP_CASE(getche);                                      \
        CRT_MAP_CASE(_getche);                                     \
        CRT_MAP_CASE(_getche_nolock);                              \
        CRT_MAP_CASE(getcwd);                                      \
        CRT_MAP_CASE(_getcwd);                                     \
        CRT_MAP_CASE(_getdcwd);                                    \
        CRT_MAP_CASE(_getdcwd_nolock);                             \
        CRT_MAP_CASE(_getdiskfree);                                \
        CRT_MAP_CASE(_getdrive);                                   \
        CRT_MAP_CASE(_getdrives);                                  \
        CRT_MAP_CASE(getenv);                                      \
        CRT_MAP_CASE(getenv_s);                                    \
        CRT_MAP_CASE(_getmaxstdio);                                \
        CRT_MAP_CASE(_getmbcp);                                    \
        CRT_MAP_CASE(_getpid);                                     \
        CRT_MAP_CASE(getpid);                                      \
        CRT_MAP_CASE(gets_s);                                      \
        CRT_MAP_CASE(_getw);                                       \
        CRT_MAP_CASE(getw);                                        \
        CRT_MAP_CASE(getwc);                                       \
        CRT_MAP_CASE(_getwc_nolock);                               \
        CRT_MAP_CASE(_getwch);                                     \
        CRT_MAP_CASE(_getwch_nolock);                              \
        CRT_MAP_CASE(getwchar);                                    \
        CRT_MAP_CASE(_getwche);                                    \
        CRT_MAP_CASE(_getwche_nolock);                             \
        CRT_MAP_CASE(_getws_s);                                    \
        CRT_MAP_CASE(gmtime);                                      \
        CRT_MAP_CASE(gmtime_s);                                    \
        CRT_MAP_CASE(_gmtime32);                                   \
        CRT_MAP_CASE(_gmtime32_s);                                 \
        CRT_MAP_CASE(_gmtime64);                                   \
        CRT_MAP_CASE(_gmtime64_s);                                 \
        CRT_MAP_CASE(_heapchk);                                    \
        CRT_MAP_CASE(_heapmin);                                    \
        CRT_MAP_CASE(_heapwalk);                                   \
        CRT_MAP_CASE(hypot);                                       \
        CRT_MAP_CASE(_hypot);                                      \
        CRT_MAP_CASE(hypotf);                                      \
        CRT_MAP_CASE(_hypotf);                                     \
        CRT_MAP_CASE(hypotl);                                      \
        CRT_MAP_CASE(_hypotl);                                     \
        CRT_MAP_CASE(_i64toa);                                     \
        CRT_MAP_CASE(_i64toa_s);                                   \
        CRT_MAP_CASE(_i64tow);                                     \
        CRT_MAP_CASE(_i64tow_s);                                   \
        CRT_MAP_CASE(ilogb);                                       \
        CRT_MAP_CASE(ilogbf);                                      \
        CRT_MAP_CASE(ilogbl);                                      \
        CRT_MAP_CASE(imaxabs);                                     \
        CRT_MAP_CASE(imaxdiv);                                     \
        CRT_MAP_CASE(_initterm);                                   \
        CRT_MAP_CASE(_initterm_e);                                 \
        CRT_MAP_CASE(_invalid_parameter_noinfo);                   \
        CRT_MAP_CASE(_invalid_parameter_noinfo_noreturn);          \
        CRT_MAP_CASE(_invoke_watson);                              \
        CRT_MAP_CASE(isalnum);                                     \
        CRT_MAP_CASE(_isalnum_l);                                  \
        CRT_MAP_CASE(isalpha);                                     \
        CRT_MAP_CASE(_isalpha_l);                                  \
        CRT_MAP_CASE(isascii);                                     \
        CRT_MAP_CASE(__isascii);                                   \
        CRT_MAP_CASE(_isatty);                                     \
        CRT_MAP_CASE(isatty);                                      \
        CRT_MAP_CASE(isblank);                                     \
        CRT_MAP_CASE(_isblank_l);                                  \
        CRT_MAP_CASE(iscntrl);                                     \
        CRT_MAP_CASE(_iscntrl_l);                                  \
        CRT_MAP_CASE(__iscsym);                                    \
        CRT_MAP_CASE(iscsym);                                      \
        CRT_MAP_CASE(__iscsymf);                                   \
        CRT_MAP_CASE(iscsymf);                                     \
        CRT_MAP_CASE(_isctype);                                    \
        CRT_MAP_CASE(_isctype_l);                                  \
        CRT_MAP_CASE(isdigit);                                     \
        CRT_MAP_CASE(_isdigit_l);                                  \
        CRT_MAP_CASE(isgraph);                                     \
        CRT_MAP_CASE(_isgraph_l);                                  \
        CRT_MAP_CASE(isleadbyte);                                  \
        CRT_MAP_CASE(_isleadbyte_l);                               \
        CRT_MAP_CASE(islower);                                     \
        CRT_MAP_CASE(_islower_l);                                  \
        CRT_MAP_CASE(_ismbbalnum);                                 \
        CRT_MAP_CASE(_ismbbalnum_l);                               \
        CRT_MAP_CASE(_ismbbalpha);                                 \
        CRT_MAP_CASE(_ismbbalpha_l);                               \
        CRT_MAP_CASE(_ismbbblank);                                 \
        CRT_MAP_CASE(_ismbbblank_l);                               \
        CRT_MAP_CASE(_ismbbgraph);                                 \
        CRT_MAP_CASE(_ismbbgraph_l);                               \
        CRT_MAP_CASE(_ismbbkalnum);                                \
        CRT_MAP_CASE(_ismbbkalnum_l);                              \
        CRT_MAP_CASE(_ismbbkana);                                  \
        CRT_MAP_CASE(_ismbbkana_l);                                \
        CRT_MAP_CASE(_ismbbkprint);                                \
        CRT_MAP_CASE(_ismbbkprint_l);                              \
        CRT_MAP_CASE(_ismbbkpunct);                                \
        CRT_MAP_CASE(_ismbbkpunct_l);                              \
        CRT_MAP_CASE(_ismbblead);                                  \
        CRT_MAP_CASE(_ismbblead_l);                                \
        CRT_MAP_CASE(_ismbbprint);                                 \
        CRT_MAP_CASE(_ismbbprint_l);                               \
        CRT_MAP_CASE(_ismbbpunct);                                 \
        CRT_MAP_CASE(_ismbbpunct_l);                               \
        CRT_MAP_CASE(_ismbbtrail);                                 \
        CRT_MAP_CASE(_ismbbtrail_l);                               \
        CRT_MAP_CASE(_ismbcalnum);                                 \
        CRT_MAP_CASE(_ismbcalnum_l);                               \
        CRT_MAP_CASE(_ismbcalpha);                                 \
        CRT_MAP_CASE(_ismbcalpha_l);                               \
        CRT_MAP_CASE(_ismbcblank);                                 \
        CRT_MAP_CASE(_ismbcblank_l);                               \
        CRT_MAP_CASE(_ismbcdigit);                                 \
        CRT_MAP_CASE(_ismbcdigit_l);                               \
        CRT_MAP_CASE(_ismbcgraph);                                 \
        CRT_MAP_CASE(_ismbcgraph_l);                               \
        CRT_MAP_CASE(_ismbchira);                                  \
        CRT_MAP_CASE(_ismbchira_l);                                \
        CRT_MAP_CASE(_ismbckata);                                  \
        CRT_MAP_CASE(_ismbckata_l);                                \
        CRT_MAP_CASE(_ismbcl0);                                    \
        CRT_MAP_CASE(_ismbcl0_l);                                  \
        CRT_MAP_CASE(_ismbcl1);                                    \
        CRT_MAP_CASE(_ismbcl1_l);                                  \
        CRT_MAP_CASE(_ismbcl2);                                    \
        CRT_MAP_CASE(_ismbcl2_l);                                  \
        CRT_MAP_CASE(_ismbclegal);                                 \
        CRT_MAP_CASE(_ismbclegal_l);                               \
        CRT_MAP_CASE(_ismbclower);                                 \
        CRT_MAP_CASE(_ismbclower_l);                               \
        CRT_MAP_CASE(_ismbcprint);                                 \
        CRT_MAP_CASE(_ismbcprint_l);                               \
        CRT_MAP_CASE(_ismbcpunct);                                 \
        CRT_MAP_CASE(_ismbcpunct_l);                               \
        CRT_MAP_CASE(_ismbcspace);                                 \
        CRT_MAP_CASE(_ismbcspace_l);                               \
        CRT_MAP_CASE(_ismbcsymbol);                                \
        CRT_MAP_CASE(_ismbcsymbol_l);                              \
        CRT_MAP_CASE(_ismbcupper);                                 \
        CRT_MAP_CASE(_ismbcupper_l);                               \
        CRT_MAP_CASE(_ismbslead);                                  \
        CRT_MAP_CASE(_ismbslead_l);                                \
        CRT_MAP_CASE(_ismbstrail);                                 \
        CRT_MAP_CASE(_ismbstrail_l);                               \
        CRT_MAP_CASE(_isnan);                                      \
        CRT_MAP_CASE(isprint);                                     \
        CRT_MAP_CASE(_isprint_l);                                  \
        CRT_MAP_CASE(ispunct);                                     \
        CRT_MAP_CASE(_ispunct_l);                                  \
        CRT_MAP_CASE(isspace);                                     \
        CRT_MAP_CASE(_isspace_l);                                  \
        CRT_MAP_CASE(isupper);                                     \
        CRT_MAP_CASE(_isupper_l);                                  \
        CRT_MAP_CASE(iswalnum);                                    \
        CRT_MAP_CASE(_iswalnum_l);                                 \
        CRT_MAP_CASE(iswalpha);                                    \
        CRT_MAP_CASE(_iswalpha_l);                                 \
        CRT_MAP_CASE(iswascii);                                    \
        CRT_MAP_CASE(iswblank);                                    \
        CRT_MAP_CASE(_iswblank_l);                                 \
        CRT_MAP_CASE(iswcntrl);                                    \
        CRT_MAP_CASE(_iswcntrl_l);                                 \
        CRT_MAP_CASE(__iswcsym);                                   \
        CRT_MAP_CASE(_iswcsym_l);                                  \
        CRT_MAP_CASE(__iswcsymf);                                  \
        CRT_MAP_CASE(_iswcsymf_l);                                 \
        CRT_MAP_CASE(iswctype);                                    \
        CRT_MAP_CASE(_iswctype_l);                                 \
        CRT_MAP_CASE(iswdigit);                                    \
        CRT_MAP_CASE(_iswdigit_l);                                 \
        CRT_MAP_CASE(iswgraph);                                    \
        CRT_MAP_CASE(_iswgraph_l);                                 \
        CRT_MAP_CASE(iswlower);                                    \
        CRT_MAP_CASE(_iswlower_l);                                 \
        CRT_MAP_CASE(iswprint);                                    \
        CRT_MAP_CASE(_iswprint_l);                                 \
        CRT_MAP_CASE(iswpunct);                                    \
        CRT_MAP_CASE(_iswpunct_l);                                 \
        CRT_MAP_CASE(iswspace);                                    \
        CRT_MAP_CASE(_iswspace_l);                                 \
        CRT_MAP_CASE(iswupper);                                    \
        CRT_MAP_CASE(_iswupper_l);                                 \
        CRT_MAP_CASE(iswxdigit);                                   \
        CRT_MAP_CASE(_iswxdigit_l);                                \
        CRT_MAP_CASE(isxdigit);                                    \
        CRT_MAP_CASE(_isxdigit_l);                                 \
        CRT_MAP_CASE(itoa);                                        \
        CRT_MAP_CASE(_itoa);                                       \
        CRT_MAP_CASE(_itoa_s);                                     \
        CRT_MAP_CASE(_itow);                                       \
        CRT_MAP_CASE(_itow_s);                                     \
        CRT_MAP_CASE(_j0);                                         \
        CRT_MAP_CASE(j0);                                          \
        CRT_MAP_CASE(_j1);                                         \
        CRT_MAP_CASE(j1);                                          \
        CRT_MAP_CASE(_jn);                                         \
        CRT_MAP_CASE(jn);                                          \
        CRT_MAP_CASE(_kbhit);                                      \
        CRT_MAP_CASE(kbhit);                                       \
        CRT_MAP_CASE(labs);                                        \
        CRT_MAP_CASE(ldexp);                                       \
        CRT_MAP_CASE(ldiv);                                        \
        CRT_MAP_CASE(_lfind);                                      \
        CRT_MAP_CASE(lfind);                                       \
        CRT_MAP_CASE(_lfind_s);                                    \
        CRT_MAP_CASE(lgamma);                                      \
        CRT_MAP_CASE(lgammaf);                                     \
        CRT_MAP_CASE(lgammal);                                     \
        CRT_MAP_CASE(llabs);                                       \
        CRT_MAP_CASE(lldiv);                                       \
        CRT_MAP_CASE(llrint);                                      \
        CRT_MAP_CASE(llrintf);                                     \
        CRT_MAP_CASE(llrintl);                                     \
        CRT_MAP_CASE(llround);                                     \
        CRT_MAP_CASE(llroundf);                                    \
        CRT_MAP_CASE(llroundl);                                    \
        CRT_MAP_CASE(localeconv);                                  \
        CRT_MAP_CASE(localtime);                                   \
        CRT_MAP_CASE(localtime_s);                                 \
        CRT_MAP_CASE(_localtime32);                                \
        CRT_MAP_CASE(_localtime32_s);                              \
        CRT_MAP_CASE(_localtime64);                                \
        CRT_MAP_CASE(_localtime64_s);                              \
        CRT_MAP_CASE(_lock_file);                                  \
        CRT_MAP_CASE(locking);                                     \
        CRT_MAP_CASE(_locking);                                    \
        CRT_MAP_CASE(log);                                         \
        CRT_MAP_CASE(log10);                                       \
        CRT_MAP_CASE(log10f);                                      \
        CRT_MAP_CASE(log1p);                                       \
        CRT_MAP_CASE(log1pf);                                      \
        CRT_MAP_CASE(log1pl);                                      \
        CRT_MAP_CASE(log2);                                        \
        CRT_MAP_CASE(log2f);                                       \
        CRT_MAP_CASE(log2l);                                       \
        CRT_MAP_CASE(logb);                                        \
        CRT_MAP_CASE(_logb);                                       \
        CRT_MAP_CASE(logbf);                                       \
        CRT_MAP_CASE(logbl);                                       \
        CRT_MAP_CASE(logf);                                        \
        CRT_MAP_CASE(longjmp);                                     \
        CRT_MAP_CASE(lrint);                                       \
        CRT_MAP_CASE(lrintf);                                      \
        CRT_MAP_CASE(lrintl);                                      \
        CRT_MAP_CASE(lround);                                      \
        CRT_MAP_CASE(lroundf);                                     \
        CRT_MAP_CASE(lroundl);                                     \
        CRT_MAP_CASE(_lsearch);                                    \
        CRT_MAP_CASE(lsearch);                                     \
        CRT_MAP_CASE(_lsearch_s);                                  \
        CRT_MAP_CASE(lseek);                                       \
        CRT_MAP_CASE(_lseek);                                      \
        CRT_MAP_CASE(_lseeki64);                                   \
        CRT_MAP_CASE(ltoa);                                        \
        CRT_MAP_CASE(_ltoa);                                       \
        CRT_MAP_CASE(_ltoa_s);                                     \
        CRT_MAP_CASE(_ltow);                                       \
        CRT_MAP_CASE(_ltow_s);                                     \
        CRT_MAP_CASE(_makepath);                                   \
        CRT_MAP_CASE(_makepath_s);                                 \
        CRT_MAP_CASE(malloc);                                      \
        CRT_MAP_CASE(_matherr);                                    \
        CRT_MAP_CASE(_mbbtombc);                                   \
        CRT_MAP_CASE(_mbbtombc_l);                                 \
        CRT_MAP_CASE(_mbbtype);                                    \
        CRT_MAP_CASE(_mbbtype_l);                                  \
        CRT_MAP_CASE(_mbccpy);                                     \
        CRT_MAP_CASE(_mbccpy_l);                                   \
        CRT_MAP_CASE(_mbccpy_s);                                   \
        CRT_MAP_CASE(_mbccpy_s_l);                                 \
        CRT_MAP_CASE(_mbcjistojms);                                \
        CRT_MAP_CASE(_mbcjistojms_l);                              \
        CRT_MAP_CASE(_mbcjmstojis);                                \
        CRT_MAP_CASE(_mbcjmstojis_l);                              \
        CRT_MAP_CASE(_mbclen);                                     \
        CRT_MAP_CASE(_mbclen_l);                                   \
        CRT_MAP_CASE(_mbctohira);                                  \
        CRT_MAP_CASE(_mbctohira_l);                                \
        CRT_MAP_CASE(_mbctokata);                                  \
        CRT_MAP_CASE(_mbctokata_l);                                \
        CRT_MAP_CASE(_mbctolower);                                 \
        CRT_MAP_CASE(_mbctolower_l);                               \
        CRT_MAP_CASE(_mbctombb);                                   \
        CRT_MAP_CASE(_mbctombb_l);                                 \
        CRT_MAP_CASE(_mbctoupper);                                 \
        CRT_MAP_CASE(_mbctoupper_l);                               \
        CRT_MAP_CASE(mblen);                                       \
        CRT_MAP_CASE(_mblen_l);                                    \
        CRT_MAP_CASE(mbrlen);                                      \
        CRT_MAP_CASE(mbrtoc16);                                    \
        CRT_MAP_CASE(mbrtoc32);                                    \
        CRT_MAP_CASE(mbrtowc);                                     \
        CRT_MAP_CASE(_mbsbtype);                                   \
        CRT_MAP_CASE(_mbsbtype_l);                                 \
        CRT_MAP_CASE(_mbscat);                                     \
        CRT_MAP_CASE(_mbscat_s);                                   \
        CRT_MAP_CASE(_mbscat_s_l);                                 \
        CRT_MAP_CASE(_mbschr);                                     \
        CRT_MAP_CASE(_mbschr_l);                                   \
        CRT_MAP_CASE(_mbscmp);                                     \
        CRT_MAP_CASE(_mbscmp_l);                                   \
        CRT_MAP_CASE(_mbscoll);                                    \
        CRT_MAP_CASE(_mbscoll_l);                                  \
        CRT_MAP_CASE(_mbscpy);                                     \
        CRT_MAP_CASE(_mbscpy_s);                                   \
        CRT_MAP_CASE(_mbscpy_s_l);                                 \
        CRT_MAP_CASE(_mbscspn);                                    \
        CRT_MAP_CASE(_mbscspn_l);                                  \
        CRT_MAP_CASE(_mbsdec);                                     \
        CRT_MAP_CASE(_mbsdec_l);                                   \
        CRT_MAP_CASE(_mbsdup);                                     \
        CRT_MAP_CASE(_mbsicmp);                                    \
        CRT_MAP_CASE(_mbsicmp_l);                                  \
        CRT_MAP_CASE(_mbsicoll);                                   \
        CRT_MAP_CASE(_mbsicoll_l);                                 \
        CRT_MAP_CASE(_mbsinc);                                     \
        CRT_MAP_CASE(_mbsinc_l);                                   \
        CRT_MAP_CASE(mbsinit);                                     \
        CRT_MAP_CASE(_mbslen);                                     \
        CRT_MAP_CASE(_mbslen_l);                                   \
        CRT_MAP_CASE(_mbslwr);                                     \
        CRT_MAP_CASE(_mbslwr_l);                                   \
        CRT_MAP_CASE(_mbslwr_s);                                   \
        CRT_MAP_CASE(_mbslwr_s_l);                                 \
        CRT_MAP_CASE(_mbsnbcat);                                   \
        CRT_MAP_CASE(_mbsnbcat_l);                                 \
        CRT_MAP_CASE(_mbsnbcat_s);                                 \
        CRT_MAP_CASE(_mbsnbcat_s_l);                               \
        CRT_MAP_CASE(_mbsnbcmp);                                   \
        CRT_MAP_CASE(_mbsnbcmp_l);                                 \
        CRT_MAP_CASE(_mbsnbcnt);                                   \
        CRT_MAP_CASE(_mbsnbcnt_l);                                 \
        CRT_MAP_CASE(_mbsnbcoll);                                  \
        CRT_MAP_CASE(_mbsnbcoll_l);                                \
        CRT_MAP_CASE(_mbsnbcpy);                                   \
        CRT_MAP_CASE(_mbsnbcpy_l);                                 \
        CRT_MAP_CASE(_mbsnbcpy_s);                                 \
        CRT_MAP_CASE(_mbsnbcpy_s_l);                               \
        CRT_MAP_CASE(_mbsnbicmp);                                  \
        CRT_MAP_CASE(_mbsnbicmp_l);                                \
        CRT_MAP_CASE(_mbsnbicoll);                                 \
        CRT_MAP_CASE(_mbsnbicoll_l);                               \
        CRT_MAP_CASE(_mbsnbset);                                   \
        CRT_MAP_CASE(_mbsnbset_l);                                 \
        CRT_MAP_CASE(_mbsnbset_s);                                 \
        CRT_MAP_CASE(_mbsnbset_s_l);                               \
        CRT_MAP_CASE(_mbsncat);                                    \
        CRT_MAP_CASE(_mbsncat_l);                                  \
        CRT_MAP_CASE(_mbsncat_s);                                  \
        CRT_MAP_CASE(_mbsncat_s_l);                                \
        CRT_MAP_CASE(_mbsnccnt);                                   \
        CRT_MAP_CASE(_mbsnccnt_l);                                 \
        CRT_MAP_CASE(_mbsncmp);                                    \
        CRT_MAP_CASE(_mbsncmp_l);                                  \
        CRT_MAP_CASE(_mbsncoll);                                   \
        CRT_MAP_CASE(_mbsncoll_l);                                 \
        CRT_MAP_CASE(_mbsncpy);                                    \
        CRT_MAP_CASE(_mbsncpy_l);                                  \
        CRT_MAP_CASE(_mbsncpy_s);                                  \
        CRT_MAP_CASE(_mbsncpy_s_l);                                \
        CRT_MAP_CASE(_mbsnextc);                                   \
        CRT_MAP_CASE(_mbsnextc_l);                                 \
        CRT_MAP_CASE(_mbsnicmp);                                   \
        CRT_MAP_CASE(_mbsnicmp_l);                                 \
        CRT_MAP_CASE(_mbsnicoll);                                  \
        CRT_MAP_CASE(_mbsnicoll_l);                                \
        CRT_MAP_CASE(_mbsninc);                                    \
        CRT_MAP_CASE(_mbsninc_l);                                  \
        CRT_MAP_CASE(_mbsnlen);                                    \
        CRT_MAP_CASE(_mbsnlen_l);                                  \
        CRT_MAP_CASE(_mbsnset);                                    \
        CRT_MAP_CASE(_mbsnset_l);                                  \
        CRT_MAP_CASE(_mbsnset_s);                                  \
        CRT_MAP_CASE(_mbsnset_s_l);                                \
        CRT_MAP_CASE(_mbspbrk);                                    \
        CRT_MAP_CASE(_mbspbrk_l);                                  \
        CRT_MAP_CASE(_mbsrchr);                                    \
        CRT_MAP_CASE(_mbsrchr_l);                                  \
        CRT_MAP_CASE(_mbsrev);                                     \
        CRT_MAP_CASE(_mbsrev_l);                                   \
        CRT_MAP_CASE(mbsrtowcs);                                   \
        CRT_MAP_CASE(mbsrtowcs_s);                                 \
        CRT_MAP_CASE(_mbsset);                                     \
        CRT_MAP_CASE(_mbsset_l);                                   \
        CRT_MAP_CASE(_mbsset_s);                                   \
        CRT_MAP_CASE(_mbsset_s_l);                                 \
        CRT_MAP_CASE(_mbsspn);                                     \
        CRT_MAP_CASE(_mbsspn_l);                                   \
        CRT_MAP_CASE(_mbsspnp);                                    \
        CRT_MAP_CASE(_mbsspnp_l);                                  \
        CRT_MAP_CASE(_mbsstr);                                     \
        CRT_MAP_CASE(_mbsstr_l);                                   \
        CRT_MAP_CASE(_mbstok);                                     \
        CRT_MAP_CASE(_mbstok_l);                                   \
        CRT_MAP_CASE(_mbstok_s);                                   \
        CRT_MAP_CASE(_mbstok_s_l);                                 \
        CRT_MAP_CASE(mbstowcs);                                    \
        CRT_MAP_CASE(_mbstowcs_l);                                 \
        CRT_MAP_CASE(mbstowcs_s);                                  \
        CRT_MAP_CASE(_mbstowcs_s_l);                               \
        CRT_MAP_CASE(_mbstrlen);                                   \
        CRT_MAP_CASE(_mbstrlen_l);                                 \
        CRT_MAP_CASE(_mbstrnlen);                                  \
        CRT_MAP_CASE(_mbstrnlen_l);                                \
        CRT_MAP_CASE(_mbsupr);                                     \
        CRT_MAP_CASE(_mbsupr_l);                                   \
        CRT_MAP_CASE(_mbsupr_s);                                   \
        CRT_MAP_CASE(_mbsupr_s_l);                                 \
        CRT_MAP_CASE(mbtowc);                                      \
        CRT_MAP_CASE(_mbtowc_l);                                   \
        CRT_MAP_CASE(memccpy);                                     \
        CRT_MAP_CASE(_memccpy);                                    \
        CRT_MAP_CASE(memchr);                                      \
        CRT_MAP_CASE(memcmp);                                      \
        CRT_MAP_CASE(memcpy);                                      \
        CRT_MAP_CASE(memcpy_s);                                    \
        CRT_MAP_CASE(memicmp);                                     \
        CRT_MAP_CASE(_memicmp);                                    \
        CRT_MAP_CASE(_memicmp_l);                                  \
        CRT_MAP_CASE(memmove);                                     \
        CRT_MAP_CASE(memmove_s);                                   \
        CRT_MAP_CASE(memset);                                      \
        CRT_MAP_CASE(mkdir);                                       \
        CRT_MAP_CASE(_mkdir);                                      \
        CRT_MAP_CASE(_mkgmtime);                                   \
        CRT_MAP_CASE(_mkgmtime32);                                 \
        CRT_MAP_CASE(_mkgmtime64);                                 \
        CRT_MAP_CASE(mktemp);                                      \
        CRT_MAP_CASE(_mktemp);                                     \
        CRT_MAP_CASE(_mktemp_s);                                   \
        CRT_MAP_CASE(mktime);                                      \
        CRT_MAP_CASE(_mktime32);                                   \
        CRT_MAP_CASE(_mktime64);                                   \
        CRT_MAP_CASE(modf);                                        \
        CRT_MAP_CASE(modff);                                       \
        CRT_MAP_CASE(_msize);                                      \
        CRT_MAP_CASE(nan);                                         \
        CRT_MAP_CASE(nanf);                                        \
        CRT_MAP_CASE(nanl);                                        \
        CRT_MAP_CASE(nearbyint);                                   \
        CRT_MAP_CASE(nearbyintf);                                  \
        CRT_MAP_CASE(nearbyintl);                                  \
        CRT_MAP_CASE(nextafter);                                   \
        CRT_MAP_CASE(_nextafter);                                  \
        CRT_MAP_CASE(nextafterf);                                  \
        CRT_MAP_CASE(nextafterl);                                  \
        CRT_MAP_CASE(nexttoward);                                  \
        CRT_MAP_CASE(nexttowardf);                                 \
        CRT_MAP_CASE(nexttowardl);                                 \
        CRT_MAP_CASE(norm);                                        \
        CRT_MAP_CASE(normf);                                       \
        CRT_MAP_CASE(norml);                                       \
        CRT_MAP_CASE(_onexit);                                     \
        CRT_MAP_CASE(open);                                        \
        CRT_MAP_CASE(_open);                                       \
        CRT_MAP_CASE(_open_osfhandle);                             \
        CRT_MAP_CASE(_pclose);                                     \
        CRT_MAP_CASE(perror);                                      \
        CRT_MAP_CASE(_pipe);                                       \
        CRT_MAP_CASE(_popen);                                      \
        CRT_MAP_CASE(pow);                                         \
        CRT_MAP_CASE(powf);                                        \
        CRT_MAP_CASE(powl);                                        \
        CRT_MAP_CASE(printf);                                      \
        CRT_MAP_CASE(_printf_l);                                   \
        CRT_MAP_CASE(_printf_p);                                   \
        CRT_MAP_CASE(_printf_p_l);                                 \
        CRT_MAP_CASE(printf_s);                                    \
        CRT_MAP_CASE(_printf_s_l);                                 \
        CRT_MAP_CASE(putc);                                        \
        CRT_MAP_CASE(_putc_nolock);                                \
        CRT_MAP_CASE(putch);                                       \
        CRT_MAP_CASE(_putch);                                      \
        CRT_MAP_CASE(_putch_nolock);                               \
        CRT_MAP_CASE(putchar);                                     \
        CRT_MAP_CASE(putenv);                                      \
        CRT_MAP_CASE(_putenv);                                     \
        CRT_MAP_CASE(_putenv_s);                                   \
        CRT_MAP_CASE(puts);                                        \
        CRT_MAP_CASE(putw);                                        \
        CRT_MAP_CASE(_putw);                                       \
        CRT_MAP_CASE(putwc);                                       \
        CRT_MAP_CASE(_putwc_nolock);                               \
        CRT_MAP_CASE(_putwch);                                     \
        CRT_MAP_CASE(_putwch_nolock);                              \
        CRT_MAP_CASE(putwchar);                                    \
        CRT_MAP_CASE(_putws);                                      \
        CRT_MAP_CASE(qsort);                                       \
        CRT_MAP_CASE(qsort_s);                                     \
        CRT_MAP_CASE(quick_exit);                                  \
        CRT_MAP_CASE(rand);                                        \
        CRT_MAP_CASE(rand_s);                                      \
        CRT_MAP_CASE(read);                                        \
        CRT_MAP_CASE(_read);                                       \
        CRT_MAP_CASE(realloc);                                     \
        CRT_MAP_CASE(_recalloc);                                   \
        CRT_MAP_CASE(remainder);                                   \
        CRT_MAP_CASE(remainderf);                                  \
        CRT_MAP_CASE(remainderl);                                  \
        CRT_MAP_CASE(remove);                                      \
        CRT_MAP_CASE(remquo);                                      \
        CRT_MAP_CASE(remquof);                                     \
        CRT_MAP_CASE(remquol);                                     \
        CRT_MAP_CASE(rename);                                      \
        CRT_MAP_CASE(_resetstkoflw);                               \
        CRT_MAP_CASE(rewind);                                      \
        CRT_MAP_CASE(rint);                                        \
        CRT_MAP_CASE(rintf);                                       \
        CRT_MAP_CASE(rintl);                                       \
        CRT_MAP_CASE(rmdir);                                       \
        CRT_MAP_CASE(_rmdir);                                      \
        CRT_MAP_CASE(rmtmp);                                       \
        CRT_MAP_CASE(_rmtmp);                                      \
        CRT_MAP_CASE(round);                                       \
        CRT_MAP_CASE(roundf);                                      \
        CRT_MAP_CASE(roundl);                                      \
        CRT_MAP_CASE(_scalb);                                      \
        CRT_MAP_CASE(scalbln);                                     \
        CRT_MAP_CASE(scalblnf);                                    \
        CRT_MAP_CASE(scalblnl);                                    \
        CRT_MAP_CASE(scalbn);                                      \
        CRT_MAP_CASE(scalbnf);                                     \
        CRT_MAP_CASE(scalbnl);                                     \
        CRT_MAP_CASE(scanf);                                       \
        CRT_MAP_CASE(_scanf_l);                                    \
        CRT_MAP_CASE(scanf_s);                                     \
        CRT_MAP_CASE(_scanf_s_l);                                  \
        CRT_MAP_CASE(_scprintf);                                   \
        CRT_MAP_CASE(_scprintf_l);                                 \
        CRT_MAP_CASE(_scprintf_p);                                 \
        CRT_MAP_CASE(_scprintf_p_l);                               \
        CRT_MAP_CASE(_scwprintf);                                  \
        CRT_MAP_CASE(_scwprintf_l);                                \
        CRT_MAP_CASE(_scwprintf_p);                                \
        CRT_MAP_CASE(_scwprintf_p_l);                              \
        CRT_MAP_CASE(_searchenv);                                  \
        CRT_MAP_CASE(_searchenv_s);                                \
        CRT_MAP_CASE(__security_init_cookie);                      \
        CRT_MAP_CASE(_seh_filter_dll);                             \
        CRT_MAP_CASE(_seh_filter_exe);                             \
        CRT_MAP_CASE(_set_abort_behavior);                         \
        CRT_MAP_CASE(_set_controlfp);                              \
        CRT_MAP_CASE(_set_doserrno);                               \
        CRT_MAP_CASE(_set_errno);                                  \
        CRT_MAP_CASE(_set_error_mode);                             \
        CRT_MAP_CASE(_set_fmode);                                  \
        CRT_MAP_CASE(_set_invalid_parameter_handler);              \
        CRT_MAP_CASE(_set_printf_count_output);                    \
        CRT_MAP_CASE(_set_purecall_handler);                       \
        CRT_MAP_CASE(_set_thread_local_invalid_parameter_handler); \
        CRT_MAP_CASE(setbuf);                                      \
        CRT_MAP_CASE(setjmp);                                      \
        CRT_MAP_CASE(setlocale);                                   \
        CRT_MAP_CASE(_setmaxstdio);                                \
        CRT_MAP_CASE(_setmbcp);                                    \
        CRT_MAP_CASE(setmode);                                     \
        CRT_MAP_CASE(_setmode);                                    \
        CRT_MAP_CASE(setvbuf);                                     \
        CRT_MAP_CASE(signal);                                      \
        CRT_MAP_CASE(sin);                                         \
        CRT_MAP_CASE(sinf);                                        \
        CRT_MAP_CASE(sinh);                                        \
        CRT_MAP_CASE(sinhf);                                       \
        CRT_MAP_CASE(sinhl);                                       \
        CRT_MAP_CASE(sinl);                                        \
        CRT_MAP_CASE(snprintf);                                    \
        CRT_MAP_CASE(_snprintf);                                   \
        CRT_MAP_CASE(_snprintf_l);                                 \
        CRT_MAP_CASE(_snprintf_s);                                 \
        CRT_MAP_CASE(_snprintf_s_l);                               \
        CRT_MAP_CASE(_snscanf);                                    \
        CRT_MAP_CASE(_snscanf_l);                                  \
        CRT_MAP_CASE(_snscanf_s);                                  \
        CRT_MAP_CASE(_snscanf_s_l);                                \
        CRT_MAP_CASE(_snwprintf);                                  \
        CRT_MAP_CASE(_snwprintf_l);                                \
        CRT_MAP_CASE(_snwprintf_s);                                \
        CRT_MAP_CASE(_snwprintf_s_l);                              \
        CRT_MAP_CASE(_snwscanf);                                   \
        CRT_MAP_CASE(_snwscanf_l);                                 \
        CRT_MAP_CASE(_snwscanf_s);                                 \
        CRT_MAP_CASE(_snwscanf_s_l);                               \
        CRT_MAP_CASE(sopen);                                       \
        CRT_MAP_CASE(_sopen);                                      \
        CRT_MAP_CASE(_sopen_s);                                    \
        CRT_MAP_CASE(spawnl);                                      \
        CRT_MAP_CASE(_spawnl);                                     \
        CRT_MAP_CASE(spawnle);                                     \
        CRT_MAP_CASE(_spawnle);                                    \
        CRT_MAP_CASE(spawnlp);                                     \
        CRT_MAP_CASE(_spawnlp);                                    \
        CRT_MAP_CASE(spawnlpe);                                    \
        CRT_MAP_CASE(_spawnlpe);                                   \
        CRT_MAP_CASE(spawnv);                                      \
        CRT_MAP_CASE(_spawnv);                                     \
        CRT_MAP_CASE(spawnve);                                     \
        CRT_MAP_CASE(_spawnve);                                    \
        CRT_MAP_CASE(spawnvp);                                     \
        CRT_MAP_CASE(_spawnvp);                                    \
        CRT_MAP_CASE(spawnvpe);                                    \
        CRT_MAP_CASE(_spawnvpe);                                   \
        CRT_MAP_CASE(_splitpath);                                  \
        CRT_MAP_CASE(_splitpath_s);                                \
        CRT_MAP_CASE(sprintf);                                     \
        CRT_MAP_CASE(_sprintf_l);                                  \
        CRT_MAP_CASE(_sprintf_p);                                  \
        CRT_MAP_CASE(_sprintf_p_l);                                \
        CRT_MAP_CASE(sprintf_s);                                   \
        CRT_MAP_CASE(_sprintf_s_l);                                \
        CRT_MAP_CASE(sqrt);                                        \
        CRT_MAP_CASE(sqrtf);                                       \
        CRT_MAP_CASE(sqrtl);                                       \
        CRT_MAP_CASE(srand);                                       \
        CRT_MAP_CASE(sscanf);                                      \
        CRT_MAP_CASE(_sscanf_l);                                   \
        CRT_MAP_CASE(sscanf_s);                                    \
        CRT_MAP_CASE(_sscanf_s_l);                                 \
        CRT_MAP_CASE(_stat);                                       \
        CRT_MAP_CASE(_stat32);                                     \
        CRT_MAP_CASE(_stat32i64);                                  \
        CRT_MAP_CASE(_stat64);                                     \
        CRT_MAP_CASE(_stat64i32);                                  \
        CRT_MAP_CASE(_stati64);                                    \
        CRT_MAP_CASE(_status87);                                   \
        CRT_MAP_CASE(_statusfp);                                   \
        CRT_MAP_CASE(strcat);                                      \
        CRT_MAP_CASE(strcat_s);                                    \
        CRT_MAP_CASE(strchr);                                      \
        CRT_MAP_CASE(strcmp);                                      \
        CRT_MAP_CASE(strcmpi);                                     \
        CRT_MAP_CASE(strcoll);                                     \
        CRT_MAP_CASE(_strcoll_l);                                  \
        CRT_MAP_CASE(strcpy);                                      \
        CRT_MAP_CASE(strcpy_s);                                    \
        CRT_MAP_CASE(strcspn);                                     \
        CRT_MAP_CASE(_strdate);                                    \
        CRT_MAP_CASE(_strdate_s);                                  \
        CRT_MAP_CASE(_strdup);                                     \
        CRT_MAP_CASE(strdup);                                      \
        CRT_MAP_CASE(strerror);                                    \
        CRT_MAP_CASE(_strerror);                                   \
        CRT_MAP_CASE(strerror_s);                                  \
        CRT_MAP_CASE(_strerror_s);                                 \
        CRT_MAP_CASE(strftime);                                    \
        CRT_MAP_CASE(_strftime_l);                                 \
        CRT_MAP_CASE(_stricmp);                                    \
        CRT_MAP_CASE(stricmp);                                     \
        CRT_MAP_CASE(_stricmp_l);                                  \
        CRT_MAP_CASE(_stricoll);                                   \
        CRT_MAP_CASE(_stricoll_l);                                 \
        CRT_MAP_CASE(strlen);                                      \
        CRT_MAP_CASE(_strlwr);                                     \
        CRT_MAP_CASE(strlwr);                                      \
        CRT_MAP_CASE(_strlwr_l);                                   \
        CRT_MAP_CASE(_strlwr_s);                                   \
        CRT_MAP_CASE(_strlwr_s_l);                                 \
        CRT_MAP_CASE(strncat);                                     \
        CRT_MAP_CASE(strncat_s);                                   \
        CRT_MAP_CASE(strncmp);                                     \
        CRT_MAP_CASE(_strncoll);                                   \
        CRT_MAP_CASE(_strncoll_l);                                 \
        CRT_MAP_CASE(strncpy);                                     \
        CRT_MAP_CASE(strncpy_s);                                   \
        CRT_MAP_CASE(_strnicmp);                                   \
        CRT_MAP_CASE(strnicmp);                                    \
        CRT_MAP_CASE(_strnicmp_l);                                 \
        CRT_MAP_CASE(_strnicoll);                                  \
        CRT_MAP_CASE(_strnicoll_l);                                \
        CRT_MAP_CASE(strnlen);                                     \
        CRT_MAP_CASE(strnlen_s);                                   \
        CRT_MAP_CASE(_strnset);                                    \
        CRT_MAP_CASE(strnset);                                     \
        CRT_MAP_CASE(_strnset_s);                                  \
        CRT_MAP_CASE(strpbrk);                                     \
        CRT_MAP_CASE(strrchr);                                     \
        CRT_MAP_CASE(_strrev);                                     \
        CRT_MAP_CASE(strrev);                                      \
        CRT_MAP_CASE(_strset);                                     \
        CRT_MAP_CASE(strset);                                      \
        CRT_MAP_CASE(_strset_s);                                   \
        CRT_MAP_CASE(strspn);                                      \
        CRT_MAP_CASE(strstr);                                      \
        CRT_MAP_CASE(_strtime);                                    \
        CRT_MAP_CASE(_strtime_s);                                  \
        CRT_MAP_CASE(strtod);                                      \
        CRT_MAP_CASE(_strtod_l);                                   \
        CRT_MAP_CASE(strtof);                                      \
        CRT_MAP_CASE(_strtof_l);                                   \
        CRT_MAP_CASE(_strtoi64);                                   \
        CRT_MAP_CASE(_strtoi64_l);                                 \
        CRT_MAP_CASE(strtoimax);                                   \
        CRT_MAP_CASE(_strtoimax_l);                                \
        CRT_MAP_CASE(strtok);                                      \
        CRT_MAP_CASE(strtok_s);                                    \
        CRT_MAP_CASE(strtol);                                      \
        CRT_MAP_CASE(_strtol_l);                                   \
        CRT_MAP_CASE(strtold);                                     \
        CRT_MAP_CASE(_strtold_l);                                  \
        CRT_MAP_CASE(strtoll);                                     \
        CRT_MAP_CASE(_strtoll_l);                                  \
        CRT_MAP_CASE(_strtoui64);                                  \
        CRT_MAP_CASE(_strtoui64_l);                                \
        CRT_MAP_CASE(strtoul);                                     \
        CRT_MAP_CASE(_strtoul_l);                                  \
        CRT_MAP_CASE(strtoull);                                    \
        CRT_MAP_CASE(_strtoull_l);                                 \
        CRT_MAP_CASE(strtoumax);                                   \
        CRT_MAP_CASE(_strtoumax_l);                                \
        CRT_MAP_CASE(_strupr);                                     \
        CRT_MAP_CASE(strupr);                                      \
        CRT_MAP_CASE(_strupr_l);                                   \
        CRT_MAP_CASE(_strupr_s);                                   \
        CRT_MAP_CASE(_strupr_s_l);                                 \
        CRT_MAP_CASE(strxfrm);                                     \
        CRT_MAP_CASE(_strxfrm_l);                                  \
        CRT_MAP_CASE(swab);                                        \
        CRT_MAP_CASE(_swab);                                       \
        CRT_MAP_CASE(swprintf);                                    \
        CRT_MAP_CASE(_swprintf_l);                                 \
        CRT_MAP_CASE(__swprintf_l);                                \
        CRT_MAP_CASE(_swprintf_p);                                 \
        CRT_MAP_CASE(_swprintf_p_l);                               \
        CRT_MAP_CASE(swprintf_s);                                  \
        CRT_MAP_CASE(_swprintf_s_l);                               \
        CRT_MAP_CASE(swscanf);                                     \
        CRT_MAP_CASE(_swscanf_l);                                  \
        CRT_MAP_CASE(swscanf_s);                                   \
        CRT_MAP_CASE(_swscanf_s_l);                                \
        CRT_MAP_CASE(system);                                      \
        CRT_MAP_CASE(tan);                                         \
        CRT_MAP_CASE(tanf);                                        \
        CRT_MAP_CASE(tanh);                                        \
        CRT_MAP_CASE(tanhf);                                       \
        CRT_MAP_CASE(tanhl);                                       \
        CRT_MAP_CASE(tanl);                                        \
        CRT_MAP_CASE(tell);                                        \
        CRT_MAP_CASE(_tell);                                       \
        CRT_MAP_CASE(_telli64);                                    \
        CRT_MAP_CASE(tempnam);                                     \
        CRT_MAP_CASE(_tempnam);                                    \
        CRT_MAP_CASE(tgamma);                                      \
        CRT_MAP_CASE(tgammaf);                                     \
        CRT_MAP_CASE(tgammal);                                     \
        CRT_MAP_CASE(time);                                        \
        CRT_MAP_CASE(_time32);                                     \
        CRT_MAP_CASE(_time64);                                     \
        CRT_MAP_CASE(timespec_get);                                \
        CRT_MAP_CASE(_timespec32_get);                             \
        CRT_MAP_CASE(_timespec64_get);                             \
        CRT_MAP_CASE(tmpfile);                                     \
        CRT_MAP_CASE(tmpfile_s);                                   \
        CRT_MAP_CASE(tmpnam);                                      \
        CRT_MAP_CASE(tmpnam_s);                                    \
        CRT_MAP_CASE(__toascii);                                   \
        CRT_MAP_CASE(toascii);                                     \
        CRT_MAP_CASE(tolower);                                     \
        CRT_MAP_CASE(_tolower);                                    \
        CRT_MAP_CASE(_tolower_l);                                  \
        CRT_MAP_CASE(toupper);                                     \
        CRT_MAP_CASE(_toupper);                                    \
        CRT_MAP_CASE(_toupper_l);                                  \
        CRT_MAP_CASE(towlower);                                    \
        CRT_MAP_CASE(_towlower_l);                                 \
        CRT_MAP_CASE(towupper);                                    \
        CRT_MAP_CASE(_towupper_l);                                 \
        CRT_MAP_CASE(trunc);                                       \
        CRT_MAP_CASE(truncf);                                      \
        CRT_MAP_CASE(truncl);                                      \
        CRT_MAP_CASE(tzset);                                       \
        CRT_MAP_CASE(_tzset);                                      \
        CRT_MAP_CASE(_ui64toa);                                    \
        CRT_MAP_CASE(_ui64toa_s);                                  \
        CRT_MAP_CASE(_ui64tow);                                    \
        CRT_MAP_CASE(_ui64tow_s);                                  \
        CRT_MAP_CASE(ultoa);                                       \
        CRT_MAP_CASE(_ultoa);                                      \
        CRT_MAP_CASE(_ultoa_s);                                    \
        CRT_MAP_CASE(_ultow);                                      \
        CRT_MAP_CASE(_ultow_s);                                    \
        CRT_MAP_CASE(umask);                                       \
        CRT_MAP_CASE(_umask);                                      \
        CRT_MAP_CASE(_umask_s);                                    \
        CRT_MAP_CASE(ungetc);                                      \
        CRT_MAP_CASE(_ungetc_nolock);                              \
        CRT_MAP_CASE(ungetch);                                     \
        CRT_MAP_CASE(_ungetch);                                    \
        CRT_MAP_CASE(_ungetch_nolock);                             \
        CRT_MAP_CASE(ungetwc);                                     \
        CRT_MAP_CASE(_ungetwc_nolock);                             \
        CRT_MAP_CASE(_ungetwch);                                   \
        CRT_MAP_CASE(_ungetwch_nolock);                            \
        CRT_MAP_CASE(unlink);                                      \
        CRT_MAP_CASE(_unlink);                                     \
        CRT_MAP_CASE(_unlock_file);                                \
        CRT_MAP_CASE(_utime);                                      \
        CRT_MAP_CASE(_utime32);                                    \
        CRT_MAP_CASE(_utime64);                                    \
        CRT_MAP_CASE(_vcprintf);                                   \
        CRT_MAP_CASE(_vcprintf_l);                                 \
        CRT_MAP_CASE(_vcprintf_p);                                 \
        CRT_MAP_CASE(_vcprintf_p_l);                               \
        CRT_MAP_CASE(_vcprintf_s);                                 \
        CRT_MAP_CASE(_vcprintf_s_l);                               \
        CRT_MAP_CASE(_vcwprintf);                                  \
        CRT_MAP_CASE(_vcwprintf_l);                                \
        CRT_MAP_CASE(_vcwprintf_p);                                \
        CRT_MAP_CASE(_vcwprintf_p_l);                              \
        CRT_MAP_CASE(_vcwprintf_s);                                \
        CRT_MAP_CASE(_vcwprintf_s_l);                              \
        CRT_MAP_CASE(vfprintf);                                    \
        CRT_MAP_CASE(_vfprintf_l);                                 \
        CRT_MAP_CASE(_vfprintf_p);                                 \
        CRT_MAP_CASE(_vfprintf_p_l);                               \
        CRT_MAP_CASE(vfprintf_s);                                  \
        CRT_MAP_CASE(_vfprintf_s_l);                               \
        CRT_MAP_CASE(vfscanf);                                     \
        CRT_MAP_CASE(vfscanf_s);                                   \
        CRT_MAP_CASE(vfwprintf);                                   \
        CRT_MAP_CASE(_vfwprintf_l);                                \
        CRT_MAP_CASE(_vfwprintf_p);                                \
        CRT_MAP_CASE(_vfwprintf_p_l);                              \
        CRT_MAP_CASE(vfwprintf_s);                                 \
        CRT_MAP_CASE(_vfwprintf_s_l);                              \
        CRT_MAP_CASE(vfwscanf);                                    \
        CRT_MAP_CASE(vfwscanf_s);                                  \
        CRT_MAP_CASE(vprintf);                                     \
        CRT_MAP_CASE(_vprintf_l);                                  \
        CRT_MAP_CASE(_vprintf_p);                                  \
        CRT_MAP_CASE(_vprintf_p_l);                                \
        CRT_MAP_CASE(vprintf_s);                                   \
        CRT_MAP_CASE(_vprintf_s_l);                                \
        CRT_MAP_CASE(vscanf);                                      \
        CRT_MAP_CASE(vscanf_s);                                    \
        CRT_MAP_CASE(_vscprintf);                                  \
        CRT_MAP_CASE(_vscprintf_l);                                \
        CRT_MAP_CASE(_vscprintf_p);                                \
        CRT_MAP_CASE(_vscprintf_p_l);                              \
        CRT_MAP_CASE(_vscwprintf);                                 \
        CRT_MAP_CASE(_vscwprintf_l);                               \
        CRT_MAP_CASE(_vscwprintf_p);                               \
        CRT_MAP_CASE(_vscwprintf_p_l);                             \
        CRT_MAP_CASE(vsnprintf);                                   \
        CRT_MAP_CASE(_vsnprintf);                                  \
        CRT_MAP_CASE(_vsnprintf_l);                                \
        CRT_MAP_CASE(vsnprintf_s);                                 \
        CRT_MAP_CASE(_vsnprintf_s);                                \
        CRT_MAP_CASE(_vsnprintf_s_l);                              \
        CRT_MAP_CASE(_vsnwprintf);                                 \
        CRT_MAP_CASE(_vsnwprintf_l);                               \
        CRT_MAP_CASE(_vsnwprintf_s);                               \
        CRT_MAP_CASE(_vsnwprintf_s_l);                             \
        CRT_MAP_CASE(vsprintf);                                    \
        CRT_MAP_CASE(_vsprintf_l);                                 \
        CRT_MAP_CASE(_vsprintf_p);                                 \
        CRT_MAP_CASE(_vsprintf_p_l);                               \
        CRT_MAP_CASE(vsprintf_s);                                  \
        CRT_MAP_CASE(_vsprintf_s_l);                               \
        CRT_MAP_CASE(vsscanf);                                     \
        CRT_MAP_CASE(vsscanf_s);                                   \
        CRT_MAP_CASE(vswprintf);                                   \
        CRT_MAP_CASE(_vswprintf_l);                                \
        CRT_MAP_CASE(__vswprintf_l);                               \
        CRT_MAP_CASE(_vswprintf_p);                                \
        CRT_MAP_CASE(_vswprintf_p_l);                              \
        CRT_MAP_CASE(vswprintf_s);                                 \
        CRT_MAP_CASE(_vswprintf_s_l);                              \
        CRT_MAP_CASE(vswscanf);                                    \
        CRT_MAP_CASE(vswscanf_s);                                  \
        CRT_MAP_CASE(vwprintf);                                    \
        CRT_MAP_CASE(_vwprintf_l);                                 \
        CRT_MAP_CASE(_vwprintf_p);                                 \
        CRT_MAP_CASE(_vwprintf_p_l);                               \
        CRT_MAP_CASE(vwprintf_s);                                  \
        CRT_MAP_CASE(_vwprintf_s_l);                               \
        CRT_MAP_CASE(vwscanf);                                     \
        CRT_MAP_CASE(vwscanf_s);                                   \
        CRT_MAP_CASE(_waccess);                                    \
        CRT_MAP_CASE(_waccess_s);                                  \
        CRT_MAP_CASE(_wasctime);                                   \
        CRT_MAP_CASE(_wasctime_s);                                 \
        CRT_MAP_CASE(_wchdir);                                     \
        CRT_MAP_CASE(_wchmod);                                     \
        CRT_MAP_CASE(_wcreat);                                     \
        CRT_MAP_CASE(_wcreate_locale);                             \
        CRT_MAP_CASE(wcrtomb);                                     \
        CRT_MAP_CASE(wcrtomb_s);                                   \
        CRT_MAP_CASE(wcscat);                                      \
        CRT_MAP_CASE(wcscat_s);                                    \
        CRT_MAP_CASE(wcschr);                                      \
        CRT_MAP_CASE(wcscmp);                                      \
        CRT_MAP_CASE(wcscoll);                                     \
        CRT_MAP_CASE(_wcscoll_l);                                  \
        CRT_MAP_CASE(wcscpy);                                      \
        CRT_MAP_CASE(wcscpy_s);                                    \
        CRT_MAP_CASE(wcscspn);                                     \
        CRT_MAP_CASE(_wcsdup);                                     \
        CRT_MAP_CASE(wcsdup);                                      \
        CRT_MAP_CASE(_wcserror);                                   \
        CRT_MAP_CASE(__wcserror);                                  \
        CRT_MAP_CASE(_wcserror_s);                                 \
        CRT_MAP_CASE(__wcserror_s);                                \
        CRT_MAP_CASE(wcsftime);                                    \
        CRT_MAP_CASE(_wcsftime_l);                                 \
        CRT_MAP_CASE(_wcsicmp);                                    \
        CRT_MAP_CASE(wcsicmp);                                     \
        CRT_MAP_CASE(_wcsicmp_l);                                  \
        CRT_MAP_CASE(_wcsicoll);                                   \
        CRT_MAP_CASE(wcsicoll);                                    \
        CRT_MAP_CASE(_wcsicoll_l);                                 \
        CRT_MAP_CASE(wcslen);                                      \
        CRT_MAP_CASE(_wcslwr);                                     \
        CRT_MAP_CASE(wcslwr);                                      \
        CRT_MAP_CASE(_wcslwr_l);                                   \
        CRT_MAP_CASE(_wcslwr_s);                                   \
        CRT_MAP_CASE(_wcslwr_s_l);                                 \
        CRT_MAP_CASE(wcsncat);                                     \
        CRT_MAP_CASE(wcsncat_s);                                   \
        CRT_MAP_CASE(wcsncmp);                                     \
        CRT_MAP_CASE(_wcsncoll);                                   \
        CRT_MAP_CASE(_wcsncoll_l);                                 \
        CRT_MAP_CASE(wcsncpy);                                     \
        CRT_MAP_CASE(wcsncpy_s);                                   \
        CRT_MAP_CASE(_wcsnicmp);                                   \
        CRT_MAP_CASE(wcsnicmp);                                    \
        CRT_MAP_CASE(_wcsnicmp_l);                                 \
        CRT_MAP_CASE(_wcsnicoll);                                  \
        CRT_MAP_CASE(_wcsnicoll_l);                                \
        CRT_MAP_CASE(wcsnlen);                                     \
        CRT_MAP_CASE(wcsnlen_s);                                   \
        CRT_MAP_CASE(_wcsnset);                                    \
        CRT_MAP_CASE(wcsnset);                                     \
        CRT_MAP_CASE(_wcsnset_s);                                  \
        CRT_MAP_CASE(wcspbrk);                                     \
        CRT_MAP_CASE(wcsrchr);                                     \
        CRT_MAP_CASE(_wcsrev);                                     \
        CRT_MAP_CASE(wcsrev);                                      \
        CRT_MAP_CASE(wcsrtombs);                                   \
        CRT_MAP_CASE(wcsrtombs_s);                                 \
        CRT_MAP_CASE(_wcsset);                                     \
        CRT_MAP_CASE(wcsset);                                      \
        CRT_MAP_CASE(_wcsset_s);                                   \
        CRT_MAP_CASE(wcsspn);                                      \
        CRT_MAP_CASE(wcsstr);                                      \
        CRT_MAP_CASE(wcstod);                                      \
        CRT_MAP_CASE(_wcstod_l);                                   \
        CRT_MAP_CASE(wcstof);                                      \
        CRT_MAP_CASE(_wcstof_l);                                   \
        CRT_MAP_CASE(_wcstoi64);                                   \
        CRT_MAP_CASE(_wcstoi64_l);                                 \
        CRT_MAP_CASE(wcstoimax);                                   \
        CRT_MAP_CASE(_wcstoimax_l);                                \
        CRT_MAP_CASE(wcstok);                                      \
        CRT_MAP_CASE(wcstok_s);                                    \
        CRT_MAP_CASE(wcstol);                                      \
        CRT_MAP_CASE(_wcstol_l);                                   \
        CRT_MAP_CASE(wcstold);                                     \
        CRT_MAP_CASE(_wcstold_l);                                  \
        CRT_MAP_CASE(wcstoll);                                     \
        CRT_MAP_CASE(_wcstoll_l);                                  \
        CRT_MAP_CASE(wcstombs);                                    \
        CRT_MAP_CASE(_wcstombs_l);                                 \
        CRT_MAP_CASE(wcstombs_s);                                  \
        CRT_MAP_CASE(_wcstombs_s_l);                               \
        CRT_MAP_CASE(_wcstoui64);                                  \
        CRT_MAP_CASE(_wcstoui64_l);                                \
        CRT_MAP_CASE(wcstoul);                                     \
        CRT_MAP_CASE(_wcstoul_l);                                  \
        CRT_MAP_CASE(wcstoull);                                    \
        CRT_MAP_CASE(_wcstoull_l);                                 \
        CRT_MAP_CASE(wcstoumax);                                   \
        CRT_MAP_CASE(_wcstoumax_l);                                \
        CRT_MAP_CASE(_wcsupr);                                     \
        CRT_MAP_CASE(wcsupr);                                      \
        CRT_MAP_CASE(_wcsupr_l);                                   \
        CRT_MAP_CASE(_wcsupr_s);                                   \
        CRT_MAP_CASE(_wcsupr_s_l);                                 \
        CRT_MAP_CASE(wcsxfrm);                                     \
        CRT_MAP_CASE(_wcsxfrm_l);                                  \
        CRT_MAP_CASE(_wctime);                                     \
        CRT_MAP_CASE(_wctime_s);                                   \
        CRT_MAP_CASE(_wctime32);                                   \
        CRT_MAP_CASE(_wctime32_s);                                 \
        CRT_MAP_CASE(_wctime64);                                   \
        CRT_MAP_CASE(_wctime64_s);                                 \
        CRT_MAP_CASE(wctob);                                       \
        CRT_MAP_CASE(wctomb);                                      \
        CRT_MAP_CASE(_wctomb_l);                                   \
        CRT_MAP_CASE(wctomb_s);                                    \
        CRT_MAP_CASE(_wctomb_s_l);                                 \
        CRT_MAP_CASE(wctype);                                      \
        CRT_MAP_CASE(_wdupenv_s);                                  \
        CRT_MAP_CASE(_wexecl);                                     \
        CRT_MAP_CASE(_wexecle);                                    \
        CRT_MAP_CASE(_wexeclp);                                    \
        CRT_MAP_CASE(_wexeclpe);                                   \
        CRT_MAP_CASE(_wexecv);                                     \
        CRT_MAP_CASE(_wexecve);                                    \
        CRT_MAP_CASE(_wexecvp);                                    \
        CRT_MAP_CASE(_wexecvpe);                                   \
        CRT_MAP_CASE(_wfdopen);                                    \
        CRT_MAP_CASE(_wfindfirst);                                 \
        CRT_MAP_CASE(_wfindfirst32);                               \
        CRT_MAP_CASE(_wfindfirst32i64);                            \
        CRT_MAP_CASE(_wfindfirst64);                               \
        CRT_MAP_CASE(_wfindfirst64i32);                            \
        CRT_MAP_CASE(_wfindfirsti64);                              \
        CRT_MAP_CASE(_wfindnext);                                  \
        CRT_MAP_CASE(_wfindnext32);                                \
        CRT_MAP_CASE(_wfindnext32i64);                             \
        CRT_MAP_CASE(_wfindnext64);                                \
        CRT_MAP_CASE(_wfindnext64i32);                             \
        CRT_MAP_CASE(_wfindnexti64);                               \
        CRT_MAP_CASE(_wfopen);                                     \
        CRT_MAP_CASE(_wfopen_s);                                   \
        CRT_MAP_CASE(_wfreopen);                                   \
        CRT_MAP_CASE(_wfreopen_s);                                 \
        CRT_MAP_CASE(_wfsopen);                                    \
        CRT_MAP_CASE(_wfullpath);                                  \
        CRT_MAP_CASE(_wgetcwd);                                    \
        CRT_MAP_CASE(_wgetdcwd);                                   \
        CRT_MAP_CASE(_wgetdcwd_nolock);                            \
        CRT_MAP_CASE(_wgetenv);                                    \
        CRT_MAP_CASE(_wgetenv_s);                                  \
        CRT_MAP_CASE(_wmakepath);                                  \
        CRT_MAP_CASE(_wmakepath_s);                                \
        CRT_MAP_CASE(wmemchr);                                     \
        CRT_MAP_CASE(wmemcmp);                                     \
        CRT_MAP_CASE(wmemcpy);                                     \
        CRT_MAP_CASE(wmemcpy_s);                                   \
        CRT_MAP_CASE(wmemmove);                                    \
        CRT_MAP_CASE(wmemmove_s);                                  \
        CRT_MAP_CASE(wmemset);                                     \
        CRT_MAP_CASE(_wmkdir);                                     \
        CRT_MAP_CASE(_wmktemp);                                    \
        CRT_MAP_CASE(_wmktemp_s);                                  \
        CRT_MAP_CASE(_wopen);                                      \
        CRT_MAP_CASE(_wperror);                                    \
        CRT_MAP_CASE(_wpopen);                                     \
        CRT_MAP_CASE(wprintf);                                     \
        CRT_MAP_CASE(_wprintf_l);                                  \
        CRT_MAP_CASE(_wprintf_p);                                  \
        CRT_MAP_CASE(_wprintf_p_l);                                \
        CRT_MAP_CASE(wprintf_s);                                   \
        CRT_MAP_CASE(_wprintf_s_l);                                \
        CRT_MAP_CASE(_wputenv);                                    \
        CRT_MAP_CASE(_wputenv_s);                                  \
        CRT_MAP_CASE(_wremove);                                    \
        CRT_MAP_CASE(_wrename);                                    \
        CRT_MAP_CASE(_write);                                      \
        CRT_MAP_CASE(write);                                       \
        CRT_MAP_CASE(_wrmdir);                                     \
        CRT_MAP_CASE(wscanf);                                      \
        CRT_MAP_CASE(_wscanf_l);                                   \
        CRT_MAP_CASE(wscanf_s);                                    \
        CRT_MAP_CASE(_wscanf_s_l);                                 \
        CRT_MAP_CASE(_wsearchenv);                                 \
        CRT_MAP_CASE(_wsearchenv_s);                               \
        CRT_MAP_CASE(_wsetlocale);                                 \
        CRT_MAP_CASE(_wsopen);                                     \
        CRT_MAP_CASE(_wsopen_s);                                   \
        CRT_MAP_CASE(_wspawnl);                                    \
        CRT_MAP_CASE(_wspawnle);                                   \
        CRT_MAP_CASE(_wspawnlp);                                   \
        CRT_MAP_CASE(_wspawnlpe);                                  \
        CRT_MAP_CASE(_wspawnv);                                    \
        CRT_MAP_CASE(_wspawnve);                                   \
        CRT_MAP_CASE(_wspawnvp);                                   \
        CRT_MAP_CASE(_wspawnvpe);                                  \
        CRT_MAP_CASE(_wsplitpath);                                 \
        CRT_MAP_CASE(_wsplitpath_s);                               \
        CRT_MAP_CASE(_wstat);                                      \
        CRT_MAP_CASE(_wstat32);                                    \
        CRT_MAP_CASE(_wstat32i64);                                 \
        CRT_MAP_CASE(_wstat64);                                    \
        CRT_MAP_CASE(_wstat64i32);                                 \
        CRT_MAP_CASE(_wstati64);                                   \
        CRT_MAP_CASE(_wstrdate);                                   \
        CRT_MAP_CASE(_wstrdate_s);                                 \
        CRT_MAP_CASE(_wstrtime);                                   \
        CRT_MAP_CASE(_wstrtime_s);                                 \
        CRT_MAP_CASE(_wsystem);                                    \
        CRT_MAP_CASE(_wtempnam);                                   \
        CRT_MAP_CASE(_wtmpnam);                                    \
        CRT_MAP_CASE(_wtmpnam_s);                                  \
        CRT_MAP_CASE(_wtof);                                       \
        CRT_MAP_CASE(_wtof_l);                                     \
        CRT_MAP_CASE(_wtoi);                                       \
        CRT_MAP_CASE(_wtoi_l);                                     \
        CRT_MAP_CASE(_wtoi64);                                     \
        CRT_MAP_CASE(_wtoi64_l);                                   \
        CRT_MAP_CASE(_wtol);                                       \
        CRT_MAP_CASE(_wtol_l);                                     \
        CRT_MAP_CASE(_wtoll);                                      \
        CRT_MAP_CASE(_wtoll_l);                                    \
        CRT_MAP_CASE(_wunlink);                                    \
        CRT_MAP_CASE(_wutime);                                     \
        CRT_MAP_CASE(_wutime32);                                   \
        CRT_MAP_CASE(_wutime64);                                   \
        CRT_MAP_CASE(_y0);                                         \
        CRT_MAP_CASE(y0);                                          \
        CRT_MAP_CASE(_y1);                                         \
        CRT_MAP_CASE(y1);                                          \
        CRT_MAP_CASE(_yn);                                         \
        CRT_MAP_CASE(yn);                                          \
    } while (0)
#endif

static void *clib_getsym(CLibrary *cl, const char *name)
{
  void *p = NULL;
#ifdef CRT_STATIC
  CRT_MAP_INIT();
#endif
  if (!p) {
    if (cl->handle == CLIB_DEFHANDLE) {  /* Search default libraries. */
      MSize i;
      for (i = 0; i < CLIB_HANDLE_MAX; i++) {
        HINSTANCE h = (HINSTANCE)clib_def_handle[i];
        if (!(void *)h) {  /* Resolve default library handles (once). */
  #if LJ_TARGET_UWP
  	h = (HINSTANCE)&__ImageBase;
  #else
  	switch (i) {
  	case CLIB_HANDLE_EXE: GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, NULL, &h); break;
  	case CLIB_HANDLE_DLL:
  	  GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
  			     (const char *)clib_def_handle, &h);
  	  break;
  	case CLIB_HANDLE_CRT:
  	  GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
  			     (const char *)&_fmode, &h);
  	  break;
  	case CLIB_HANDLE_KERNEL32: h = LJ_WIN_LOADLIBA("kernel32.dll"); break;
  	case CLIB_HANDLE_USER32: h = LJ_WIN_LOADLIBA("user32.dll"); break;
  	case CLIB_HANDLE_GDI32: h = LJ_WIN_LOADLIBA("gdi32.dll"); break;
  	}
  	if (!h) continue;
  #endif
  	clib_def_handle[i] = (void *)h;
        }
        p = (void *)GetProcAddress(h, name);
        if (p) break;
      }
    } else {
      p = (void *)GetProcAddress((HINSTANCE)cl->handle, name);
    }
  }
  return p;
}

#else

#define CLIB_DEFHANDLE	NULL

LJ_NORET LJ_NOINLINE static void clib_error(lua_State *L, const char *fmt,
					    const char *name)
{
  lj_err_callermsg(L, lj_strfmt_pushf(L, fmt, name, "no support for this OS"));
}

static void *clib_loadlib(lua_State *L, const char *name, int global)
{
  lj_err_callermsg(L, "no support for loading dynamic libraries for this OS");
  UNUSED(name); UNUSED(global);
  return NULL;
}

static void clib_unloadlib(CLibrary *cl)
{
  UNUSED(cl);
}

static void *clib_getsym(CLibrary *cl, const char *name)
{
  UNUSED(cl); UNUSED(name);
  return NULL;
}

#endif

/* -- C library indexing -------------------------------------------------- */

#if LJ_TARGET_X86 && LJ_ABI_WIN
/* Compute argument size for fastcall/stdcall functions. */
static CTSize clib_func_argsize(CTState *cts, CType *ct)
{
  CTSize n = 0;
  while (ct->sib) {
    CType *d;
    ct = ctype_get(cts, ct->sib);
    if (ctype_isfield(ct->info)) {
      d = ctype_rawchild(cts, ct);
      n += ((d->size + 3) & ~3);
    }
  }
  return n;
}
#endif

/* Get redirected or mangled external symbol. */
static const char *clib_extsym(CTState *cts, CType *ct, GCstr *name)
{
  if (ct->sib) {
    CType *ctf = ctype_get(cts, ct->sib);
    if (ctype_isxattrib(ctf->info, CTA_REDIR))
      return strdata(gco2str(gcref(ctf->name)));
  }
  return strdata(name);
}

/* Index a C library by name. */
TValue *lj_clib_index(lua_State *L, CLibrary *cl, GCstr *name)
{
  TValue *tv = lj_tab_setstr(L, cl->cache, name);
  if (LJ_UNLIKELY(tvisnil(tv))) {
    CTState *cts = ctype_cts(L);
    CType *ct;
    CTypeID id = lj_ctype_getname(cts, &ct, name, CLNS_INDEX);
    if (!id)
      lj_err_callerv(L, LJ_ERR_FFI_NODECL, strdata(name));
    if (ctype_isconstval(ct->info)) {
      CType *ctt = ctype_child(cts, ct);
      lj_assertCTS(ctype_isinteger(ctt->info) && ctt->size <= 4,
		   "only 32 bit const supported");  /* NYI */
      if ((ctt->info & CTF_UNSIGNED) && (int32_t)ct->size < 0)
	setnumV(tv, (lua_Number)(uint32_t)ct->size);
      else
	setintV(tv, (int32_t)ct->size);
    } else {
      const char *sym = clib_extsym(cts, ct, name);
#if LJ_TARGET_WINDOWS
      DWORD oldwerr = GetLastError();
#endif
      void *p = clib_getsym(cl, sym);
      GCcdata *cd;
      lj_assertCTS(ctype_isfunc(ct->info) || ctype_isextern(ct->info),
		   "unexpected ctype %08x in clib", ct->info);
#if LJ_TARGET_X86 && LJ_ABI_WIN
      /* Retry with decorated name for fastcall/stdcall functions. */
      if (!p && ctype_isfunc(ct->info)) {
	CTInfo cconv = ctype_cconv(ct->info);
	if (cconv == CTCC_FASTCALL || cconv == CTCC_STDCALL) {
	  CTSize sz = clib_func_argsize(cts, ct);
	  const char *symd = lj_strfmt_pushf(L,
			       cconv == CTCC_FASTCALL ? "@%s@%d" : "_%s@%d",
			       sym, sz);
	  L->top--;
	  p = clib_getsym(cl, symd);
	}
      }
#endif
      if (!p)
	clib_error(L, "cannot resolve symbol " LUA_QS ": %s", sym);
#if LJ_TARGET_WINDOWS
      SetLastError(oldwerr);
#endif
      cd = lj_cdata_new(cts, id, CTSIZE_PTR);
      *(void **)cdataptr(cd) = p;
      setcdataV(L, tv, cd);
      lj_gc_anybarriert(L, cl->cache);
    }
  }
  return tv;
}

/* -- C library management ------------------------------------------------ */

/* Create a new CLibrary object and push it on the stack. */
static CLibrary *clib_new(lua_State *L, GCtab *mt)
{
  GCtab *t = lj_tab_new(L, 0, 0);
  GCudata *ud = lj_udata_new(L, sizeof(CLibrary), t);
  CLibrary *cl = (CLibrary *)uddata(ud);
  cl->cache = t;
  ud->udtype = UDTYPE_FFI_CLIB;
  /* NOBARRIER: The GCudata is new (marked white). */
  setgcref(ud->metatable, obj2gco(mt));
  setudataV(L, L->top++, ud);
  return cl;
}

/* Load a C library. */
void lj_clib_load(lua_State *L, GCtab *mt, GCstr *name, int global)
{
  void *handle = clib_loadlib(L, strdata(name), global);
  CLibrary *cl = clib_new(L, mt);
  cl->handle = handle;
}

/* Unload a C library. */
void lj_clib_unload(CLibrary *cl)
{
  clib_unloadlib(cl);
  cl->handle = NULL;
}

/* Create the default C library object. */
void lj_clib_default(lua_State *L, GCtab *mt)
{
  CLibrary *cl = clib_new(L, mt);
  cl->handle = CLIB_DEFHANDLE;
}

#endif
