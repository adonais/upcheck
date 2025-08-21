ROOT = ..

!include "$(ROOT)\system.mak"

CFLAGS = -nologo -W3 -WX- -wd4996 -wd4819 -O2 -Zi -Gd -D "_CRT_SECURE_NO_WARNINGS"  \
         -D "SQLITE_OMIT_BUILTIN_TEST" -utf-8 -D "USE_ARES" $(CFLAGS) -D "COBJMACROS"

CXXFLAGS = $(CFLAGS) /TP

RFLAGS  = -nologo -D "_UNICODE" -D "UNICODE"

LDFLAGS = -DEBUG -opt:ref -opt:icf -MACHINE:$(PLATFORM) -ENTRY:wmainCRTStartup

!IF "$(BITS)" == "32"
LDFLAGS = -LARGEADDRESSAWARE $(LDFLAGS)
!ENDIF

!IF "$(EUAPI_LINK)" == "1"
RFLAGS  = $(RFLAGS) -D "EUAPI_LINK"
DEP     = $(BIND)\zlib.lib $(BIND)\7z.lib
!ELSE
DEP     = $(BIND)\libcurl.lib  $(BIND)\libcares.lib $(BIND)\nghttp2.lib $(BIND)\zlib.lib $(BIND)\7z.lib
CFLAGS  = $(CFLAGS) -DCURL_STATICLIB
LDFLAGS = -NODEFAULTLIB:MSVCRT $(LDFLAGS)
!ENDIF

LIBS    = $(DEP)

!IF "$(DLL_INJECT)" == "1"
DEP     = $(DEP) $(BIND)\detours.lib
CFLAGS  = $(CFLAGS) -DDLL_INJECT=1
LIBS = $(DEP) -WHOLEARCHIVE:$(BIND)\7z.lib
!ELSE
LIBS = $(DEP) $(BIND)\7z.lib
!ENDIF

LIBS = $(LIBS) ws2_32.lib gdi32.lib crypt32.lib wldap32.lib shlwapi.lib user32.lib advapi32.lib normaliz.lib ole32.lib secur32.lib

!if "$(APP_DEBUG)"=="1"
CFLAGS = $(CFLAGS) $(DEBUG_L)
!ELSEIF "$(LOG_DEBUG)"=="1"
CFLAGS = $(CFLAGS) -DLOG_DEBUG
!ELSE
CFLAGS = $(CFLAGS) $(RELEASE)
!ENDIF

OBJS = \
    $(OBJD)\ini_parser.obj     \
    $(OBJD)\upcheck.obj        \
    $(OBJD)\urlcode.obj        \
    $(OBJD)\spinlock.obj       \
    $(OBJD)\extract7z.obj      \
    $(OBJD)\progressui.obj     \
    $(OBJD)\updates.obj        \
!IF "$(DLL_INJECT)" == "1"
    $(OBJD)\setdll.obj         \
!ENDIF
    $(OBJD)\thunderagent.obj   \
    $(OBJD)\xml.obj            \
    $(OBJD)\sqlite3.obj        \
    $(OBJD)\cookies.obj        \
    $(OBJD)\resource.res       \

##############################################################################

.SUFFIXES: .cpp .cc .c .h .obj

.c{$(OBJD)}.obj:
    $(CC) $(CFLAGS) -Fd$(BIND)\upcheck$(BITS).pdb -Fo$(OBJD)\ -c $<

.rc{$(OBJD)}.res:
    $(RC) $(RFLAGS) -Fo$@ $<

##############################################################################

all: dirs $(BIND)\upcheck$(BITS).exe


##############################################################################

clean:
    -rmdir /q /s $(OBJD) $(BIND) 2>nul

##############################################################################

dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)

$(BIND)\upcheck$(BITS).exe : $(OBJS) $(DEP) $(BIND)\7z.lib
    $(LD) /out:$@ $(OBJS) $(LDFLAGS) $(LIBS)
    -copy /y $@ $(BIND)\upcheck.exe

$(OBJD)\ini_parser.obj  : ini_parser.c *.h
$(OBJD)\upcheck.obj     : upcheck.c *.h
$(OBJD)\urlcode.obj     : urlcode.c urlcode.h
$(OBJD)\spinlock.obj    : spinlock.c spinlock.h
$(OBJD)\extract7z.obj   : extract7z.c extract7z.h
$(OBJD)\progressui.obj  : progressui.c progressui.h
$(OBJD)\updates.obj     : updates.c updates.h
!IF "$(DLL_INJECT)" == "1"
$(OBJD)\setdll.obj      : setdll.c setdll.h
!ENDIF
$(OBJD)\thunderagent.obj: thunderagent.c thunderagent.h
$(OBJD)\xml.obj         : xml.c xml.h
$(OBJD)\sqlite3.obj     : sqlite3.c sqlite3.h
$(OBJD)\cookies.obj     : cookies.c cookies.h
$(OBJD)\resource.res    : resource.rc resource.h upcheck.exe.manifest
