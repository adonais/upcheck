ROOT = ..

!include "$(ROOT)\system.mak"

CFLAGS = -nologo -W3 -WX- -wd4996 -wd4819 -O2 -Zi -Gd -D "_CRT_SECURE_NO_WARNINGS"  \
         -D "SQLITE_OMIT_BUILTIN_TEST" -utf-8 -D "USE_ARES" $(CFLAGS) -D "COBJMACROS"

CXXFLAGS = $(CFLAGS) /TP

RFLAGS  = -nologo -D "_UNICODE" -D "UNICODE"

LDFLAGS = -NOLOGO -DEBUG -opt:ref -opt:icf -MACHINE:$(PLATFORM) -ENTRY:wmainCRTStartup

!IF "$(BITS)" == "32"
LDFLAGS = -LARGEADDRESSAWARE $(LDFLAGS)
!ENDIF

!IF "$(EUAPI_LINK)" == "1"
RFLAGS  = $(RFLAGS) -D "EUAPI_LINK"
DEP     = $(BIND)\zlib.lib  $(BIND)\lib7z.lib
!ELSE
DEP     = $(BIND)\libcurl.lib  $(BIND)\libcares.lib $(BIND)\nghttp2.lib $(BIND)\zlib.lib  $(BIND)\lib7z.lib
CFLAGS  = $(CFLAGS) -DCURL_STATICLIB
LDFLAGS = -NODEFAULTLIB:MSVCRT $(LDFLAGS)
!ENDIF

LIBS = $(DEP) ws2_32.lib gdi32.lib crypt32.lib wldap32.lib shlwapi.lib user32.lib advapi32.lib normaliz.lib ole32.lib

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
    $(OBJD)\7zc.obj            \
    $(OBJD)\progressui.obj     \
    $(OBJD)\updates.obj        \
    $(OBJD)\unzip.obj          \
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

$(BIND)\upcheck$(BITS).exe : $(OBJS) $(DEP)
    $(LD) /out:$@ $(OBJS) $(LDFLAGS) $(LIBS)
    -copy /y $@ $(BIND)\upcheck.exe

$(OBJD)\ini_parser.obj  : ini_parser.c *.h
$(OBJD)\upcheck.obj     : upcheck.c *.h
$(OBJD)\urlcode.obj     : urlcode.c urlcode.h
$(OBJD)\spinlock.obj    : spinlock.c spinlock.h
$(OBJD)\7zc.obj         : 7zc.c 7zc.h
$(OBJD)\progressui.obj  : progressui.c progressui.h
$(OBJD)\updates.obj     : updates.c updates.h
$(OBJD)\unzip.obj       : unzip.c unzip.h
$(OBJD)\thunderagent.obj: thunderagent.c thunderagent.h
$(OBJD)\xml.obj         : xml.c xml.h
$(OBJD)\sqlite3.obj     : sqlite3.c sqlite3.h
$(OBJD)\cookies.obj     : cookies.c cookies.h
$(OBJD)\resource.res    : resource.rc resource.h upcheck.exe.manifest
