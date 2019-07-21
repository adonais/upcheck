ROOT = ..
!include "$(ROOT)\system.mak"

CFLAGS=/nologo /MT /W3 /WX- /wd4996 /wd4819 /O2 /Zi /Gd /D "_CRT_SECURE_NO_WARNINGS"  \
       /D "SQLITE_OMIT_BUILTIN_TEST" /utf-8 $(RELEASE) /D "USE_ARES" $(CFLAGS) /D "COBJMACROS"
      
CXXFLAGS = $(CFLAGS) /TP

RFLAGS  = /nologo /D "_UNICODE" /D "UNICODE" 

LDFLAGS = /NOLOGO /DEBUG /opt:ref /opt:icf /LARGEADDRESSAWARE /MACHINE:$(PLATFORM) $(HIDE) /NODEFAULTLIB:MSVCRT /ENTRY:wmainCRTStartup

DEP  = $(BIND)\libcurl.lib  $(BIND)\zlib.lib $(BIND)\libcares.lib $(BIND)\lib7z.lib
LIBS = $(DEP) ws2_32.lib gdi32.lib crypt32.lib wldap32.lib shlwapi.lib user32.lib advapi32.lib normaliz.lib ole32.lib

OBJS = \
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
    $(CC) $(CFLAGS) /Fd$(BIND)\upcheck.pdb /Fo$(OBJD)\ /c $<
    
.rc{$(OBJD)}.res:
    $(RC) $(RFLAGS) /Fo$@ $<
    
##############################################################################

all: dirs $(BIND)\upcheck.exe


##############################################################################

clean:
    -rmdir /q /s $(OBJD) $(BIND) 2>nul

##############################################################################

dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)

$(BIND)\upcheck.exe : $(OBJS) $(DEP)
    link /out:$@ $(OBJS) $(LDFLAGS) $(LIBS)
    
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
$(OBJD)\resource.res    : resource.rc resource.h upcheck.exe.manifest upcheck.exe.comctl32.manifest
