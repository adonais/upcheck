# Makefile for zlib using Microsoft (Visual) C
# zlib is copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler
#
# The toplevel directory of the source tree.
#
ROOT = ..\..
!include "$(ROOT)\system.mak"

TOP = .\src

# variables
STATICLIB = $(BIND)\zlib.lib

RC = rc
CFLAGS  = -nologo -W3 -O2 -Oy- -Zi -Fd"$(BIND)\zlib" -Isrc -I../include $(LOC) $(CFLAGS) \
          -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE
!if "$(APP_DEBUG)"=="1"
CFLAGS = $(CFLAGS) $(DEBUG_L)
!ELSE
CFLAGS = $(CFLAGS) $(RELEASE)
!ENDIF
ASFLAGS = -Zi $(LOC)
LDFLAGS = -nologo -debug -incremental:no -opt:ref
ARFLAGS = -nologo

OBJS = \
    $(OBJD)\zlib\adler32.obj  \
    $(OBJD)\zlib\compress.obj \
    $(OBJD)\zlib\crc32.obj    \
    $(OBJD)\zlib\deflate.obj  \
    $(OBJD)\zlib\gzclose.obj  \
    $(OBJD)\zlib\gzlib.obj    \
    $(OBJD)\zlib\gzread.obj   \
    $(OBJD)\zlib\gzwrite.obj  \
    $(OBJD)\zlib\infback.obj  \
    $(OBJD)\zlib\inflate.obj  \
    $(OBJD)\zlib\inftrees.obj \
    $(OBJD)\zlib\inffast.obj  \
    $(OBJD)\zlib\trees.obj    \
    $(OBJD)\zlib\uncompr.obj  \
    $(OBJD)\zlib\zutil.obj    \

#disable asm
!if "$(BITS)" == "32"
# optional build flags
AS = ml
ASFLAGS = -coff $(ASFLAGS)
#LOC = -DASMV -DASMINF
#OBJS = $(OBJS) $(OBJD)\zlib\inffas32.obj $(OBJD)\zlib\match686.obj
!else
AS = ml64
#LOC = -DASMV -DASMINF -I.
#OBJS = $(OBJS) $(OBJD)\zlib\inffasx64.obj $(OBJD)\zlib\gvmat64.obj $(OBJD)\zlib\inffas8664.obj
!endif

# targets
all: dirs $(STATICLIB) \
     $(INCD)\zlib.h    \
     $(INCD)\zconf.h   \

dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(OBJD)\zlib" mkdir "$(OBJD)\zlib" && echo.   Created "$(OBJD)\zlib"
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(OBJS)
	$(AR) $(ARFLAGS) -out:$@ $(OBJS)

{$(TOP)}.c{$(OBJD)\zlib}.obj:
	$(CC) -c $(CFLAGS) -Fo$(OBJD)\zlib\ $<

{$(TOP)/asm/masmx64}.c{$(OBJD)\zlib}.obj:
	$(CC) -c $(CFLAGS) -Fo$(OBJD)\zlib\ $<

{$(TOP)/asm/masmx64}.asm{$(OBJD)\zlib}.obj:
	$(AS) -c $(ASFLAGS) -Fo$(OBJD)\zlib\ $<

{$(TOP)/asm/masmx86}.asm{$(OBJD)\zlib}.obj:
	$(AS) -c $(ASFLAGS) -Fo$(OBJD)\zlib\ $<

$(INCD)\zlib.h : src\zlib.h
    @copy src\zlib.h $@ /y

$(INCD)\zconf.h : src\zconf.h
    @copy src\zconf.h $@ /y

$(OBJD)\zlib\adler32.obj: $(TOP)/adler32.c $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\zlib\compress.obj: $(TOP)/compress.c $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\zlib\crc32.obj: $(TOP)/crc32.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/crc32.h

$(OBJD)\zlib\deflate.obj: $(TOP)/deflate.c $(TOP)/deflate.h $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\zlib\gzclose.obj: $(TOP)/gzclose.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/gzguts.h

$(OBJD)\zlib\gzlib.obj: $(TOP)/gzlib.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/gzguts.h

$(OBJD)\zlib\gzread.obj: $(TOP)/gzread.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/gzguts.h

$(OBJD)\zlib\gzwrite.obj: $(TOP)/gzwrite.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/gzguts.h

$(OBJD)\zlib\infback.obj: $(TOP)/infback.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/inftrees.h $(TOP)/inflate.h \
                          $(TOP)/inffast.h $(TOP)/inffixed.h

$(OBJD)\zlib\inffast.obj: $(TOP)/inffast.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/inftrees.h $(TOP)/inflate.h \
                          $(TOP)/inffast.h

$(OBJD)\zlib\inflate.obj: $(TOP)/inflate.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/inftrees.h $(TOP)/inflate.h \
                          $(TOP)/inffast.h $(TOP)/inffixed.h

$(OBJD)\zlib\inftrees.obj: $(TOP)/inftrees.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/inftrees.h

$(OBJD)\zlib\trees.obj: $(TOP)/trees.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/deflate.h $(TOP)/trees.h

$(OBJD)\zlib\uncompr.obj: $(TOP)/uncompr.c $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\zlib\zutil.obj: $(TOP)/zutil.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\zlib\gvmat64.obj: $(TOP)/asm/masmx64/gvmat64.asm

$(OBJD)\zlib\inffasx64.obj: $(TOP)/asm/masmx64/inffasx64.asm

$(OBJD)\zlib\inffas8664.obj: $(TOP)/asm/masmx64/inffas8664.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h \
                             $(TOP)/inftrees.h $(TOP)/inflate.h $(TOP)/inffast.h

$(OBJD)\zlib\inffas32.obj: $(TOP)/asm/masmx86/inffas32.asm

$(OBJD)\zlib\match686.obj: $(TOP)/asm/masmx86/match686.asm

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(OBJS) 2>nul
	-del /q $(INCD)\zlib.h 2>nul
	-del /q $(INCD)\zconf.h 2>nul
	-rd  /s /q "$(OBJD)\zlib" 2>nul
