# Makefile for zlib using Microsoft (Visual) C
# zlib is copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler
#
# The toplevel directory of the source tree.
#
ROOT = ..\..\..
!include "$(ROOT)\system.mak"

TOP = .

# variables
STATICLIB = $(BIND)\zlib.lib

CC = cl
LD = link
AR = lib
RC = rc
CFLAGS  = -nologo -MT -W3 -O2 -Oy- -Zi -Fd"$(BIND)\zlib" -I../include $(LOC)
WFLAGS  = -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE
ASFLAGS = -Zi $(LOC)
LDFLAGS = -nologo -debug -incremental:no -opt:ref
ARFLAGS = -nologo
RCFLAGS = /dWIN32 /r

OBJS = \
    $(OBJD)\adler32.obj  \
    $(OBJD)\compress.obj \
    $(OBJD)\crc32.obj    \
    $(OBJD)\deflate.obj  \
    $(OBJD)\gzclose.obj  \
    $(OBJD)\gzlib.obj    \
    $(OBJD)\gzread.obj   \
    $(OBJD)\gzwrite.obj  \
    $(OBJD)\infback.obj  \
    $(OBJD)\inflate.obj  \
    $(OBJD)\inftrees.obj \
    $(OBJD)\inffast.obj  \
    $(OBJD)\trees.obj    \
    $(OBJD)\uncompr.obj  \
    $(OBJD)\zutil.obj    \

!if "$(BITS)" == "32"
# optional build flags
AS = ml
ASFLAGS = -coff $(ASFLAGS)
LOC = -DASMV -DASMINF
OBJS = $(OBJS) $(OBJD)\inffas32.obj $(OBJD)\match686.obj
!else
AS = ml64
LOC = -DASMV -DASMINF -I.
OBJS = $(OBJS) $(OBJD)\inffasx64.obj $(OBJD)\gvmat64.obj $(OBJD)\inffas8664.obj
!endif

# targets
all: dirs $(STATICLIB) \
     $(INCD)\zlib.h    \
     $(INCD)\zconf.h   \

dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(OBJS)
	$(AR) $(ARFLAGS) -out:$@ $(OBJS)

{$(TOP)}.c{$(OBJD)}.obj:
	$(CC) -c $(WFLAGS) $(CFLAGS) /Fo$(OBJD)\ $<

{$(TOP)/asm/masmx64}.c{$(OBJD)}.obj:
	$(CC) -c $(WFLAGS) $(CFLAGS) /Fo$(OBJD)\ $<

{$(TOP)/asm/masmx64}.asm{$(OBJD)}.obj:
	$(AS) -c $(ASFLAGS) /Fo$(OBJD)\ $<

{$(TOP)/asm/masmx86}.asm{$(OBJD)}.obj:
	$(AS) -c $(ASFLAGS) /Fo$(OBJD)\ $<
	
$(INCD)\zlib.h : zlib.h
    @copy zlib.h $@ /y

$(INCD)\zconf.h : zconf.h
    @copy zconf.h $@ /y

$(OBJD)\adler32.obj: $(TOP)/adler32.c $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\compress.obj: $(TOP)/compress.c $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\crc32.obj: $(TOP)/crc32.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/crc32.h

$(OBJD)\deflate.obj: $(TOP)/deflate.c $(TOP)/deflate.h $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\gzclose.obj: $(TOP)/gzclose.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/gzguts.h

$(OBJD)\gzlib.obj: $(TOP)/gzlib.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/gzguts.h

$(OBJD)\gzread.obj: $(TOP)/gzread.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/gzguts.h

$(OBJD)\gzwrite.obj: $(TOP)/gzwrite.c $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/gzguts.h

$(OBJD)\infback.obj: $(TOP)/infback.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/inftrees.h $(TOP)/inflate.h \
             $(TOP)/inffast.h $(TOP)/inffixed.h

$(OBJD)\inffast.obj: $(TOP)/inffast.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/inftrees.h $(TOP)/inflate.h \
             $(TOP)/inffast.h

$(OBJD)\inflate.obj: $(TOP)/inflate.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/inftrees.h $(TOP)/inflate.h \
             $(TOP)/inffast.h $(TOP)/inffixed.h

$(OBJD)\inftrees.obj: $(TOP)/inftrees.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/inftrees.h

$(OBJD)\trees.obj: $(TOP)/trees.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h $(TOP)/deflate.h $(TOP)/trees.h

$(OBJD)\uncompr.obj: $(TOP)/uncompr.c $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\zutil.obj: $(TOP)/zutil.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h

$(OBJD)\gvmat64.obj: $(TOP)/asm\masmx64\gvmat64.asm

$(OBJD)\inffasx64.obj: $(TOP)/asm\masmx64\inffasx64.asm

$(OBJD)\inffas8664.obj: $(TOP)/asm\masmx64\inffas8664.c $(TOP)/zutil.h $(TOP)/zlib.h $(TOP)/zconf.h \
		                $(TOP)/inftrees.h $(TOP)/inflate.h $(TOP)/inffast.h

$(OBJD)\inffas32.obj: $(TOP)/asm\masmx86\inffas32.asm

$(OBJD)\match686.obj: $(TOP)/asm\masmx86\match686.asm

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(BIND)\*.pdb 2>nul
	-del /q $(OBJD)\*.obj 2>nul
	-del /q $(OBJD)\*.res 2>nul
	-del /q $(INCD)\zlib.h 2>nul
	-del /q $(INCD)\zconf.h 2>nul
