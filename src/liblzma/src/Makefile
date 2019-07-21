NAME = 7z
SRCDIR = .

ROOT = ..\..\..
!include "$(ROOT)\system.mak"

STATICLIB = $(BIND)\lib$(NAME).lib

CFLAGS = -nologo -c -W4 -WX -TC -Gy -GR- -GF -MT -GS- -Zc:forScope -Zc:wchar_t -MP2 \
         -O2 -D_7ZIP_PPMD_SUPPPORT -Zi -Fd"$(BIND)\lib7z" $(CFLAGS) 

OBJS = \
  $(OBJD)\7zAlloc.obj  \
  $(OBJD)\7zBuf.obj    \
  $(OBJD)\7zCrc.obj    \
  $(OBJD)\7zCrcOpt.obj \
  $(OBJD)\7zFile.obj   \
  $(OBJD)\7zDec.obj    \
  $(OBJD)\7zArcIn.obj  \
  $(OBJD)\7zStream.obj \
  $(OBJD)\Bcj2.obj     \
  $(OBJD)\Bra.obj      \
  $(OBJD)\Bra86.obj    \
  $(OBJD)\BraIA64.obj  \
  $(OBJD)\CpuArch.obj  \
  $(OBJD)\Delta.obj    \
  $(OBJD)\Lzma2Dec.obj \
  $(OBJD)\LzmaDec.obj  \
  $(OBJD)\Ppmd7.obj    \
  $(OBJD)\Ppmd7Dec.obj \

{$(SRCDIR)}.c{$(OBJD)}.obj:
    cl $(CFLAGS) /Fo$@ /c $<

# ---------------------------------------------------------------------
# Targets only available
# ---------------------------------------------------------------------

all: dirs $(STATICLIB)      \
     $(INCD)\7z.h           \
     
dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(OBJS)
	link -lib -nologo -out:$@ $(OBJS)
	
$(INCD)\7z.h : $(SRCDIR)\7z.h
    @copy $(SRCDIR)\*.h $(INCD)\ /y
    
$(OBJS): *.c *.h

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(BIND)\*.pdb 2>nul
	-del /q $(BIND)\*.idb 2>nul
	-del /q $(OBJD)\*.obj 2>nul
	-del /q $(INCD)\*.h 2>nul
	-del /q $(OBJD)\*.res 2>nul
