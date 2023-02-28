NAME = 7z
SRCDIR = .\src

ROOT = ..\..
!include "$(ROOT)\system.mak"

STATICLIB = $(BIND)\lib$(NAME).lib

CFLAGS = -nologo -c -W4 -WX -TC -Gy -GR- -GF -GS- -Zc:forScope -Zc:wchar_t \
         -O2 -D_7ZIP_PPMD_SUPPPORT -Isrc -Zi -Fd"$(BIND)\lib7z" $(CFLAGS)
!if "$(APP_DEBUG)"=="1"
CFLAGS = $(CFLAGS) $(DEBUG_L)
!ELSE
CFLAGS = $(CFLAGS) $(RELEASE)
!ENDIF
OBJS = \
  $(OBJD)\liblzma\7zAlloc.obj  \
  $(OBJD)\liblzma\7zBuf.obj    \
  $(OBJD)\liblzma\7zCrc.obj    \
  $(OBJD)\liblzma\7zCrcOpt.obj \
  $(OBJD)\liblzma\7zFile.obj   \
  $(OBJD)\liblzma\7zDec.obj    \
  $(OBJD)\liblzma\7zArcIn.obj  \
  $(OBJD)\liblzma\7zStream.obj \
  $(OBJD)\liblzma\Bcj2.obj     \
  $(OBJD)\liblzma\Bra.obj      \
  $(OBJD)\liblzma\Bra86.obj    \
  $(OBJD)\liblzma\BraIA64.obj  \
  $(OBJD)\liblzma\CpuArch.obj  \
  $(OBJD)\liblzma\Delta.obj    \
  $(OBJD)\liblzma\Lzma2Dec.obj \
  $(OBJD)\liblzma\LzmaDec.obj  \
  $(OBJD)\liblzma\Ppmd7.obj    \
  $(OBJD)\liblzma\Ppmd7Dec.obj \

{$(SRCDIR)}.c{$(OBJD)\liblzma}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<

# ---------------------------------------------------------------------
# Targets only available
# ---------------------------------------------------------------------

all: dirs $(STATICLIB)      \
     $(INCD)\7z.h           \
     
dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(OBJD)\liblzma" mkdir "$(OBJD)\liblzma" && echo.   Created $(OBJD)\liblzma
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(OBJS)
	$(AR) -out:$@ $(OBJS)

$(INCD)\7z.h : $(SRCDIR)\7z.h
	@copy $(SRCDIR)\*.h $(INCD)\ /y

$(OBJS): $(SRCDIR)\*.c $(SRCDIR)\*.h

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(BIND)\*.pdb 2>nul
	-del /q $(BIND)\*.idb 2>nul
	-del /q $(INCD)\*.h 2>nul
	-del /q $(OBJD)\liblzma\*.obj 2>nul
	-del /q $(OBJD)\liblzma\*.res 2>nul
	-rd  /s /q "$(OBJD)\liblzma" 2>nul
