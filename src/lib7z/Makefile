NAME = 7z
SRCDIR = .\C

ROOT = ..\..
!include "$(ROOT)\system.mak"

STATICLIB = $(BIND)\$(NAME).lib

CFLAGS = -nologo -c -W4 -WX -TC -Gy -GR- -GF -GS- -Zc:forScope -Zc:wchar_t \
         -O2 -DZ7_PPMD_SUPPORT -DZ7_EXTRACT_ONLY -Zi -Fd"$(BIND)\7z" $(CFLAGS)
!if "$(APP_DEBUG)"=="1"
CFLAGS = $(CFLAGS) $(DEBUG_L)
!ELSE
CFLAGS = $(CFLAGS) $(RELEASE)
!ENDIF
OBJS = \
  $(OBJD)\lib7z\7zCrcOpt.obj   \
  $(OBJD)\lib7z\XzCrc64Opt.obj \
  $(OBJD)\lib7z\Sha1Opt.obj    \
  $(OBJD)\lib7z\Sha256Opt.obj  \
  $(OBJD)\lib7z\AesOpt.obj     \
  $(OBJD)\lib7z\7zAlloc.obj    \
  $(OBJD)\lib7z\7zBuf.obj      \
  $(OBJD)\lib7z\7zCrc.obj      \
  $(OBJD)\lib7z\7zFile.obj     \
  $(OBJD)\lib7z\7zDec.obj      \
  $(OBJD)\lib7z\7zArcIn.obj    \
  $(OBJD)\lib7z\7zStream.obj   \
  $(OBJD)\lib7z\Bcj2.obj       \
  $(OBJD)\lib7z\Bra.obj        \
  $(OBJD)\lib7z\Bra86.obj      \
  $(OBJD)\lib7z\BraIA64.obj    \
  $(OBJD)\lib7z\CpuArch.obj    \
  $(OBJD)\lib7z\Delta.obj      \
  $(OBJD)\lib7z\Lzma2Dec.obj   \
  $(OBJD)\lib7z\LzmaDec.obj    \
  $(OBJD)\lib7z\Ppmd7.obj      \
  $(OBJD)\lib7z\Ppmd7Dec.obj   \

{$(SRCDIR)}.c{$(OBJD)\lib7z}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<

# ---------------------------------------------------------------------
# Targets only available
# ---------------------------------------------------------------------

all: dirs $(STATICLIB)      \
     $(INCD)\7z.h           \
     
dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(OBJD)\lib7z" mkdir "$(OBJD)\lib7z" && echo.   Created $(OBJD)\lib7z
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
	-del /q $(OBJD)\lib7z\*.obj 2>nul
	-del /q $(OBJD)\lib7z\*.res 2>nul
	-rd  /s /q "$(OBJD)\lib7z" 2>nul
