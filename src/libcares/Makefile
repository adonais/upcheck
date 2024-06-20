# ------------------------------------------------NMAKE----------------------------------------------------------

NAME = cares
MY_NO_UNICODE = true

# ------------------------------------------------
# c-ares static and dynamic libraries common base
# file names for release and debug configurations
# ------------------------------------------------

ROOT = ..\..
!include "$(ROOT)\system.mak"

# --------------------------
# Runtime library selection
# --------------------------
CARES_OBJDIR = $(OBJD)\libcares
STATICLIB = $(BIND)\lib$(NAME).lib
CFLAGS = -nologo -I. -Iinclude -W3 -EHsc -O2 -Zi -Fd"$(BIND)\libcares" -DCARES_BUILDING_LIBRARY \
         -DCARES_STATICLIB -D_WIN32_WINNT=0x0600 -DHAVE_INET_NTOP -DHAVE_INET_PTON $(CFLAGS) 
!if "$(APP_DEBUG)"=="1"
CFLAGS = $(CFLAGS) $(DEBUG_L)
!ELSE
CFLAGS = $(CFLAGS) $(RELEASE)
!ENDIF
# ----------------------------------------
# Subdir holding sources for all projects
# ----------------------------------------

SRCDIR = .\src

# -------------------------------------------------
# Switches that depend on ancient compiler versions
# -------------------------------------------------

!IF $(CC_VERS_NUM) == 60
PDB_NONE            = -pdb:none
PDBTYPE_CONSOLIDATE = -pdbtype:consolidate
!ELSE
!UNDEF PDB_NONE
!UNDEF PDBTYPE_CONSOLIDATE
!ENDIF

!IF $(CC_VERS_NUM) <= 70
RT_ERROR_CHECKING = -GZ
!ELSE
RT_ERROR_CHECKING = -RTCsu
!ENDIF

# --------------------------------------------
# Makefile.inc provides lists of source files
# --------------------------------------------

!INCLUDE $(SRCDIR)\Makefile.inc

!IF [ECHO CARES_OBJS=^$(CARES_OBJDIR)\$(CSOURCES: = $(CARES_OBJDIR^)\) > .\cares_objs.inc] == 0
!INCLUDE .\cares_objs.inc
!IF [DEL .\cares_objs.inc]
!ENDIF
!ELSE
!ERROR Problem generating CARES_OBJS list.
!ENDIF
CARES_OBJS = $(CARES_OBJS:.c=.obj)

# --------------------------------
# Only our custom inference rules
# --------------------------------

.SUFFIXES:
.SUFFIXES: .c

{$(SRCDIR)}.c{$(CARES_OBJDIR)}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<

# ---------------------------------------------------------------------
# Targets only available when a proper CFG library type has been given
# ---------------------------------------------------------------------

all: dirs $(STATICLIB)      \
     $(INCD)\ares.h         \
     
dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(CARES_OBJDIR)" mkdir "$(CARES_OBJDIR)" && echo.   Created $(CARES_OBJDIR)
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(CARES_OBJS)
	$(AR) $(ARFLAGS) -out:$@ $(CARES_OBJS)
	
$(INCD)\ares.h : include\ares.h
	@copy include\*.h $(INCD)\ /y

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(CARES_OBJDIR)\*.pdb 2>nul
	-del /q $(CARES_OBJDIR)\*.idb 2>nul
	-del /q $(CARES_OBJDIR)\*.obj 2>nul
	-del /q $(CARES_OBJDIR)\*.res 2>nul
	-del /q $(INCD)\ares.h 2>nul
	-del /q $(INCD)\ares_build.h 2>nul
	-del /q $(INCD)\ares_rules.h 2>nul
	-del /q $(INCD)\ares_dns.h 2>nul
	-del /q $(INCD)\ares_nameser.h 2>nul
	-del /q $(INCD)\ares_version.h 2>nul
	-rd  /s /q "$(CARES_OBJDIR)" 2>nul
