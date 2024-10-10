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
CFLAGS = -nologo -I. -Iinclude -Isrc\include -W3 -EHsc -O2 -Zi -Fd"$(BIND)\libcares" -DCARES_BUILDING_LIBRARY \
         -DCARES_STATICLIB -DHAVE_INET_NTOP -DHAVE_INET_PTON $(CFLAGS) 
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
CARES_OBJS = $(CARES_OBJS:/=\)

# --------------------------------
# Only our custom inference rules
# --------------------------------

.SUFFIXES:
.SUFFIXES: .c

{$(SRCDIR)}.c{$(CARES_OBJDIR)}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<

{$(SRCDIR)\dsa}.c{$(CARES_OBJDIR)\dsa}.obj:
    $(CC) $(CFLAGS) -I$(SRCDIR) -Fo$@ -c $<

{$(SRCDIR)\event}.c{$(CARES_OBJDIR)\event}.obj:
    $(CC) $(CFLAGS) -I$(SRCDIR)  -Fo$@ -c $<

{$(SRCDIR)\legacy}.c{$(CARES_OBJDIR)\legacy}.obj:
    $(CC) $(CFLAGS) -I$(SRCDIR)  -Fo$@ -c $<

{$(SRCDIR)\record}.c{$(CARES_OBJDIR)\record}.obj:
    $(CC) $(CFLAGS) -I$(SRCDIR)  -Fo$@ -c $<

{$(SRCDIR)\str}.c{$(CARES_OBJDIR)\str}.obj:
    $(CC) $(CFLAGS) -I$(SRCDIR)  -Fo$@ -c $<

{$(SRCDIR)\util}.c{$(CARES_OBJDIR)\util}.obj:
    $(CC) $(CFLAGS) -I$(SRCDIR)  -Fo$@ -c $<

# ---------------------------------------------------------------------
# Targets only available when a proper CFG library type has been given
# ---------------------------------------------------------------------

all: dirs $(STATICLIB)      \
     $(INCD)\ares.h         \
     
dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(CARES_OBJDIR)" mkdir "$(CARES_OBJDIR)" && echo.   Created $(CARES_OBJDIR)
    @if not exist "$(CARES_OBJDIR)\dsa" mkdir "$(CARES_OBJDIR)\dsa" && echo.   Created $(CARES_OBJDIR)\dsa
    @if not exist "$(CARES_OBJDIR)\event" mkdir "$(CARES_OBJDIR)\event" && echo.   Created $(CARES_OBJDIR)\event
    @if not exist "$(CARES_OBJDIR)\legacy" mkdir "$(CARES_OBJDIR)\legacy" && echo.   Created $(CARES_OBJDIR)\legacy
    @if not exist "$(CARES_OBJDIR)\record" mkdir "$(CARES_OBJDIR)\record" && echo.   Created $(CARES_OBJDIR)\record
    @if not exist "$(CARES_OBJDIR)\str" mkdir "$(CARES_OBJDIR)\str" && echo.   Created $(CARES_OBJDIR)\str
    @if not exist "$(CARES_OBJDIR)\thirdparty" mkdir "$(CARES_OBJDIR)\thirdparty" && echo.   Created $(CARES_OBJDIR)\thirdparty
    @if not exist "$(CARES_OBJDIR)\util" mkdir "$(CARES_OBJDIR)\util" && echo.   Created $(CARES_OBJDIR)\util
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(CARES_OBJS)
	$(AR) $(ARFLAGS) -out:$@ $(CARES_OBJS)
	
$(INCD)\ares.h : include\ares.h
	@copy include\*.h $(INCD)\ /y

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul 2>nul
	-del /q $(BIND)\*.pdb 2>nul
	-del /q $(CARES_OBJDIR)\*.pdb 2>nul
	-del /q $(CARES_OBJDIR)\*.idb 2>nul
	-del /q $(CARES_OBJDIR)\*.obj 2>nul
	-del /q $(CARES_OBJDIR)\*.res 2>nul
	-del /q $(INCD)\ares.h 2>nul
	-del /q $(INCD)\ares_build.h 2>nul
	-del /q $(INCD)\ares_dns.h 2>nul
	-del /q $(INCD)\ares_dns_record.h 2>nul
	-del /q $(INCD)\ares_nameser.h 2>nul
	-del /q $(INCD)\ares_version.h 2>nul
	-rd  /s /q "$(CARES_OBJDIR)" 2>nul
