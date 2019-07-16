# -----------------------------------------------
# Detect NMAKE version deducing old MSVC versions
# -----------------------------------------------

!IFNDEF _NMAKE_VER
!  MESSAGE Macro _NMAKE_VER not defined.
!  MESSAGE Use MSVC's NMAKE to process this makefile.
!  ERROR   See previous message.
!ENDIF

!IF     "$(_NMAKE_VER)" == "6.00.8168.0"
CC_VERS_NUM = 60
!ELSEIF "$(_NMAKE_VER)" == "6.00.9782.0"
CC_VERS_NUM = 60
!ELSEIF "$(_NMAKE_VER)" == "7.00.8882"
CC_VERS_NUM = 70
!ELSEIF "$(_NMAKE_VER)" == "7.00.9466"
CC_VERS_NUM = 70
!ELSEIF "$(_NMAKE_VER)" == "7.00.9955"
CC_VERS_NUM = 70
!ELSEIF "$(_NMAKE_VER)" == "14.13.26132.0"
CC_VERS_NUM = 140
!ELSE
# Pick an arbitrary bigger number for all later versions
CC_VERS_NUM = 199
!ENDIF

!if "$(PLATFORM)"=="X64" || "$(TARGET_CPU)"=="x64" || "$(VSCMD_ARG_HOST_ARCH)"=="x64"
PLATFORM = X64
BITS	 = 64
!else
PLATFORM = X86
BITS	 = 32
!endif

!IF "$(PLATFORM)" == "X64"
#!MESSAGE Building for 64-bit X64.
CFLAGS   = $(CFLAGS) /DWIN64 /D_WIN64 /favor:blend /I$(INCD)
!ELSEIF "$(PLATFORM)" == "X86"
#!MESSAGE Building for 32-bit X86.
CFLAGS   = $(CFLAGS) /DWIN32 /D_WIN32 /I$(INCD)
!ELSE
!ERROR Unknown target processor: $(PLATFORM)
!ENDIF

!IFNDEF MY_NO_UNICODE
CFLAGS = $(CFLAGS) /D_UNICODE /DUNICODE
!ENDIF 

XPCFLAGS = /D "_USING_V110_SDK71_"
XPLFALGS = /subsystem:console,5.01
RELEASE  = /D "NDEBUG"
DEBUG_L  = /D "DEBUG" /D "DEBUG_LOG"
HIDE     = /subsystem:windows

##############################################################################
##
INCD  = $(ROOT)\include
BIND  = $(ROOT)\Release
OBJD  = $(ROOT)\.dep
