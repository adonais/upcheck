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

!IF "$(PLATFORM)"=="x64" || "$(TARGET_CPU)"=="x64" || "$(VSCMD_ARG_HOST_ARCH)"=="x64"
BITS	 = 64
CFLAGS   = $(CFLAGS) /DWIN64 /D_WIN64 /I$(INCD)
!IF "$(CC)" == "cl"
CFLAGS   = $(CFLAGS) /favor:blend
!ENDIF
!ELSEIF "$(PLATFORM)"=="x86"
BITS	 = 32
CFLAGS   = $(CFLAGS) /DWIN32 /D_WIN32 /I$(INCD)
!ELSE
!ERROR Unknown target processor: $(PLATFORM)
!ENDIF

!IF "$(CC)" == "cl"
AR   = lib /nologo 
LD   = link /nologo
!ELSEIF "$(CC)" == "clang-cl"
AR   = llvm-lib /nologo /llvmlibthin
LD   = lld-link /nologo
CFLAGS   = -flto=thin $(CFLAGS) -Wno-unused-variable -Wno-unused-function \
           -Wno-incompatible-pointer-types
!IF "$(BITS)" == "32"
CFLAGS   = --target=i686-pc-windows-msvc $(CFLAGS) 
!ENDIF
!ELSE
!ERROR Unknown compiler
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
