CC       := gcc 
CFLAGS   = -O2 -I. $(shell pkg-config --cflags libcurl libarchive sqlite3 luajit)
LD       = $(CC) -o
AR       ?= ar

RC_TAR32 = -F pe-i386
RC_TAR64 = -F pe-x86-64
USE_GCC  =
OUT      = $(BIND)/upcheck

ifeq ($(findstring clang,$(CC)),)
USE_GCC  = 1
endif

BUILD    = $(shell file `which $(CC) 2>/dev/null` 2>/dev/null | grep x86-64)

ifeq ($(BUILD),)
BITS	 = 32
else
BITS	 = 64
endif

DEL      = rm -f
RD      =  rm -fr
MD       = mkdir -p
CP       = cp

##############################################################################
RELEASE  = -D "NDEBUG"
DEBUG_L  = -D "DEBUG" -D "APP_DEBUG"

ifeq ($(ROOT),)
ROOT     = .
endif

INCD     = $(ROOT)/include
BIND     = $(ROOT)/release
OBJD     = $(ROOT)/dep
