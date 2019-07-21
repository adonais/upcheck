# ------------------------------------------------NMAKE----------------------------------------------------------

NAME = cares

# ------------------------------------------------
# c-ares static and dynamic libraries common base
# file names for release and debug configurations
# ------------------------------------------------

ROOT = ..\..\..
!include "$(ROOT)\system.mak"

# --------------------------
# Runtime library selection
# --------------------------

STATICLIB = $(BIND)\lib$(NAME).lib
CFLAGS = /nologo /I. /W3 /EHsc /FD /DNDEBUG /O2 /Zi -Fd"$(BIND)\libcares" /DCARES_BUILDING_LIBRARY \
         /DCARES_STATICLIB /D_WIN32_WINNT=0x0600 -DHAVE_INET_NTOP -DHAVE_INET_PTON $(CFLAGS) 
RC_CMD_REL = rc.exe /l 0x409 /d "NDEBUG"
LINK_CMD_LIB = link.exe /lib /nologo

# ----------------------------------------
# Subdir holding sources for all projects
# ----------------------------------------

SRCDIR = .

# -------------------------------------------------
# Switches that depend on ancient compiler versions
# -------------------------------------------------

!IF $(CC_VERS_NUM) == 60
PDB_NONE            = /pdb:none
PDBTYPE_CONSOLIDATE = /pdbtype:consolidate
!ELSE
!UNDEF PDB_NONE
!UNDEF PDBTYPE_CONSOLIDATE
!ENDIF

!IF $(CC_VERS_NUM) <= 70
RT_ERROR_CHECKING = /GZ
!ELSE
RT_ERROR_CHECKING = /RTCsu
!ENDIF

# ----------------------------
# Build lists of object files
# ----------------------------

OBJS = \
    $(OBJD)\ares__close_sockets.obj     \
    $(OBJD)\ares__get_hostent.obj		\
    $(OBJD)\ares__read_line.obj		    \
    $(OBJD)\ares__timeval.obj			\
    $(OBJD)\ares_android.obj			\
    $(OBJD)\ares_cancel.obj			    \
    $(OBJD)\ares_data.obj				\
    $(OBJD)\ares_destroy.obj			\
    $(OBJD)\ares_expand_name.obj		\
    $(OBJD)\ares_expand_string.obj	    \
    $(OBJD)\ares_fds.obj				\
    $(OBJD)\ares_free_hostent.obj		\
    $(OBJD)\ares_free_string.obj		\
    $(OBJD)\ares_getenv.obj			    \
    $(OBJD)\ares_gethostbyaddr.obj	    \
    $(OBJD)\ares_gethostbyname.obj	    \
    $(OBJD)\ares_getnameinfo.obj		\
    $(OBJD)\ares_getsock.obj			\
    $(OBJD)\ares_init.obj				\
    $(OBJD)\ares_library_init.obj		\
    $(OBJD)\ares_llist.obj			    \
    $(OBJD)\ares_mkquery.obj			\
    $(OBJD)\ares_create_query.obj		\
    $(OBJD)\ares_nowarn.obj			    \
    $(OBJD)\ares_options.obj			\
    $(OBJD)\ares_parse_a_reply.obj	    \
    $(OBJD)\ares_parse_aaaa_reply.obj	\
    $(OBJD)\ares_parse_mx_reply.obj	    \
    $(OBJD)\ares_parse_naptr_reply.obj  \
    $(OBJD)\ares_parse_ns_reply.obj	    \
    $(OBJD)\ares_parse_ptr_reply.obj	\
    $(OBJD)\ares_parse_soa_reply.obj	\
    $(OBJD)\ares_parse_srv_reply.obj	\
    $(OBJD)\ares_parse_txt_reply.obj	\
    $(OBJD)\ares_platform.obj			\
    $(OBJD)\ares_process.obj			\
    $(OBJD)\ares_query.obj			    \
    $(OBJD)\ares_search.obj			    \
    $(OBJD)\ares_send.obj				\
    $(OBJD)\ares_strcasecmp.obj		    \
    $(OBJD)\ares_strdup.obj			    \
    $(OBJD)\ares_strerror.obj			\
    $(OBJD)\ares_strsplit.obj			\
    $(OBJD)\ares_timeout.obj			\
    $(OBJD)\ares_version.obj			\
    $(OBJD)\ares_writev.obj			    \
    $(OBJD)\bitncmp.obj				    \
    $(OBJD)\inet_net_pton.obj			\
    $(OBJD)\inet_ntop.obj				\
    $(OBJD)\windows_port.obj            \

CSOURCES = \
  ares__close_sockets.c	    \
  ares__get_hostent.c		\
  ares__read_line.c			\
  ares__timeval.c			\
  ares_android.c			\
  ares_cancel.c				\
  ares_data.c				\
  ares_destroy.c			\
  ares_expand_name.c		\
  ares_expand_string.c		\
  ares_fds.c				\
  ares_free_hostent.c		\
  ares_free_string.c		\
  ares_getenv.c				\
  ares_gethostbyaddr.c		\
  ares_gethostbyname.c		\
  ares_getnameinfo.c		\
  ares_getsock.c			\
  ares_init.c				\
  ares_library_init.c		\
  ares_llist.c				\
  ares_mkquery.c			\
  ares_create_query.c		\
  ares_nowarn.c				\
  ares_options.c			\
  ares_parse_a_reply.c		\
  ares_parse_aaaa_reply.c	\
  ares_parse_mx_reply.c		\
  ares_parse_naptr_reply.c	\
  ares_parse_ns_reply.c		\
  ares_parse_ptr_reply.c	\
  ares_parse_soa_reply.c	\
  ares_parse_srv_reply.c	\
  ares_parse_txt_reply.c	\
  ares_platform.c			\
  ares_process.c			\
  ares_query.c				\
  ares_search.c				\
  ares_send.c				\
  ares_strcasecmp.c			\
  ares_strdup.c				\
  ares_strerror.c			\
  ares_strsplit.c			\
  ares_timeout.c			\
  ares_version.c			\
  ares_writev.c				\
  bitncmp.c				    \
  inet_net_pton.c			\
  inet_ntop.c				\
  windows_port.c

HHEADERS = ares.h		   \
  ares_android.h            \
  ares_build.h				\
  ares_data.h				\
  ares_dns.h				\
  ares_getenv.h				\
  ares_inet_net_pton.h		\
  ares_iphlpapi.h			\
  ares_ipv6.h				\
  ares_library_init.h		\
  ares_llist.h				\
  ares_nowarn.h				\
  ares_platform.h			\
  ares_private.h			\
  ares_rules.h				\
  ares_strcasecmp.h			\
  ares_strdup.h				\
  ares_strsplit.h			\
  ares_version.h			\
  ares_writev.h				\
  bitncmp.h				    \
  nameser.h				    \
  ares_setup.h				\
  setup_once.h              \
  
# --------------------------------
# Only our custom inference rules
# --------------------------------

.SUFFIXES:
.SUFFIXES: .c .rc

{$(SRCDIR)}.rc{$(OBJD)}.res:
    $(RC_CMD) /Fo $@ $<

{$(SRCDIR)}.c{$(OBJD)}.obj:
    cl $(CFLAGS) /Fo$@ /c $<

# ---------------------------------------------------------------------
# Targets only available when a proper CFG library type has been given
# ---------------------------------------------------------------------

all: dirs $(STATICLIB)      \
     $(INCD)\ares.h         \
     $(INCD)\ares_build.h   \
     $(INCD)\ares_rules.h   \
     $(INCD)\ares_version.h \
     
dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(OBJS)
	$(LINK_CMD_LIB) $(ARFLAGS) -out:$@ $(OBJS)
	
$(INCD)\ares.h : ares.h
    @copy ares.h $@ /y

$(INCD)\ares_build.h : ares_build.h
    @copy ares_build.h $@ /y
    
$(INCD)\ares_rules.h : ares_rules.h
    @copy ares_rules.h $@ /y

$(INCD)\ares_version.h : ares_version.h
    @copy ares_version.h $@ /y    
    
$(OBJS): $(CSOURCES) $(HHEADERS)

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(BIND)\*.pdb 2>nul
	-del /q $(BIND)\*.idb 2>nul
	-del /q $(OBJD)\*.obj 2>nul
	-del /q $(OBJD)\*.res 2>nul
	-del /q $(INCD)\ares.h 2>nul
	-del /q $(INCD)\ares_build.h 2>nul
	-del /q $(INCD)\ares_rules.h 2>nul
	-del /q $(INCD)\ares_version.h 2>nul
