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
         -DCARES_STATICLIB -DHAVE_CONFIG_H=1 -DWIN32_LEAN_AND_MEAN -D_CRT_NONSTDC_NO_DEPRECATE -D_CRT_SECURE_NO_DEPRECATE $(CFLAGS)

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
# lists of source files
# --------------------------------------------
CARES_OBJS = \
    $(CARES_OBJDIR)\ares_addrinfo2hostent.obj \
    $(CARES_OBJDIR)\ares_addrinfo_localhost.obj \
    $(CARES_OBJDIR)\ares_android.obj \
    $(CARES_OBJDIR)\ares_cancel.obj \
    $(CARES_OBJDIR)\ares_close_sockets.obj \
    $(CARES_OBJDIR)\ares_conn.obj \
    $(CARES_OBJDIR)\ares_cookie.obj \
    $(CARES_OBJDIR)\ares_data.obj \
    $(CARES_OBJDIR)\ares_destroy.obj \
    $(CARES_OBJDIR)\ares_free_hostent.obj \
    $(CARES_OBJDIR)\ares_free_string.obj \
    $(CARES_OBJDIR)\ares_freeaddrinfo.obj \
    $(CARES_OBJDIR)\ares_getaddrinfo.obj \
    $(CARES_OBJDIR)\ares_getenv.obj \
    $(CARES_OBJDIR)\ares_gethostbyaddr.obj \
    $(CARES_OBJDIR)\ares_gethostbyname.obj \
    $(CARES_OBJDIR)\ares_getnameinfo.obj \
    $(CARES_OBJDIR)\ares_hosts_file.obj \
    $(CARES_OBJDIR)\ares_init.obj \
    $(CARES_OBJDIR)\ares_library_init.obj \
    $(CARES_OBJDIR)\ares_metrics.obj \
    $(CARES_OBJDIR)\ares_options.obj \
    $(CARES_OBJDIR)\ares_parse_into_addrinfo.obj \
    $(CARES_OBJDIR)\ares_process.obj \
    $(CARES_OBJDIR)\ares_qcache.obj \
    $(CARES_OBJDIR)\ares_query.obj \
    $(CARES_OBJDIR)\ares_search.obj \
    $(CARES_OBJDIR)\ares_send.obj \
    $(CARES_OBJDIR)\ares_set_socket_functions.obj \
    $(CARES_OBJDIR)\ares_socket.obj \
    $(CARES_OBJDIR)\ares_sortaddrinfo.obj \
    $(CARES_OBJDIR)\ares_strerror.obj \
    $(CARES_OBJDIR)\ares_sysconfig.obj \
    $(CARES_OBJDIR)\ares_sysconfig_files.obj \
    $(CARES_OBJDIR)\ares_sysconfig_mac.obj \
    $(CARES_OBJDIR)\ares_sysconfig_win.obj \
    $(CARES_OBJDIR)\ares_timeout.obj \
    $(CARES_OBJDIR)\ares_update_servers.obj \
    $(CARES_OBJDIR)\ares_version.obj \
    $(CARES_OBJDIR)\inet_net_pton.obj \
    $(CARES_OBJDIR)\inet_ntop.obj \
    $(CARES_OBJDIR)\windows_port.obj \
    $(CARES_OBJDIR)\dsa/ares_array.obj \
    $(CARES_OBJDIR)\dsa/ares_htable.obj \
    $(CARES_OBJDIR)\dsa/ares_htable_asvp.obj \
    $(CARES_OBJDIR)\dsa/ares_htable_dict.obj \
    $(CARES_OBJDIR)\dsa/ares_htable_strvp.obj \
    $(CARES_OBJDIR)\dsa/ares_htable_szvp.obj \
    $(CARES_OBJDIR)\dsa/ares_htable_vpstr.obj \
    $(CARES_OBJDIR)\dsa/ares_htable_vpvp.obj \
    $(CARES_OBJDIR)\dsa/ares_llist.obj \
    $(CARES_OBJDIR)\dsa/ares_slist.obj \
    $(CARES_OBJDIR)\event/ares_event_configchg.obj \
    $(CARES_OBJDIR)\event/ares_event_epoll.obj \
    $(CARES_OBJDIR)\event/ares_event_kqueue.obj \
    $(CARES_OBJDIR)\event/ares_event_poll.obj \
    $(CARES_OBJDIR)\event/ares_event_select.obj \
    $(CARES_OBJDIR)\event/ares_event_thread.obj \
    $(CARES_OBJDIR)\event/ares_event_wake_pipe.obj \
    $(CARES_OBJDIR)\event/ares_event_win32.obj \
    $(CARES_OBJDIR)\legacy/ares_create_query.obj \
    $(CARES_OBJDIR)\legacy/ares_expand_name.obj \
    $(CARES_OBJDIR)\legacy/ares_expand_string.obj \
    $(CARES_OBJDIR)\legacy/ares_fds.obj \
    $(CARES_OBJDIR)\legacy/ares_getsock.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_a_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_aaaa_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_caa_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_mx_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_naptr_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_ns_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_ptr_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_soa_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_srv_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_txt_reply.obj \
    $(CARES_OBJDIR)\legacy/ares_parse_uri_reply.obj \
    $(CARES_OBJDIR)\record/ares_dns_mapping.obj \
    $(CARES_OBJDIR)\record/ares_dns_multistring.obj \
    $(CARES_OBJDIR)\record/ares_dns_name.obj \
    $(CARES_OBJDIR)\record/ares_dns_parse.obj \
    $(CARES_OBJDIR)\record/ares_dns_record.obj \
    $(CARES_OBJDIR)\record/ares_dns_write.obj \
    $(CARES_OBJDIR)\str/ares_buf.obj \
    $(CARES_OBJDIR)\str/ares_str.obj \
    $(CARES_OBJDIR)\str/ares_strsplit.obj \
    $(CARES_OBJDIR)\util/ares_iface_ips.obj \
    $(CARES_OBJDIR)\util/ares_threads.obj \
    $(CARES_OBJDIR)\util/ares_timeval.obj \
    $(CARES_OBJDIR)\util/ares_math.obj \
    $(CARES_OBJDIR)\util/ares_rand.obj \
    $(CARES_OBJDIR)\util/ares_uri.obj \

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
