# ------------------------------------------------NMAKE----------------------------------------------------------

NAME = curl

# --------------------------
# Runtime library selection
# --------------------------
MY_NO_UNICODE = true
USE_ZLIB      = true
USE_CARES     = true
USE_IPV6      = true
USE_SSPI      = true
USE_WINSSL    = true
USE_IDN       = true

# ------------------------------------------------
# libcurl static and dynamic libraries common base
# file names for release and debug configurations
# ------------------------------------------------

ROOT = ..\..\..
!include "$(ROOT)\system.mak"

STATICLIB = $(BIND)\lib$(NAME).lib
CFLAGS = /nologo /O2 /DNDEBUG /MT /DCURL_STATICLIB /I. /I../include /W4 /wd4127 /EHsc /FD /c \
         /Zi -Fd"$(BIND)\libcurl" /DBUILDING_LIBCURL /D_WIN32_WINNT=0x0600 \
        -DHAVE_INET_NTOP -DHAVE_INET_PTON $(CFLAGS) 
RC_CMD_REL = rc.exe /l 0x409 /d "NDEBUG"
LINK_CMD_LIB = link.exe /lib /nologo

!IFDEF USE_ZLIB
CFLAGS = $(CFLAGS) /DHAVE_ZLIB_H /DHAVE_ZLIB /DHAVE_LIBZ $(ADDITIONAL_ZLIB_CFLAGS) /I..\..\libz\src
!ENDIF 

!IFDEF USE_CARES
CFLAGS   = $(CFLAGS) /DUSE_ARES /I..\..\libc-ares\src
!ENDIF

!IF "$(USE_IPV6)"=="true"
CFLAGS = $(CFLAGS) /DUSE_IPV6
!ENDIF

!IF "$(USE_SSPI)"=="true"
CFLAGS = $(CFLAGS) /DUSE_WINDOWS_SSPI
!ENDIF

!IF "$(USE_SSPI)"=="true"
CFLAGS = $(CFLAGS) /DUSE_WIN32_IDN /DWANT_IDN_PROTOTYPES
!ENDIF

!IF "$(USE_WINSSL)"=="true"
!IF "$(USE_SSPI)"!="true"
!ERROR cannot build with WinSSL without SSPI
!ENDIF
CFLAGS = $(CFLAGS) /DUSE_SCHANNEL
!ENDIF

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
    $(OBJD)\file.obj          \
    $(OBJD)\timeval.obj       \
    $(OBJD)\base64.obj        \
    $(OBJD)\hostip.obj        \
    $(OBJD)\progress.obj      \
    $(OBJD)\formdata.obj      \
    $(OBJD)\cookie.obj        \
    $(OBJD)\http.obj          \
    $(OBJD)\sendf.obj         \
    $(OBJD)\ftp.obj           \
    $(OBJD)\url.obj           \
    $(OBJD)\dict.obj          \
    $(OBJD)\if2ip.obj         \
    $(OBJD)\speedcheck.obj    \
    $(OBJD)\ldap.obj          \
    $(OBJD)\version.obj       \
    $(OBJD)\getenv.obj        \
    $(OBJD)\escape.obj        \
    $(OBJD)\mprintf.obj       \
    $(OBJD)\telnet.obj        \
    $(OBJD)\netrc.obj         \
    $(OBJD)\getinfo.obj       \
    $(OBJD)\transfer.obj      \
    $(OBJD)\strcase.obj       \
    $(OBJD)\easy.obj          \
    $(OBJD)\security.obj      \
    $(OBJD)\curl_fnmatch.obj  \
    $(OBJD)\fileinfo.obj      \
    $(OBJD)\ftplistparser.obj \
    $(OBJD)\wildcard.obj      \
    $(OBJD)\krb5.obj          \
    $(OBJD)\memdebug.obj      \
    $(OBJD)\http_chunks.obj   \
    $(OBJD)\strtok.obj        \
    $(OBJD)\connect.obj       \
    $(OBJD)\llist.obj         \
    $(OBJD)\hash.obj          \
    $(OBJD)\multi.obj         \
    $(OBJD)\content_encoding.obj \
    $(OBJD)\share.obj            \
    $(OBJD)\http_digest.obj      \
    $(OBJD)\md4.obj              \
    $(OBJD)\md5.obj              \
    $(OBJD)\http_negotiate.obj   \
    $(OBJD)\inet_pton.obj        \
    $(OBJD)\strtoofft.obj        \
    $(OBJD)\strerror.obj         \
    $(OBJD)\amigaos.obj          \
    $(OBJD)\hostasyn.obj         \
    $(OBJD)\hostip4.obj          \
    $(OBJD)\hostip6.obj          \
    $(OBJD)\hostsyn.obj          \
    $(OBJD)\inet_ntop.obj        \
    $(OBJD)\parsedate.obj        \
    $(OBJD)\select.obj           \
    $(OBJD)\tftp.obj             \
    $(OBJD)\splay.obj            \
    $(OBJD)\strdup.obj           \
    $(OBJD)\socks.obj            \
    $(OBJD)\ssh.obj              \
    $(OBJD)\ssh-libssh.obj       \
    $(OBJD)\curl_addrinfo.obj    \
    $(OBJD)\socks_gssapi.obj     \
    $(OBJD)\socks_sspi.obj       \
    $(OBJD)\curl_sspi.obj        \
    $(OBJD)\slist.obj            \
    $(OBJD)\nonblock.obj         \
    $(OBJD)\curl_memrchr.obj     \
    $(OBJD)\imap.obj             \
    $(OBJD)\pop3.obj             \
    $(OBJD)\smtp.obj             \
    $(OBJD)\pingpong.obj         \
    $(OBJD)\rtsp.obj             \
    $(OBJD)\curl_threads.obj     \
    $(OBJD)\warnless.obj         \
    $(OBJD)\hmac.obj             \
    $(OBJD)\curl_rtmp.obj        \
    $(OBJD)\openldap.obj         \
    $(OBJD)\curl_gethostname.obj \
    $(OBJD)\gopher.obj           \
    $(OBJD)\idn_win32.obj        \
    $(OBJD)\http_proxy.obj       \
    $(OBJD)\non-ascii.obj        \
    $(OBJD)\asyn-ares.obj        \
    $(OBJD)\asyn-thread.obj      \
    $(OBJD)\curl_gssapi.obj      \
    $(OBJD)\http_ntlm.obj        \
    $(OBJD)\curl_ntlm_wb.obj     \
    $(OBJD)\curl_ntlm_core.obj   \
    $(OBJD)\curl_sasl.obj        \
    $(OBJD)\rand.obj             \
    $(OBJD)\curl_multibyte.obj   \
    $(OBJD)\hostcheck.obj        \
    $(OBJD)\conncache.obj        \
    $(OBJD)\dotdot.obj           \
    $(OBJD)\x509asn1.obj         \
    $(OBJD)\http2.obj            \
    $(OBJD)\smb.obj              \
    $(OBJD)\curl_endian.obj      \
    $(OBJD)\curl_des.obj         \
    $(OBJD)\system_win32.obj     \
    $(OBJD)\mime.obj             \
    $(OBJD)\sha256.obj           \
    $(OBJD)\setopt.obj           \
    $(OBJD)\curl_path.obj        \
    $(OBJD)\curl_ctype.obj       \
    $(OBJD)\curl_range.obj       \
    $(OBJD)\psl.obj              \
    $(OBJD)\doh.obj              \
    $(OBJD)\urlapi.obj           \
    $(OBJD)\curl_get_line.obj    \
    $(OBJD)\altsvc.obj           \
    $(OBJD)\vauth\vauth.obj      \
    $(OBJD)\vauth\cleartext.obj  \
    $(OBJD)\vauth\cram.obj       \
    $(OBJD)\vauth\digest.obj     \
    $(OBJD)\vauth\digest_sspi.obj   \
    $(OBJD)\vauth\krb5_gssapi.obj   \
    $(OBJD)\vauth\krb5_sspi.obj     \
    $(OBJD)\vauth\ntlm.obj          \
    $(OBJD)\vauth\ntlm_sspi.obj     \
    $(OBJD)\vauth\oauth2.obj        \
    $(OBJD)\vauth\spnego_gssapi.obj \
    $(OBJD)\vauth\spnego_sspi.obj   \
    $(OBJD)\vtls\openssl.obj        \
    $(OBJD)\vtls\gtls.obj           \
    $(OBJD)\vtls\vtls.obj           \
    $(OBJD)\vtls\nss.obj            \
    $(OBJD)\vtls\polarssl.obj       \
    $(OBJD)\vtls\polarssl_threadlock.obj \
    $(OBJD)\vtls\cyassl.obj              \
    $(OBJD)\vtls\schannel.obj            \
    $(OBJD)\vtls\schannel_verify.obj     \
    $(OBJD)\vtls\sectransp.obj           \
    $(OBJD)\vtls\gskit.obj               \
    $(OBJD)\vtls\mbedtls.obj             \
    $(OBJD)\vtls\mesalink.obj            \

!INCLUDE ".\Makefile.inc"
  
# --------------------------------
# Only our custom inference rules
# --------------------------------

.SUFFIXES:
.SUFFIXES: .c .rc

{$(SRCDIR)}.rc{$(OBJD)}.res:
    $(RC_CMD) /Fo $@ $<

{$(SRCDIR)}.c{$(OBJD)}.obj:
    cl $(CFLAGS) /Fo$@ /c $<
    
{$(SRCDIR)\vauth}.c{$(OBJD)\vauth}.obj:
    cl $(CFLAGS) /Fo$@ /c $<
 
{$(SRCDIR)\vtls}.c{$(OBJD)\vtls}.obj:
    cl $(CFLAGS) /Fo$@ /c $<
        
# ---------------------------------------------------------------------
# Targets only available when a proper CFG library type has been given
# ---------------------------------------------------------------------

all: dirs $(STATICLIB)      \
     $(INCD)\curl           \
     
dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)"\vauth mkdir "$(OBJD)"\vauth && echo.   Created $(OBJD)\vauth
    @if not exist "$(OBJD)"\vtls mkdir "$(OBJD)"\vtls && echo.   Created $(OBJD)\vtls    
    @if not exist "$(OBJD)" mkdir "$(OBJD)" && echo.   Created $(OBJD)
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(OBJS)
	$(LINK_CMD_LIB) $(ARFLAGS) -out:$@ $(OBJS)
	
$(INCD)\curl : ..\include\curl\curl.h
    @xcopy ..\include\curl\* $@ /y /e /i /q
    
$(OBJS): $(CSOURCES) $(HHEADERS)

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(BIND)\*.pdb 2>nul
	-del /q $(BIND)\*.idb 2>nul
	-del /q $(OBJD)\*.obj 2>nul
	-del /q $(OBJD)\vauth\*.obj 2>nul
	-del /q $(OBJD)\vtls\*.obj 2>nul
	-del /q $(OBJD)\*.res 2>nul
	-rd  /s /q $(INCD)\curl 2>nul
