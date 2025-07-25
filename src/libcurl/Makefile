# ------------------------------------------------NMAKE----------------------------------------------------------

NAME = curl

# --------------------------
# Runtime library selection
# --------------------------
MY_NO_UNICODE      = true
USE_ZLIB           = true
USE_CARES          = true
USE_NGHTTP2        = true
USE_IPV6           = true
USE_SSPI           = true
USE_WINSSL         = true
USE_IDN            = true
DISABLE_WEBSOCKETS = true

# ------------------------------------------------
# libcurl static and dynamic libraries common base
# file names for release and debug configurations
# ------------------------------------------------

ROOT = ..\..
!include "$(ROOT)\system.mak"

STATICLIB = $(BIND)\lib$(NAME).lib
CFLAGS = -nologo -O2 -DCURL_STATICLIB -I. -Isrc -Iinclude -W4 -wd4127 -EHsc -c \
         -Zi -Fd"$(BIND)\libcurl" -DBUILDING_LIBCURL \
         -DHAVE_INET_NTOP -DHAVE_INET_PTON $(CFLAGS)
RC_CMD_REL = rc.exe -l 0x409 -d "NDEBUG"
LINK_CMD_LIB = link.exe -lib -nologo
!if "$(APP_DEBUG)"=="1"
CFLAGS = $(CFLAGS) $(DEBUG_L)
!ELSE
CFLAGS = $(CFLAGS) $(RELEASE)
!ENDIF

!IFDEF USE_ZLIB
CFLAGS = $(CFLAGS) -DHAVE_ZLIB_H -DHAVE_ZLIB -DHAVE_LIBZ $(ADDITIONAL_ZLIB_CFLAGS) -I..\..\libz\src
!ENDIF

!IFDEF USE_CARES
CFLAGS   = $(CFLAGS) -DUSE_ARES -I..\..\libc-ares\src
!ENDIF

!IFDEF USE_NGHTTP2
CFLAGS   = $(CFLAGS) -DUSE_NGHTTP2 -DNGHTTP2_STATICLIB -I..\..\libngttp2\src
!ENDIF

!IF "$(USE_IPV6)"=="true"
CFLAGS = $(CFLAGS) -DUSE_IPV6
!ENDIF

!IF "$(USE_SSPI)"=="true"
CFLAGS = $(CFLAGS) -DUSE_WINDOWS_SSPI
!ENDIF

!IF "$(USE_SSPI)"=="true"
CFLAGS = $(CFLAGS) -DUSE_WIN32_IDN -DWANT_IDN_PROTOTYPES
!ENDIF

!IF "$(USE_WINSSL)"=="true"
!IF "$(USE_SSPI)"!="true"
!ERROR cannot build with WinSSL without SSPI
!ENDIF
CFLAGS = $(CFLAGS) -DUSE_SCHANNEL
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

# ----------------------------
# Build lists of object files
# ----------------------------

OBJS = \
    $(OBJD)\libcurl\macos.obj                   \
    $(OBJD)\libcurl\file.obj                    \
    $(OBJD)\libcurl\bufq.obj                    \
    $(OBJD)\libcurl\cf-h1-proxy.obj             \
    $(OBJD)\libcurl\cf-h2-proxy.obj             \
    $(OBJD)\libcurl\cf-haproxy.obj              \
    $(OBJD)\libcurl\hostip.obj                  \
    $(OBJD)\libcurl\progress.obj                \
    $(OBJD)\libcurl\formdata.obj                \
    $(OBJD)\libcurl\cookie.obj                  \
    $(OBJD)\libcurl\http.obj                    \
    $(OBJD)\libcurl\sendf.obj                   \
    $(OBJD)\libcurl\ftp.obj                     \
    $(OBJD)\libcurl\url.obj                     \
    $(OBJD)\libcurl\dict.obj                    \
    $(OBJD)\libcurl\if2ip.obj                   \
    $(OBJD)\libcurl\speedcheck.obj              \
    $(OBJD)\libcurl\ldap.obj                    \
    $(OBJD)\libcurl\version.obj                 \
    $(OBJD)\libcurl\getenv.obj                  \
    $(OBJD)\libcurl\escape.obj                  \
    $(OBJD)\libcurl\mprintf.obj                 \
    $(OBJD)\libcurl\telnet.obj                  \
    $(OBJD)\libcurl\netrc.obj                   \
    $(OBJD)\libcurl\getinfo.obj                 \
    $(OBJD)\libcurl\transfer.obj                \
    $(OBJD)\libcurl\strcase.obj                 \
    $(OBJD)\libcurl\easy.obj                    \
    $(OBJD)\libcurl\noproxy.obj                 \
    $(OBJD)\libcurl\curl_fnmatch.obj            \
    $(OBJD)\libcurl\fileinfo.obj                \
    $(OBJD)\libcurl\ftplistparser.obj           \
    $(OBJD)\libcurl\krb5.obj                    \
    $(OBJD)\libcurl\memdebug.obj                \
    $(OBJD)\libcurl\http_chunks.obj             \
    $(OBJD)\libcurl\cshutdn.obj                 \
    $(OBJD)\libcurl\connect.obj                 \
    $(OBJD)\libcurl\llist.obj                   \
    $(OBJD)\libcurl\hash.obj                    \
    $(OBJD)\libcurl\multi.obj                   \
    $(OBJD)\libcurl\content_encoding.obj        \
    $(OBJD)\libcurl\share.obj                   \
    $(OBJD)\libcurl\http_digest.obj             \
    $(OBJD)\libcurl\md4.obj                     \
    $(OBJD)\libcurl\md5.obj                     \
    $(OBJD)\libcurl\http_negotiate.obj          \
    $(OBJD)\libcurl\cw-pause.obj                \
    $(OBJD)\libcurl\multi_ev.obj                \
    $(OBJD)\libcurl\strequal.obj                \
    $(OBJD)\libcurl\strerror.obj                \
    $(OBJD)\libcurl\amigaos.obj                 \
    $(OBJD)\libcurl\hostip4.obj                 \
    $(OBJD)\libcurl\hostip6.obj                 \
    $(OBJD)\libcurl\parsedate.obj               \
    $(OBJD)\libcurl\select.obj                  \
    $(OBJD)\libcurl\tftp.obj                    \
    $(OBJD)\libcurl\splay.obj                   \
    $(OBJD)\libcurl\strdup.obj                  \
    $(OBJD)\libcurl\socks.obj                   \
    $(OBJD)\libcurl\rename.obj                  \
    $(OBJD)\libcurl\socketpair.obj              \
    $(OBJD)\libcurl\curl_addrinfo.obj           \
    $(OBJD)\libcurl\socks_gssapi.obj            \
    $(OBJD)\libcurl\socks_sspi.obj              \
    $(OBJD)\libcurl\curl_sspi.obj               \
    $(OBJD)\libcurl\slist.obj                   \
    $(OBJD)\libcurl\curl_memrchr.obj            \
    $(OBJD)\libcurl\imap.obj                    \
    $(OBJD)\libcurl\pop3.obj                    \
    $(OBJD)\libcurl\smtp.obj                    \
    $(OBJD)\libcurl\pingpong.obj                \
    $(OBJD)\libcurl\rtsp.obj                    \
    $(OBJD)\libcurl\curl_threads.obj            \
    $(OBJD)\libcurl\hmac.obj                    \
    $(OBJD)\libcurl\curl_rtmp.obj               \
    $(OBJD)\libcurl\openldap.obj                \
    $(OBJD)\libcurl\curl_gethostname.obj        \
    $(OBJD)\libcurl\gopher.obj                  \
    $(OBJD)\libcurl\idn.obj                     \
    $(OBJD)\libcurl\hsts.obj                    \
    $(OBJD)\libcurl\http_aws_sigv4.obj          \
    $(OBJD)\libcurl\http_proxy.obj              \
    $(OBJD)\libcurl\mqtt.obj                    \
    $(OBJD)\libcurl\asyn-ares.obj               \
    $(OBJD)\libcurl\asyn-base.obj               \
    $(OBJD)\libcurl\asyn-thrdd.obj              \
    $(OBJD)\libcurl\curl_gssapi.obj             \
    $(OBJD)\libcurl\http_ntlm.obj               \
    $(OBJD)\libcurl\curl_sha512_256.obj         \
    $(OBJD)\libcurl\curl_ntlm_core.obj          \
    $(OBJD)\libcurl\curl_sasl.obj               \
    $(OBJD)\libcurl\rand.obj                    \
    $(OBJD)\libcurl\fake_addrinfo.obj           \
    $(OBJD)\libcurl\headers.obj                 \
    $(OBJD)\libcurl\fopen.obj                   \
    $(OBJD)\libcurl\easyoptions.obj             \
    $(OBJD)\libcurl\easygetopt.obj              \
    $(OBJD)\libcurl\conncache.obj               \
    $(OBJD)\libcurl\curl_trc.obj                \
    $(OBJD)\libcurl\uint-bset.obj               \
    $(OBJD)\libcurl\uint-hash.obj               \
    $(OBJD)\libcurl\uint-spbset.obj             \
    $(OBJD)\libcurl\uint-table.obj              \
    $(OBJD)\libcurl\ws.obj                      \
    $(OBJD)\libcurl\dynhds.obj                  \
    $(OBJD)\libcurl\http1.obj                   \
    $(OBJD)\libcurl\http2.obj                   \
    $(OBJD)\libcurl\smb.obj                     \
    $(OBJD)\libcurl\curl_endian.obj             \
    $(OBJD)\libcurl\curl_des.obj                \
    $(OBJD)\libcurl\system_win32.obj            \
    $(OBJD)\libcurl\mime.obj                    \
    $(OBJD)\libcurl\sha256.obj                  \
    $(OBJD)\libcurl\setopt.obj                  \
    $(OBJD)\libcurl\bufref.obj                  \
    $(OBJD)\libcurl\cf-https-connect.obj        \
    $(OBJD)\libcurl\cfilters.obj                \
    $(OBJD)\libcurl\cf-socket.obj               \
    $(OBJD)\libcurl\httpsrr.obj                 \
    $(OBJD)\libcurl\curl_range.obj              \
    $(OBJD)\libcurl\psl.obj                     \
    $(OBJD)\libcurl\doh.obj                     \
    $(OBJD)\libcurl\urlapi.obj                  \
    $(OBJD)\libcurl\curl_get_line.obj           \
    $(OBJD)\libcurl\altsvc.obj                  \
    $(OBJD)\libcurl\cw-out.obj                  \
    $(OBJD)\libcurl\request.obj                 \
    $(OBJD)\libcurl\curlx\base64.obj            \
    $(OBJD)\libcurl\curlx\dynbuf.obj            \
    $(OBJD)\libcurl\curlx\inet_pton.obj         \
    $(OBJD)\libcurl\curlx\multibyte.obj         \
    $(OBJD)\libcurl\curlx\nonblock.obj          \
    $(OBJD)\libcurl\curlx\strparse.obj          \
    $(OBJD)\libcurl\curlx\timediff.obj          \
    $(OBJD)\libcurl\curlx\timeval.obj           \
    $(OBJD)\libcurl\curlx\version_win32.obj     \
    $(OBJD)\libcurl\curlx\warnless.obj          \
    $(OBJD)\libcurl\curlx\winapi.obj            \
    $(OBJD)\libcurl\curlx\inet_ntop.obj         \
    $(OBJD)\libcurl\curlx\wait.obj              \
    $(OBJD)\libcurl\vauth\vauth.obj             \
    $(OBJD)\libcurl\vauth\cleartext.obj         \
    $(OBJD)\libcurl\vauth\cram.obj              \
    $(OBJD)\libcurl\vauth\digest.obj            \
    $(OBJD)\libcurl\vauth\digest_sspi.obj       \
    $(OBJD)\libcurl\vauth\gsasl.obj             \
    $(OBJD)\libcurl\vauth\krb5_gssapi.obj       \
    $(OBJD)\libcurl\vauth\krb5_sspi.obj         \
    $(OBJD)\libcurl\vauth\ntlm.obj              \
    $(OBJD)\libcurl\vauth\ntlm_sspi.obj         \
    $(OBJD)\libcurl\vauth\oauth2.obj            \
    $(OBJD)\libcurl\vauth\spnego_gssapi.obj     \
    $(OBJD)\libcurl\vauth\spnego_sspi.obj       \
    $(OBJD)\libcurl\vquic\curl_msh3.obj         \
    $(OBJD)\libcurl\vquic\curl_ngtcp2.obj       \
    $(OBJD)\libcurl\vquic\curl_osslq.obj        \
    $(OBJD)\libcurl\vquic\curl_quiche.obj       \
    $(OBJD)\libcurl\vquic\vquic.obj             \
    $(OBJD)\libcurl\vquic\vquic-tls.obj         \
    $(OBJD)\libcurl\vssh\curl_path.obj          \
    $(OBJD)\libcurl\vssh\libssh.obj             \
    $(OBJD)\libcurl\vssh\libssh2.obj            \
    $(OBJD)\libcurl\vssh\wolfssh.obj            \
    $(OBJD)\libcurl\vtls\gtls.obj               \
    $(OBJD)\libcurl\vtls\hostcheck.obj          \
    $(OBJD)\libcurl\vtls\keylog.obj             \
    $(OBJD)\libcurl\vtls\mbedtls.obj            \
    $(OBJD)\libcurl\vtls\mbedtls_threadlock.obj \
    $(OBJD)\libcurl\vtls\openssl.obj            \
    $(OBJD)\libcurl\vtls\rustls.obj             \
    $(OBJD)\libcurl\vtls\schannel.obj           \
    $(OBJD)\libcurl\vtls\schannel_verify.obj    \
    $(OBJD)\libcurl\vtls\vtls.obj               \
    $(OBJD)\libcurl\vtls\vtls_scache.obj        \
    $(OBJD)\libcurl\vtls\vtls_spack.obj         \
    $(OBJD)\libcurl\vtls\wolfssl.obj            \
    $(OBJD)\libcurl\vtls\x509asn1.obj           \
    $(OBJD)\libcurl\vtls\cipher_suite.obj       \

# --------------------------------
# Only our custom inference rules
# --------------------------------

.SUFFIXES:
.SUFFIXES: .c .rc

{$(SRCDIR)}.rc{$(OBJD)\libcurl}.res:
    $(RC_CMD_REL) -Fo $@ $<

{$(SRCDIR)}.c{$(OBJD)\libcurl}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<

{$(SRCDIR)\curlx}.c{$(OBJD)\libcurl\curlx}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<

{$(SRCDIR)\vauth}.c{$(OBJD)\libcurl\vauth}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<
    	
{$(SRCDIR)\vquic}.c{$(OBJD)\libcurl\vquic}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<
    	
{$(SRCDIR)\vssh}.c{$(OBJD)\libcurl\vssh}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<    	    	
 
{$(SRCDIR)\vtls}.c{$(OBJD)\libcurl\vtls}.obj:
    $(CC) $(CFLAGS) -Fo$@ -c $<

# ---------------------------------------------------------------------
# Targets only available when a proper CFG library type has been given
# ---------------------------------------------------------------------

all: dirs $(STATICLIB)      \
     $(INCD)\curl           \
     
dirs:
    @if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
    @if not exist "$(OBJD)\libcurl" mkdir "$(OBJD)\libcurl" && echo.   Created $(OBJD)\libcurl
    @if not exist "$(OBJD)\libcurl\curlx" mkdir "$(OBJD)\libcurl\curlx" && echo.   Created $(OBJD)\libcurl\curlx
    @if not exist "$(OBJD)\libcurl\vauth" mkdir "$(OBJD)\libcurl\vauth" && echo.   Created $(OBJD)\libcurl\vauth
    @if not exist "$(OBJD)\libcurl\vquic" mkdir "$(OBJD)\libcurl\vquic" && echo.   Created $(OBJD)\libcurl\vquic
    @if not exist "$(OBJD)\libcurl\vssh" mkdir "$(OBJD)\libcurl\vssh" && echo.   Created $(OBJD)\libcurl\vssh
    @if not exist "$(OBJD)\libcurl\vtls" mkdir "$(OBJD)\libcurl\vtls" && echo.   Created $(OBJD)\libcurl\vtls
    @if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)

$(STATICLIB): $(OBJS)
	$(AR) $(ARFLAGS) -out:$@ $(OBJS)

$(INCD)\curl : include\curl\curl.h
	@xcopy include\curl\* $@ /y /e /i /q

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(BIND)\*.pdb 2>nul
	-del /q $(BIND)\*.idb 2>nul
	-del /q $(OBJD)\libcurl\*.obj 2>nul
	-del /q $(OBJD)\libcurl\curlx\*.obj 2>nul
	-del /q $(OBJD)\libcurl\vauth\*.obj 2>nul
	-del /q $(OBJD)\libcurl\vquic\*.obj 2>nul
	-del /q $(OBJD)\libcurl\vssh\*.obj 2>nul
	-del /q $(OBJD)\libcurl\vtls\*.obj 2>nul
	-del /q $(OBJD)\libcurl\*.res 2>nul
	-rd  /s /q $(INCD)\curl 2>nul
