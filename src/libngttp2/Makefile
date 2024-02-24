# ------------------------------------------------NMAKE----------------------------------------------------------

NAME = nghttp2

# ------------------------------------------------
# c-ares static and dynamic libraries common base
# file names for release and debug configurations
# ------------------------------------------------

ROOT = ..\..
!include "$(ROOT)\system.mak"

# --------------------------
# Runtime library selection
# --------------------------
NGHTTP2_OBJDIR = $(OBJD)\nghttp2
STATICLIB = $(BIND)\$(NAME).lib
CFLAGS = -nologo -I. -Iinclude -Iinclude/nghttp2 -W3 -EHsc -O2 -Zi -Fd"$(BIND)\nghttp2" -D_CRT_SECURE_NO_WARNINGS \
         -DBUILDING_NGHTTP2 -DNGHTTP2_STATICLIB -D_WIN32_WINNT=0x0600 -DWIN32 -D_WINDOWS $(CFLAGS)
!if "$(APP_DEBUG)"=="1"
CFLAGS = $(CFLAGS) $(DEBUG_L)
!ELSE
CFLAGS = $(CFLAGS) $(RELEASE)
!ENDIF
# ----------------------------------------
# Subdir holding sources for all projects
# ----------------------------------------

SRC = .\src

# -------------------------------------------------
# Switches that depend on ancient compiler versions
# -------------------------------------------------

OBJS = \
    $(NGHTTP2_OBJDIR)\nghttp2_pq.obj              \
    $(NGHTTP2_OBJDIR)\nghttp2_map.obj             \
    $(NGHTTP2_OBJDIR)\nghttp2_queue.obj           \
    $(NGHTTP2_OBJDIR)\nghttp2_frame.obj           \
    $(NGHTTP2_OBJDIR)\nghttp2_buf.obj             \
    $(NGHTTP2_OBJDIR)\nghttp2_stream.obj          \
    $(NGHTTP2_OBJDIR)\nghttp2_outbound_item.obj   \
    $(NGHTTP2_OBJDIR)\nghttp2_session.obj         \
    $(NGHTTP2_OBJDIR)\nghttp2_submit.obj          \
    $(NGHTTP2_OBJDIR)\nghttp2_helper.obj          \
    $(NGHTTP2_OBJDIR)\nghttp2_alpn.obj            \
    $(NGHTTP2_OBJDIR)\nghttp2_hd.obj              \
    $(NGHTTP2_OBJDIR)\nghttp2_hd_huffman.obj      \
    $(NGHTTP2_OBJDIR)\nghttp2_hd_huffman_data.obj \
    $(NGHTTP2_OBJDIR)\nghttp2_version.obj         \
    $(NGHTTP2_OBJDIR)\nghttp2_priority_spec.obj   \
    $(NGHTTP2_OBJDIR)\nghttp2_option.obj          \
    $(NGHTTP2_OBJDIR)\nghttp2_callbacks.obj       \
    $(NGHTTP2_OBJDIR)\nghttp2_mem.obj             \
    $(NGHTTP2_OBJDIR)\nghttp2_http.obj            \
    $(NGHTTP2_OBJDIR)\nghttp2_rcbuf.obj           \
    $(NGHTTP2_OBJDIR)\nghttp2_extpri.obj          \
    $(NGHTTP2_OBJDIR)\nghttp2_debug.obj           \
    $(NGHTTP2_OBJDIR)\nghttp2_ratelim.obj         \
    $(NGHTTP2_OBJDIR)\nghttp2_time.obj            \
    $(NGHTTP2_OBJDIR)\sfparse.obj                 \

##############################################################################
##
.SUFFIXES: .c .h

{$(SRC)}.c{$(NGHTTP2_OBJDIR)}.obj:
    $(CC) $(CFLAGS) -Fo$(NGHTTP2_OBJDIR)\ -c $<

##############################################################################

# targets
all: dirs $(STATICLIB) $(INCD)\nghttp2\nghttp2.h

dirs:
	@if not exist "$(BIND)" mkdir "$(BIND)" && echo.   Created $(BIND)
	@if not exist "$(INCD)" mkdir "$(INCD)" && echo.   Created $(INCD)
	@if not exist "$(INCD)\nghttp2" mkdir "$(INCD)\nghttp2" && echo.   Created $(INCD)\nghttp2
	@if not exist "$(NGHTTP2_OBJDIR)" mkdir "$(NGHTTP2_OBJDIR)" && echo.   Created $(NGHTTP2_OBJDIR)

$(STATICLIB): $(OBJS)
	$(AR) $(ARFLAGS) -out:$@ $(OBJS)

$(INCD)\nghttp2\nghttp2.h : include\nghttp2\nghttp2.h
	@xcopy "include\nghttp2\*" "$(INCD)\nghttp2" /y /e /i /q

$(OBJS): $(SRC)\*.c $(SRC)\*.h

# cleanup
clean:
	-del /q $(STATICLIB) 2>nul
	-del /q $(BIND)\*.pdb 2>nul
	-del /q $(BIND)\*.idb 2>nul
	-del /q $(OBJS) 2>nul
	-rd  /s /q $(INCD)\nghttp2 2>nul