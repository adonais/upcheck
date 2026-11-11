ROOT = ..
include $(ROOT)/system.mak

CFLAGS += -DCJSON_HIDE_SYMBOLS

ifeq ("$(APP_DEBUG)", "1")
CFLAGS += $(DEBUG_L)
else
CFLAGS += $(RELEASE)
endif

OBJECTS  = $(OBJD)/cookies.o     \
           $(OBJD)/spinlock.o    \
           $(OBJD)/upcheck.o     \
           $(OBJD)/urlcode.o     \
           $(OBJD)/ini_parser.o  \
           $(OBJD)/load_chrome.o \
           $(OBJD)/load_script.o \
           $(OBJD)/xml.o         \
           $(OBJD)/manger.o      \
           $(OBJD)/cjson.o       \
           $(OBJD)/json_paser.o  \
           $(OBJD)/extractxz.o   \

all : dirs $(OUT)

dirs:
	@if [ ! -d "$(BIND)" ]; then $(MD) "$(BIND)"; fi
	@if [ ! -d "$(OBJD)" ]; then $(MD) "$(OBJD)"; fi
	@if [ ! -d "$(INCD)" ]; then $(MD) "$(INCD)"; fi

$(OUT)       : $(OBJECTS)
	$(LD) $@ $(OBJECTS) $(shell pkg-config --libs libcurl sqlite3 luajit libarchive) -lrt -pthread -lm -s

$(OBJD)/cookies.o     : cookies.c cookies.h spinlock.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/spinlock.o    : spinlock.c spinlock.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/upcheck.o     : upcheck.c upcheck.h urlcode.h load_script.h xml.h spinlock.h manger.h json_paser.h extractxz.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/urlcode.o     : urlcode.c urlcode.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/ini_parser.o  : ini_parser.c ini_parser.h spinlock.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/load_chrome.o : load_chrome.c load_chrome.h xml.h spinlock.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/load_script.o : load_script.c load_script.h xml.h spinlock.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/xml.o         : xml.c xml.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/manger.o      : manger.c manger.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/cjson.o       : cjson.c cjson.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/json_paser.o  : json_paser.c json_paser.h cjson.h
	$(CC) -c $< $(CFLAGS) -o $@
$(OBJD)/extractxz.o : extractxz.c extractxz.h
	$(CC) -c $< $(CFLAGS) -o $@

.PHONY                : clean
clean                 :
	-rm -f $(OBJECTS) $(OUT)

