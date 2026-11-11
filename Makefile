all:
	@if [ -f "$(CURDIR)/lib7z/Makefile" ]; then \
		cd "$(CURDIR)/lib7z" && $(MAKE) $(MAKEFLAGS); \
	fi
	@if [ -f "$(CURDIR)/src/Makefile" ]; then \
		cd "$(CURDIR)/src" && $(MAKE) $(MAKEFLAGS); \
	fi

clean:
	if [ -f "$(CURDIR)/lib7z/Makefile" ]; then cd "$(CURDIR)/lib7z" && $(MAKE) $(MAKEFLAGS) clean; fi
	if [ -f "$(CURDIR)/src/Makefile" ]; then cd "$(CURDIR)/src" && $(MAKE) $(MAKEFLAGS) clean; fi
	cd "$(CURDIR)"
	-rm -f *~ 2>/dev/null
	-rm -rf dep include release 2>/dev/null
