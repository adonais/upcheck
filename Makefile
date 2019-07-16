ROOT = .
!include "$(ROOT)\system.mak"

all:
    cd "$(MAKEDIR)"
	@if exist "$(MAKEDIR)\src\libz\src\Makefile" cd "$(MAKEDIR)\src\libz\src" && $(MAKE)  /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\libc-ares\src\Makefile" cd "$(MAKEDIR)\src\libc-ares\src" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\libcurl\src\Makefile" cd "$(MAKEDIR)\src\libcurl\src" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\liblzma\src\Makefile" cd "$(MAKEDIR)\src\liblzma\src" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
    cd "$(MAKEDIR)\src"
    @$(MAKE) /NOLOGO /$(MAKEFLAGS)
    cd "$(MAKEDIR)"

clean:
    cd "$(MAKEDIR)"
	@if exist "$(MAKEDIR)\src\libz\src\Makefile" cd "$(MAKEDIR)\src\libz\src" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\libc-ares\src\Makefile" cd "$(MAKEDIR)\src\libc-ares\src" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\libcurl\src\Makefile" cd "$(MAKEDIR)\src\libcurl\src" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\liblzma\src\Makefile" cd "$(MAKEDIR)\src\liblzma\src" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
    cd "$(MAKEDIR)\src"
    @$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
    cd "$(MAKEDIR)"
    -del /q /f /s *~ 2>nul
    -rd /s /q include 2>nul
