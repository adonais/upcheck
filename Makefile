ROOT = .
!include "$(ROOT)\system.mak"

all:
    cd "$(MAKEDIR)"
	@if exist "$(MAKEDIR)\src\zlib\Makefile" cd "$(MAKEDIR)\src\zlib" && $(MAKE)  /NOLOGO /$(MAKEFLAGS)
!IF "$(CURL_LINK)" != "1"
	@if exist "$(MAKEDIR)\src\libcares\Makefile" cd "$(MAKEDIR)\src\libcares" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\libngttp2\Makefile" cd "$(MAKEDIR)\src\libngttp2" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\libcurl\Makefile" cd "$(MAKEDIR)\src\libcurl" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
!ENDIF
	@if exist "$(MAKEDIR)\src\liblzma\Makefile" cd "$(MAKEDIR)\src\liblzma" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
    cd "$(MAKEDIR)\src"
    @$(MAKE) /NOLOGO /$(MAKEFLAGS)
    cd "$(MAKEDIR)"

clean:
    cd "$(MAKEDIR)"
	@if exist "$(MAKEDIR)\src\zlib\Makefile" cd "$(MAKEDIR)\src\zlib" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\libcares\Makefile" cd "$(MAKEDIR)\src\libcares" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\libngttp2\Makefile" cd "$(MAKEDIR)\src\libngttp2" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\libcurl\Makefile" cd "$(MAKEDIR)\src\libcurl" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\liblzma\Makefile" cd "$(MAKEDIR)\src\liblzma" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
    cd "$(MAKEDIR)\src"
    @$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
    cd "$(MAKEDIR)"
    -del /q /f /s *~ 2>nul
    -rd /s /q include 2>nul
