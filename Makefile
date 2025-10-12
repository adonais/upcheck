ROOT = .
!include "$(ROOT)\system.mak"

all:
	cd "$(MAKEDIR)"
	@if exist "$(MAKEDIR)\src\zlib\Makefile" cd "$(MAKEDIR)\src\zlib" && $(MAKE)  /NOLOGO /$(MAKEFLAGS)
!IF "$(EUAPI_LINK)" != "1"
	@if exist "$(MAKEDIR)\src\libcares\Makefile" cd "$(MAKEDIR)\src\libcares" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\libngttp2\Makefile" cd "$(MAKEDIR)\src\libngttp2" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\libcurl\Makefile" cd "$(MAKEDIR)\src\libcurl" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\luajit\Makefile" cd "$(MAKEDIR)\src\luajit" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
!ENDIF
!IF "$(DLL_INJECT)" == "1"
	@if exist "$(MAKEDIR)\src\detours\Makefile" cd "$(MAKEDIR)\src\detours" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
	@if exist "$(MAKEDIR)\src\lib7z\CPP\7zip\Bundles\Alone" cd "$(MAKEDIR)\src\lib7z\CPP\7zip\Bundles\Alone" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
!ELSE
	@if exist "$(MAKEDIR)\src\lib7z\Makefile" cd "$(MAKEDIR)\src\lib7z" && $(MAKE) /NOLOGO /$(MAKEFLAGS)
!ENDIF
	cd "$(MAKEDIR)\src"
	@$(MAKE) /NOLOGO /$(MAKEFLAGS)
	cd "$(MAKEDIR)"

clean:
	cd "$(MAKEDIR)"
	@if exist "$(MAKEDIR)\src\zlib\Makefile" cd "$(MAKEDIR)\src\zlib" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\libcares\Makefile" cd "$(MAKEDIR)\src\libcares" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\libngttp2\Makefile" cd "$(MAKEDIR)\src\libngttp2" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\libcurl\Makefile" cd "$(MAKEDIR)\src\libcurl" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\luajit\Makefile" cd "$(MAKEDIR)\src\luajit" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\detours\Makefile" cd "$(MAKEDIR)\src\detours" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\lib7z\CPP\7zip\Bundles\Alone" cd "$(MAKEDIR)\src\lib7z\CPP\7zip\Bundles\Alone" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	@if exist "$(MAKEDIR)\src\lib7z\Makefile" cd "$(MAKEDIR)\src\lib7z" && $(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd "$(MAKEDIR)\src"
	@$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
	cd "$(MAKEDIR)"
	-del /q /f /s *~ 2>nul
	-rd /s /q include 2>nul
