#DEBUG = 1


COMPILEROPTS = /W4 /LD /GD /MD /I . /Istl
LINKEROPTS = /incremental:no /opt:nowin98
LINKERLIBS = kernel32.lib wsock32.lib gdi32.lib user32.lib \
                ssleay32.lib libeay32.lib detours.lib

!ifdef DEBUG
COMPILEROPTS = $(COMPILEROPTS) /DDEBUG /Zi /GZ
LINKEROPTS = $(LINKEROPTS) /debug
!else
COMPILEROPTS = $(COMPILEROPTS) /DNDEBUG
LINKEROPTS = $(LINKEROPTS) /release
!endif


all:    stuntour.dll stunrun.exe


stuntour.dll:   stuntour.cpp
        cl $(COMPILEROPTS) /Fe$@ $** $(LINKERLIBS) \
                /link $(LINKEROPTS) /export:LoadDll /export:UnloadDll /export:load_stunnel

stunrun.exe:    stunrun.cpp
        cl /Fe$@ $** $(LINKERLIBS) /link $(LINKEROPTS)
