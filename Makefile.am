AM_CFLAGS = $(GPG_MESSAGE_CFLAGS)
AM_CXXFLAGS = $(GPG_MESSAGE_CFLAGS)
LIBS = $(GPG_MESSAGE_LIBS)

bin_PROGRAMS = gpg_message

gpg_message_SOURCES = gui.cxx main.cxx encrypt.c

if TARGET_LINUX
LINUXDEPLOY = linuxdeploy-devbuild-$(SYSTEM_ARCH).AppImage

$(HOME)/bin/$(LINUXDEPLOY):
	mkdir -p $(HOME)/bin
	wget https://www.lilitun.net/downloads/tools/$(LINUXDEPLOY) -O $(HOME)/bin/$(LINUXDEPLOY)
	chmod 755 $@

GPG_Message-$(VERSION)-$(SYSTEM_ARCH).AppImage: $(HOME)/bin/$(LINUXDEPLOY)
	-chrpath -c gpg_message
#	convert $(top_srcdir)/hopscotch_logo_RGB_symbol_only.png -resize 256x256\> hopscotch_logo_RGB_symbol_only.png
	VERSION=$(VERSION) $(HOME)/bin/$(LINUXDEPLOY)	\
	    --appdir AppDir				\
	    -e gpg_message				\
	    -d linux/gpg_message.desktop		\
	    -i gpg_message.png
	VERSION=$(VERSION) $(HOME)/bin/$(LINUXDEPLOY)	\
	    --appdir AppDir				\
	    -o appimage

install-exec-hook: GPG_Message-$(VERSION)-$(SYSTEM_ARCH).AppImage
	$(INSTALL) -D -m 755 $^ $(DESTDIR)$(bindir)/$^

clean-local:
	rm -rf AppDir
	rm -f GPG_Message-$(VERSION)-$(SYSTEM_ARCH).AppImage
endif

if TARGET_MACOS
resourcesdir = $(prefix)/gpg-message.app/Contents/Resources
resources_DATA = osx/gpg-message.icns

contentsdir = $(prefix)/gpg-message.app/Contents
contents_DATA = osx/PkgInfo osx/Info.plist
endif

.rc.o:
	$(RC) $^ -o $@
%.o : %.rc
	$(RC) $^ -o $@
