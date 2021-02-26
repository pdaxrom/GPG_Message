AC_INIT([gpg_message], [1.0])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_PROG_CXX
AC_PROG_OBJC
AC_PROG_LIBTOOL

AC_CHECK_PROGS([RC],[${ac_tool_prefix}windres])

AC_PATH_PROG([PKG_CONFIG], [pkg-config])

PKG_CHECK_MODULES(GPG_MESSAGE, gpgme)

FLTK_INCLUDE=""
FLTK_LIB=""
FLTK_INCLUDE="$(${FLTK_DIR}fltk-config --use-images --cxxflags)"
FLTK_LIB="$(${FLTK_DIR}fltk-config --use-images --ldstaticflags)"

if test "$FLTK_LIB" = ""; then
    AC_MSG_ERROR([fltk-config not found])
fi

ADDONS_LIBS=""

case $host_os in
    cygwin*|mingw*)
        build_for="windows"
        ADDONS_LIBS="-all-static"
    ;;
    darwin*)
        bindir=${prefix}/gpg_message.app/Contents/MacOS
        build_for="macos"
        ADDONS_LIBS="-framework Carbon"
    ;;
    *)
        build_for="linux"
    ;;
esac

GPG_MESSAGE_INCLUDES="$GPG_MESSAGE_INCLUDES $FLTK_INCLUDE"
GPG_MESSAGE_LIBS="$GPG_MESSAGE_LIBS $FLTK_LIB $ADDONS_LIBS"

SYSTEM_ARCH=$host_cpu

AM_CONDITIONAL([TARGET_LINUX], [test "$build_for" = "linux"])
AM_CONDITIONAL([TARGET_WINDOWS], [test "$build_for" = "windows"])
AM_CONDITIONAL([TARGET_MACOS], [test "$build_for" = "macos"])
AC_SUBST(LIBTOOL_DEPS)
AC_SUBST([GPG_MESSAGE_INCLUDES])
AC_SUBST([GPG_MESSAGE_LIBS])
AC_SUBST([SYSTEM_ARCH])
AC_LTDL_DLLIB
AC_CONFIG_FILES([Makefile
                osx/Info.plist
                linux/gpg_message.desktop])
AC_OUTPUT
