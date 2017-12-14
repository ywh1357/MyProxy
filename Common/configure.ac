#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(libmyproxy, 0.1, ywh1357@gmail.com)
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([sslsetting.cpp])
#AC_CONFIG_HEADERS([config.h])

AC_PROG_RANLIB
AC_PROG_LIBTOOL

# Checks for programs.
AC_PROG_CXX
#AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(ssl,crypto,pthread,boost_system)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
#AC_CHECK_HEADER_STDBOOL
#AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
#AC_FUNC_ERROR_AT_LINE
#AC_CHECK_FUNCS([socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
