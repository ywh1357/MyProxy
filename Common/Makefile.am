lib_LIBRARIES = libmyproxy.a
#moduledir = $(libdir)
#module_PROGRAMS = libmyproxy.so
libmyproxy_a_SOURCES = abstractproxysession.cpp abstractproxytunnel.cpp  basic.cpp  iohelper.cpp  packages.cpp  sslsetting.cpp
#libmyproxy_a_LDFLAGS = -all-static
libmyproxy_a_CXXFLAGS  = -std=c++17 -lboost_system -lbotan-2 -lpthread 
#LIBS = -lssl -lcrypto -lboost_system -lpthread
#nodist_libmyproxy_SOURCES = abstractproxysession.h  basic.h  iohelper.h  sslsetting.h packages.h define.h
AM_CXXFLAGS = -std=c++17 
AUTOMAKE_OPTIONS = foreign
