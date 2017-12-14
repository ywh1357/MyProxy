AUTOMAKE_OPTIONS = foreign
#INCLUDES= -I../Common
bin_PROGRAMS = myproxyserver
myproxyserver_SOURCES = main.cpp server.cpp
myproxyserver_LDADD = -L../Common/ -lmyproxy -lssl -lcrypto -lpthread -lboost_system
AM_CPPFLAGS = --std=c++17 -I../Common
