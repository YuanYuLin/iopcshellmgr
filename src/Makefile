
TARGET = iopcshellmgr

#CFLAGS += -I$(SDKSTAGE)/usr/include/libiopcdao
CFLAGS += -I$(SDKSTAGE)/usr/include/libiopcmisc
#CFLAGS += -I$(SDKSTAGE)/usr/include/libiopctask
#CFLAGS += -I$(SDKSTAGE)/usr/include/libiopccmd
CFLAGS += -I$(SDKSTAGE)/usr/include/libiopcnet
#CFLAGS += -I$(SDKSTAGE)/usr/include/libjsonc
CFLAGS += -I$(SDKSTAGE)/usr/include/
CFLAGS += -I./include/

LDFLAGS += -L$(CC_SYSROOT)/usr/lib/ 
LDFLAGS += -L$(SDKSTAGE)/usr/lib/ 
LDFLAGS += -L$(SDKSTAGE)/lib/ 
LDFLAGS += -lc -lpthread -lrt -lz -lbz2
LDFLAGS += -ljson-c -lutil
#LDFLAGS += -llua5.1
#LDFLAGS += -ldb -ltokyocabinet -ltokyotyrant 
LDFLAGS += -liopcmisc -liopcnet

SRC = 
SRC += main.c

include Makefile.include.app
