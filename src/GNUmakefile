CXX ?= g++
AR ?= ar

CFLAGS ?= -I. -I../vendor/zstd

include sources.mk
SOURCES += util/aes_ecb.cc.o util/log.cc.o util/sha256.cc.o util/crypto.cc.o util/randombytes.cc.o


all: x86

x86: liblongfellow-zk.a

liblongfellow-zk.a: CFLAGS += -ggdb -mpclmul -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow
liblongfellow-zk.a: $(SOURCES)
	$(AR) -r $@ $(SOURCES)

clean:
	find . -name "*.cc.o" -type f -delete
	rm -f *.a
	rm -f longfellow-zk

# hard-code build information
%.cc.o: %.cc
	$(CXX) -std=c++17 $(CFLAGS) -c -o $@ $<
CFLAGS ?= -I. -I../vendor/zstd

include sources.mk
SOURCES += util/aes_ecb.cc.o util/log.cc.o util/sha256.cc.o util/crypto.cc.o util/randombytes.cc.o


all: x86

x86: liblongfellow-zk.a

liblongfellow-zk.a: CFLAGS += -ggdb -mpclmul -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow
liblongfellow-zk.a: $(SOURCES)
	$(AR) -r $@ $(SOURCES)

clean:
	find . -name "*.cc.o" -type f -delete
	rm -f *.a
	rm -f longfellow-zk

# hard-code build information
%.cc.o: %.cc
	$(CXX) -std=c++17 $(CFLAGS) -c -o $@ $<
