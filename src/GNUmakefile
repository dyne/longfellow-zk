CXX ?= g++
AR ?= ar


include sources.mk
SOURCES += util/aes_ecb.cc.o util/log.cc.o util/sha256.cc.o util/crypto.cc.o util/randombytes.cc.o

all: x86

x86: liblongfellow-zk.a

liblongfellow-zk.a: $(SOURCES)
	$(AR) -rcs $@ $(SOURCES)

clean:
	find . -name "*.cc.o" -type f -delete
	rm -f *.a
	rm -f longfellow-zk

# hard-code build information
%.cc.o: %.cc
	$(CXX) -std=c++17 $(CXXFLAGS) -c -o $@ $<
