CXX ?= g++
AR ?= ar
CFLAGS ?= -I.

include sources.mk

all: x86

x86: liblongfellow-zk.a

liblongfellow-zk.a: CFLAGS += -ggdb -mpclmul -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow
liblongfellow-zk.a: $(SOURCES)
	$(AR) -r $@ $(SOURCES)

clean:
	find . -name "*.cc.o" -type f -delete
	rm -f *.a

# hard-code build information
%.cc.o: %.cc
	$(CXX) -std=c++17 $(CFLAGS) -c -o $@ $<
