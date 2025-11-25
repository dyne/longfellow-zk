LDADD := ../../src/liblongfellow-zk.a
LDADD += ../../vendor/zstd/lib/libzstd.a
CXX ?= g++

SOURCES := main.cc encoding.cc nanobench.cc
OBJECTS := $(SOURCES:.cc=.o)
HEADERS := encoding.h nanobench.h json.hpp CLI11.hpp

.PHONY: all clean

all: ../../longfellow-zk

../../longfellow-zk: $(OBJECTS) $(LDADD)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJECTS) $(LDADD)

# Object files depend on their source and all headers
%.o: %.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECTS) ../../longfellow-zk
