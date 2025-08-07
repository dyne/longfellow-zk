LDADD := ../../src/liblongfellow-zk.a
LDADD += ../../vendor/zstd/libzstd.a
CXX ?= g++
CXXFLAGS ?= -ggdb -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow
CXXFLAGS += -I. -I../../vendor/longfellow-zk/lib -std=c++17


all:
	$(CXX) $(CXXFLAGS) -o ../longfellow-zk main.cc $(LDADD)