CXX ?= g++
CXXFLAGS ?= -std=c++17 -O3 -I../src

.PHONY: extract
extract: extract_mdocs
	./extract_mdocs

extract_mdocs: extract_mdocs.cc ../src/cli/encoding.cc
	$(CXX) $(CXXFLAGS) -o extract_mdocs extract_mdocs.cc ../src/cli/encoding.cc

# WIP, dynamic extraction of attributes using the witness code
extract_mdocs_dynamic: extract_mdocs_dynamic.cc ../src/cli/encoding.cc
	$(CXX) $(CXXFLAGS) -o extract_mdocs_dynamic extract_mdocs_dynamic.cc ../src/cli/encoding.cc ../src/liblongfellow-zk.a

clean:
	rm -f extract_mdocs extract_mdocs_dynamic *.json
