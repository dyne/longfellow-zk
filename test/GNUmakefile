CXX := g++
CXXFLAGS := -std=c++17 -O3 -I../src

extract_mdocs: extract_mdocs.cc ../src/cli/encoding.cc
	$(CXX) $(CXXFLAGS) -o extract_mdocs extract_mdocs.cc ../src/cli/encoding.cc

.PHONY: extract
extract: extract_mdocs
	./extract_mdocs

.PHONY: clean
clean:
	rm -f extract_mdocs mdoc_*.bin mdoc_*.txt mdoc_*.json transcript_*.bin pk*.txt

.PHONY: distclean
distclean: clean
	rm -f *.bin *.txt circuit_*.bin
