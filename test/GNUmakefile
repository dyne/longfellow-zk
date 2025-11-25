CXX := g++
CXXFLAGS := -std=c++17 -O3 -I../src

extract_mdocs: extract_mdocs.cc
	$(CXX) $(CXXFLAGS) -o extract_mdocs extract_mdocs.cc

.PHONY: extract
extract: extract_mdocs
	./extract_mdocs

.PHONY: clean
clean:
	rm -f extract_mdocs mdoc_*.bin mdoc_*.txt transcript_*.bin pk*.txt

.PHONY: distclean
distclean: clean
	rm -f *.bin *.txt circuit_*.bin
