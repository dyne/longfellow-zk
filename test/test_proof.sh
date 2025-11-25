#!/bin/bash
# Test script to generate circuits and proofs for all examples
# This demonstrates the full ZK proof workflow

set -e

cd "$(dirname "$0")"

echo "================================"
echo "ZK Proof Generation Test Suite"
echo "================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Generate circuits for different attribute counts
echo "Step 1: Generating circuits for v6 specs..."
echo "-------------------------------------------"

for attrs in 1 2 3 4; do
    circuit_file="circuit_v6_${attrs}attr.bin"
    if [ ! -f "$circuit_file" ]; then
        echo -n "Generating circuit for $attrs attributes... "
        if ../src/longfellow-zk circuit_gen --zkspec $((attrs - 1)) --circuit "$circuit_file" > /dev/null 2>&1; then
            size=$(stat -f%z "$circuit_file" 2>/dev/null || stat -c%s "$circuit_file" 2>/dev/null)
            echo -e "${GREEN}✓${NC} ($size bytes)"
        else
            echo -e "${RED}✗ Failed${NC}"
            exit 1
        fi
    else
        echo "Circuit for $attrs attributes already exists, skipping..."
    fi
done

echo ""
echo "Step 2: Testing proof generation with example 0..."
echo "---------------------------------------------------"

# Note: Current CLI uses hardcoded example 0, so we pass dummy files
# that match the expected parameters but the actual example data is used internally

echo -n "Generating proof for example 0... "

# The CLI currently requires these files to exist but uses hardcoded data
# We'll pass the extracted files
proof_file="proof_00.bin"

# Clean old proof if exists
rm -f "$proof_file"

# Run prover - note the CLI uses hardcoded example 0 internally
if ../src/longfellow-zk mdoc_prove \
    --circuit circuit_v6_1attr.bin \
    --proof "$proof_file" \
    --public-key pkx_00.txt \
    --transcript transcript_00.bin \
    --time "2024-01-30T09:00:00Z" \
    --doc-type "org.iso.18013.5.1.mDL" > proof_00.log 2>&1; then
    
    if [ -f "$proof_file" ]; then
        size=$(stat -f%z "$proof_file" 2>/dev/null || stat -c%s "$proof_file" 2>/dev/null)
        echo -e "${GREEN}✓${NC} Proof generated ($size bytes)"
    else
        echo -e "${YELLOW}⚠${NC} Command succeeded but no proof file created"
        cat proof_00.log
    fi
else
    echo -e "${RED}✗ Failed${NC}"
    cat proof_00.log
    exit 1
fi

echo ""
echo "Step 3: Verifying proof..."
echo "--------------------------"

echo -n "Verifying proof for example 0... "

if ../src/longfellow-zk mdoc_verify \
    --circuit circuit_v6_1attr.bin \
    --proof "$proof_file" \
    --public-key pkx_00.txt \
    --transcript transcript_00.bin \
    --time "2024-01-30T09:00:00Z" \
    --doc-type "org.iso.18013.5.1.mDL" > verify_00.log 2>&1; then
    
    echo -e "${GREEN}✓${NC} Proof verified successfully"
else
    echo -e "${RED}✗ Verification failed${NC}"
    cat verify_00.log
    exit 1
fi

echo ""
echo "================================"
echo -e "${GREEN}All tests passed!${NC}"
echo "================================"
echo ""
echo "Generated files:"
ls -lh circuit_*.bin proof_*.bin 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
echo ""
