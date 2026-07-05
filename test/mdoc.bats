load bats_setup

@test "Run BIP340 circuit integration tests" {
  run make -C "$R" test/bip340_test
  assert_success

  run "$R/test/bip340_test"
  assert_success
  assert_output --partial "bip340 tests passed"
}

# Test 1: Generate circuit for zkspec 0 (used by test mdocs)
@test "Generate circuit for zkspec 0" {
  [[ -r "$T/circuit_0.json" ]] || {
    run $R/longfellow-zk circuit_gen --zkspec 0 -c "$T/circuit_0.json"
    assert_success
  }
  assert_file_exist "$T/circuit_0.json"
  # Verify JSON structure
  command -v jq && {
    run jq -e '.circuit_data_base64' "$T/circuit_0.json"
    assert_success
    run jq -e '._zkspec.index == 0' "$T/circuit_0.json"
    assert_success
  }
}

# Test 2: Prove with mdoc_00 (has 1 attribute - age_over_18)
@test "Generate proof with mdoc_00 (1 attribute)" {
  run $R/longfellow-zk mdoc_prove \
    -c "$T/circuit_0.json" \
    -m "$T/mdoc_00.json" \
    -p "$T/proof_00.json"
  assert_success
  assert_file_exist "$T/proof_00.json"
  # Verify proof JSON structure
  command -v jq && {
    run jq -e '.proof_data_base64' "$T/proof_00.json"
    assert_success
    run jq -e '.proof_size > 0' "$T/proof_00.json"
    assert_success
  }
}

# Test 3: Verify valid proof from mdoc_00
@test "Verify valid proof from mdoc_00" {
  run $R/longfellow-zk mdoc_verify \
    -c "$T/circuit_0.json" \
    -p "$T/proof_00.json"
  assert_success
  assert_output --partial "verification successful"
}

# Test 4: Prove with mdoc_01 (age_over_18 attribute)
@test "Generate proof with mdoc_01 (1 attribute)" {
  run $R/longfellow-zk mdoc_prove \
    -c "$T/circuit_0.json" \
    -m "$T/mdoc_01.json" \
    -p "$T/proof_01.json"
  assert_success
  assert_file_exist "$T/proof_01.json"
}

# Test 5: Verify valid proof from mdoc_01
@test "Verify valid proof from mdoc_01" {
  run $R/longfellow-zk mdoc_verify \
    -c "$T/circuit_0.json" \
    -p "$T/proof_01.json"
  assert_success
  assert_output --partial "verification successful"
}

# Generate circuit for zkspec 1
@test "Generate circuit for zkspec 1" {
  [[ -r "$T/circuit_1.json" ]] || {
    run $R/longfellow-zk circuit_gen --zkspec 1 -c "$T/circuit_1.json"
    assert_success
  }
  assert_file_exist "$T/circuit_1.json"
  # Verify JSON structure
  command -v jq && {
    run jq -e '.circuit_data_base64' "$T/circuit_1.json"
    assert_success
    run jq -e '._zkspec.index == 1' "$T/circuit_1.json"
    assert_success
  }
}

# Test 6: Failure case - mismatched circuit and proof zkspec
@test "Verify fails with wrong zkspec circuit" {
  # Use proof from mdoc_00 which requires zkspec 0
  # Try to verify with wrong circuit
  run $R/longfellow-zk mdoc_verify \
    -c "$T/circuit_1.json" \
    -p "$T/proof_00.json"
  assert_failure
}

# Test 7: Failure case - tampered proof data
@test "Verify fails with tampered proof" {
  # Tamper with proof by changing a byte in the base64 data
  jq '.proof_data_base64 = (.proof_data_base64[0:10] + "AAAA" + .proof_data_base64[14:])' \
    "$T/proof_00.json" > "$T/proof_tampered.json"

  run $R/longfellow-zk mdoc_verify \
    -c "$T/circuit_0.json" \
    -p "$T/proof_tampered.json"
  assert_failure
}

# Test 8: Failure case - wrong public key
@test "Verify fails with wrong public key" {
  # Change public key coordinates
  jq '.public_key.x = "0x0000000000000000000000000000000000000000000000000000000000000001"' \
    "$T/proof_00.json" > "$T/proof_wrong_pk.json"

  run $R/longfellow-zk mdoc_verify \
    -c "$T/circuit_0.json" \
    -p "$T/proof_wrong_pk.json"
  assert_failure
}

# Test 9: Failure case - wrong timestamp
@test "Verify fails with wrong timestamp" {
  command -v jq && {
    # Change timestamp to invalid time (way in the past)
    jq '.time = "1999-01-01T00:00:00Z"' \
       "$T/proof_00.json" > "$T/proof_wrong_time.json"

    run $R/longfellow-zk mdoc_verify \
        -c "$T/circuit_0.json" \
        -p "$T/proof_wrong_time.json"
    assert_failure
  }
}

# Test 10: Failure case - modified attribute value
@test "Verify fails with wrong attribute value" {
  # Change attribute value (age_over_18 from true=0xf5 to false=0xf4)
  jq '.attributes[0].cbor_value = "0xf4"' \
    "$T/proof_00.json" > "$T/proof_wrong_attr.json"

  run $R/longfellow-zk mdoc_verify \
    -c "$T/circuit_0.json" \
    -p "$T/proof_wrong_attr.json"
  assert_failure
}

# Test 11: Generate circuits for multiple zkspecs
@test "Generate circuits for different zkspecs" {
  # Test a few different zkspecs
  for spec in 2 3; do
    run $R/longfellow-zk circuit_gen --zkspec $spec -c "$T/circuit_${spec}.json"
    assert_success
    assert_file_exist "$T/circuit_${spec}.json"
    # Verify zkspec index matches
    command -v jq && {
      run jq -e "._zkspec.index == $spec" "$T/circuit_${spec}.json"
      assert_success
    }
  done
}

# Test 12: Test with different doc types (if available)
@test "Prove and verify with different doc type (mdoc_04 - wallet idcard)" {
  # mdoc_04 has doc_type: com.google.wallet.idcard.1
  run $R/longfellow-zk mdoc_prove \
    -c "$T/circuit_0.json" \
    -m "$T/mdoc_04.json" \
    -p "$T/proof_04.json"
  assert_success

  run $R/longfellow-zk mdoc_verify \
    -c "$T/circuit_0.json" \
    -p "$T/proof_04.json"
  assert_success
  assert_output --partial "verification successful"
}

# Test 13: Test with EU doc type (mdoc_09)
@test "Prove and verify with EU doc type (mdoc_09 - eu.europa.ec.av.1)" {
  # mdoc_09 has doc_type: eu.europa.ec.av.1
  run $R/longfellow-zk mdoc_prove \
    -c "$T/circuit_0.json" \
    -m "$T/mdoc_09.json" \
    -p "$T/proof_09.json"
  assert_success

  run $R/longfellow-zk mdoc_verify \
    -c "$T/circuit_0.json" \
    -p "$T/proof_09.json"
  assert_success
  assert_output --partial "verification successful"
}

# Test 14: Failure case - circuit file doesn't exist
@test "Prove fails with missing circuit file" {
  run $R/longfellow-zk mdoc_prove \
    -c "nonexistent_circuit.json" \
    -m "$T/mdoc_00.json" \
    -p "$T/proof_fail.json"
  assert_failure
}

# Test 15: Failure case - mdoc file doesn't exist
@test "Prove fails with missing mdoc file" {
  run $R/longfellow-zk mdoc_prove \
    -c "$T/circuit_0.json" \
    -m "nonexistent_mdoc.json" \
    -p "$T/proof_fail.json"
  assert_failure
}
