load bats_setup

@test "Generate circuit" {
  >&3 $R/longfellow-zk circuit_gen -c 0
}
