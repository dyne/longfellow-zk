use std::path::Path;

use circuits_boolean::Boolean;
use compile_algebra::p256::P256Field;
use compile_eval::compute_id;
use compile_logic::LogicIO;
use core_proto::{reader::CircuitReader, writer::CircuitWriter, FieldID};

/// Validate a complete, canonical P-256 LFC2 circuit, including its circuit ID.
pub fn validate_lfc2(bytes: &[u8]) -> Result<(), String> {
    let field = P256Field::new();
    let reader = CircuitReader::new(&field, FieldID::P256);
    let (circuit, remaining) = reader.from_bytes(bytes, true)?;
    if !remaining.is_empty() {
        return Err(format!("LFC2 fixture has {} trailing bytes", remaining.len()));
    }
    if compute_id(&field, &circuit.raw) != circuit.id {
        return Err("LFC2 fixture circuit ID does not match its contents".to_owned());
    }
    Ok(())
}

/// Create the canonical upstream Rust LFC2 fixture used for reciprocal C++ reads.
#[must_use]
pub fn canonical_rust_lfc2() -> Vec<u8> {
    let field = P256Field::new();
    let (circuit, _, _) = compile_compiler::compile(&field, |iologic| {
        let boolean = Boolean::new(&iologic);
        let a = iologic.input(1);
        let b = iologic.input(2);
        let ab = boolean.of_eltw(a);
        let bb = boolean.of_eltw(b);
        let x = boolean.xorb(&ab, &bb);
        (boolean.assert_true("assert_x", &x), 1, 0)
    });
    CircuitWriter::new(&field, FieldID::P256).to_bytes_lfc2(&circuit)
}

/// Read the C++ fixture under the same strict contract, then write the Rust fixture.
pub fn exchange(cpp_fixture: &Path, rust_fixture: &Path) -> Result<(), String> {
    let cpp_bytes = std::fs::read(cpp_fixture)
        .map_err(|error| format!("read C++ LFC2 fixture {}: {error}", cpp_fixture.display()))?;
    validate_lfc2(&cpp_bytes)?;

    let rust_bytes = canonical_rust_lfc2();
    validate_lfc2(&rust_bytes)?;
    std::fs::write(rust_fixture, rust_bytes)
        .map_err(|error| format!("write Rust LFC2 fixture {}: {error}", rust_fixture.display()))
}

#[cfg(test)]
mod tests {
    use super::{canonical_rust_lfc2, validate_lfc2};

    #[test]
    fn canonical_rust_fixture_has_valid_id_and_no_remaining_bytes() {
        let bytes = canonical_rust_lfc2();
        assert!(bytes.starts_with(b"LFC2"));
        validate_lfc2(&bytes).unwrap();
    }

    #[test]
    fn complete_fixture_contract_rejects_trailing_bytes() {
        let mut bytes = canonical_rust_lfc2();
        bytes.push(0);
        assert!(validate_lfc2(&bytes).unwrap_err().contains("trailing bytes"));
    }
}
