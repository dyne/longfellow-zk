use std::{env, fs};

use core_algebra::{ec, AlgebraicField, Curve, Nat, SerializableField, SupportsU128Conversions, SupportsU64Conversions, GF2_16_BASIS_V1};
use runtime_algebra::{gf2_128::Gf2_128Field, lch14::Lch14, lch14_reed_solomon::Lch14ReedSolomon, p256::P256Field, subfield::BinarySubfield, Interpolator, Q256Field, RuntimeNat, RuntimeSecp256r1, Subfield, SupportsSampling};
use runtime_random::{RandomEngine, Transcript};
use runtime_merkle::{commit as merkle_commit, open as merkle_open, verify as merkle_verify, verify_proof, Digest, MerkleHeap};
use sha2::Digest as ShaDigest;
use compile_algebra::p256::P256Field as CompileP256Field;
use core_proto::{circuit::{Circuit as ProtoCircuit, RawCircuit, compute_id}, reader::CircuitReader, writer::CircuitWriter, FieldID, Layer, TermDelta};
use runtime_ligero::{LigeroConfig, LigeroParam, LigeroProver, LigeroQuadraticConstraint, LigeroVerifier};
use runtime_algebra::lch14_reed_solomon::Lch14InterpolatorFactory;
use runtime_zk::{ZkProver, ZkVerifier, common::ZkContext};

// Bounded canonical circuit from Google Rust `test_zk_rfc_testvector1`.
const ZK_RFC_CIRCUIT: &[u8] = &[
    0x01, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x5f, 0x8d, 0x9e,
    0x33, 0x1b, 0x0e, 0x60, 0x11, 0x46, 0x46, 0x5e, 0x20, 0x7c, 0xb6, 0xbf, 0x38, 0x73, 0xac,
    0xfe, 0x5d, 0x0b, 0xf0, 0xe3, 0x26, 0x18, 0x0d, 0xbb, 0xaf, 0xcc, 0x48, 0x8c, 0xb6,
];

fn record(out: &mut Vec<u8>, key: u32, value: &[u8]) {
    out.extend_from_slice(b"LFP2"); out.extend_from_slice(&[1, 1]);
    out.extend_from_slice(&((5 + value.len()) as u32).to_le_bytes());
    out.extend_from_slice(&key.to_le_bytes()); out.push(1); out.extend_from_slice(value);
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 { std::process::exit(64); }
    if fs::read(&args[1]).is_err() { std::process::exit(65); }
    let binary = [1u8, 2, 3]; let mut out = Vec::new();
    let mut empty = Transcript::new(&[]); record(&mut out, 1, &empty.bytes(31));
    let mut boundaries = Transcript::new(&binary);
    boundaries.write0(0); boundaries.write0(31); boundaries.write0(32); boundaries.write0(33);
    record(&mut out, 2, &boundaries.bytes(33));
    let f = P256Field::new(); let one = f.one(); let seven = f.u64_to_element(7);
    let zk_rfc_field = Gf2_128Field::new();
    let zk_rfc_circuit = CircuitReader::new(&zk_rfc_field, FieldID::Gf2_128).from_bytes(ZK_RFC_CIRCUIT, false).expect("RFC circuit must parse").0;
    let zk_rfc_prover = ZkProver::new(zk_rfc_circuit, LigeroConfig { rateinv: 4, nreq: 6, block_enc: 128 });
    let zk_rfc_subfield = BinarySubfield::new(&GF2_16_BASIS_V1);
    let zk_rfc_interpolator = Lch14InterpolatorFactory::new(&zk_rfc_field, &zk_rfc_subfield);
    struct ZkRfcRng;
    impl RandomEngine for ZkRfcRng {
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            let mut bytes = vec![0; len];
            if !bytes.is_empty() { bytes[0] = 2; }
            bytes
        }
    }
    let zk_rfc_n = zk_rfc_subfield.embed(5);
    let zk_rfc_m = zk_rfc_subfield.embed(6);
    let mut zk_rfc_inputs = vec![zk_rfc_field.one(); zk_rfc_prover.circuit.raw.ninput];
    zk_rfc_inputs[1] = zk_rfc_n;
    zk_rfc_inputs[2] = zk_rfc_m;
    zk_rfc_inputs[3] = zk_rfc_field.mulf(&zk_rfc_field.addf(&zk_rfc_n, &zk_rfc_m), &zk_rfc_field.u128_to_element(2));
    let mut zk_rfc_transcript = Transcript::new(b"test");
    let mut zk_rfc_rng = ZkRfcRng;
    let (zk_rfc_commit, _zk_rfc_geometry) = zk_rfc_prover.commit(
        &zk_rfc_inputs[zk_rfc_prover.circuit.raw.npublic_input..],
        &ZkContext { f: &zk_rfc_field, make_interpolator: &zk_rfc_interpolator },
        &mut zk_rfc_transcript,
        &mut zk_rfc_rng,
        &zk_rfc_subfield,
    );
    let zk_rfc_public = zk_rfc_inputs[..zk_rfc_prover.circuit.raw.npublic_input].to_vec();
    let zk_rfc_witness = zk_rfc_inputs[zk_rfc_prover.circuit.raw.npublic_input..].to_vec();
    let zk_rfc_proof = zk_rfc_prover.prove(zk_rfc_public.clone(), zk_rfc_witness, &zk_rfc_commit,
        &mut zk_rfc_transcript, &ZkContext { f: &zk_rfc_field, make_interpolator: &zk_rfc_interpolator })
        .expect("RFC ZK proof must succeed");
    let zk_rfc_verifier_circuit = CircuitReader::new(&zk_rfc_field, FieldID::Gf2_128).from_bytes(ZK_RFC_CIRCUIT, false).expect("RFC circuit must reparse").0;
    let zk_rfc_verifier = ZkVerifier::new(zk_rfc_verifier_circuit, LigeroConfig { rateinv: 4, nreq: 6, block_enc: 128 });
    let mut zk_rfc_verify_transcript = Transcript::new(b"test");
    let zk_rfc_ctx = ZkContext { f: &zk_rfc_field, make_interpolator: &zk_rfc_interpolator };
    zk_rfc_verifier.recv_commitment(&zk_rfc_proof, &mut zk_rfc_verify_transcript, &zk_rfc_ctx);
    let zk_rfc_verified = zk_rfc_verifier.verify(zk_rfc_public, &zk_rfc_proof, &mut zk_rfc_verify_transcript, &zk_rfc_ctx).is_ok();
    let mut zk_rfc_tampered = zk_rfc_proof.clone(); zk_rfc_tampered.com.root.data[0] ^= 1;
    let mut zk_rfc_tampered_transcript = Transcript::new(b"test");
    zk_rfc_verifier.recv_commitment(&zk_rfc_tampered, &mut zk_rfc_tampered_transcript, &zk_rfc_ctx);
    let zk_rfc_tampered_verified = zk_rfc_verifier.verify(
        zk_rfc_inputs[..zk_rfc_prover.circuit.raw.npublic_input].to_vec(),
        &zk_rfc_tampered, &mut zk_rfc_tampered_transcript, &zk_rfc_ctx).is_ok();
    let mut zk_rfc_value = zk_rfc_proof.com.root.data.to_vec();
    zk_rfc_value.extend([u8::from(zk_rfc_verified), u8::from(zk_rfc_tampered_verified)]);
    record(&mut out, 70, &zk_rfc_value);
    let mut typed = Transcript::new(&binary); typed.write_elt_field(&one, &f); typed.write_elt_field_slice(&[one, seven], &f);
    record(&mut out, 3, &typed.bytes(32));
    let mut cloned = Transcript::new(&binary); let _ = cloned.bytes(5); let mut clone = cloned.clone();
    let mut clone_bytes = cloned.bytes(29); clone_bytes.extend(clone.bytes(29)); record(&mut out, 4, &clone_bytes);
    let mut changed = Transcript::new(&binary); let _ = changed.bytes(16); let mut changed_clone = changed.clone(); changed_clone.write_bytes(&binary);
    let mut changed_bytes = changed.bytes(33); changed_bytes.extend(changed_clone.bytes(33)); record(&mut out, 5, &changed_bytes);
    let mut compatibility = Transcript::new(&binary); record(&mut out, 6, &compatibility.bytes(25600));
    let gf = Gf2_128Field::new(); let ga = gf.u128_to_element(0x8000000000000043); let gb = gf.u128_to_element(0x123456789abcdef0);
    let mut gf_values = gf.to_bytes(&gf.addf(&ga, &gb)); gf_values.extend(gf.to_bytes(&gf.mulf(&ga, &gb))); gf_values.extend(gf.to_bytes(&gf.invert(&ga))); record(&mut out, 10, &gf_values);
    let pa = f.u64_to_element(7); let pb = f.u64_to_element(19);
    let mut p_values = f.to_bytes(&f.addf(&pa, &pb)); p_values.extend(f.to_bytes(&f.mulf(&pa, &pb))); p_values.extend(f.to_bytes(&f.invert(&pa))); record(&mut out, 11, &p_values);
    let q = Q256Field::new(); let qa = q.u64_to_element(7); let qb = q.u64_to_element(19);
    let mut q_values = q.to_bytes(&q.addf(&qa, &qb)); q_values.extend(q.to_bytes(&q.mulf(&qa, &qb))); q_values.extend(q.to_bytes(&q.invert(&qa))); record(&mut out, 12, &q_values);
    record(&mut out, 13, &[u8::from(f.bytes_to_element(&[0xff; 32]).is_ok())]);
    let subfield = BinarySubfield::new(&GF2_16_BASIS_V1);
    let mut boundary_values = Vec::new(); for value in [0, 1, 0xa55a] { boundary_values.extend(subfield.to_bytes(&subfield.embed(value))); }
    for value in [f.zero(), f.one(), f.u64_to_element(0x80000000)] { boundary_values.extend(f.to_bytes(&value)); }
    for value in [q.zero(), q.one(), q.u64_to_element(0x80000000)] { boundary_values.extend(q.to_bytes(&value)); }
    record(&mut out, 14, &boundary_values);
    // C++ only exposes fixed-width decode pointers; wrong-length decoding is
    // intentionally not claimed as cross-language parity.
    let mut extended_fields = Vec::new();
    let a = f.u64_to_element(23); let b = f.u64_to_element(7); extended_fields.extend(f.to_bytes(&f.subf(&a, &b))); extended_fields.extend(f.to_bytes(&f.mulf(&a, &a))); extended_fields.extend(f.to_bytes(&f.addf(&a, &a))); let encoded = f.to_bytes(&a); extended_fields.extend([u8::from(f.zero() == f.zero()), u8::from(f.one() == f.one()), u8::from(a == f.u64_to_element(23)), u8::from(f.bytes_to_element(&encoded).is_ok())]);
    let a = q.u64_to_element(23); let b = q.u64_to_element(7); extended_fields.extend(q.to_bytes(&q.subf(&a, &b))); extended_fields.extend(q.to_bytes(&q.mulf(&a, &a))); extended_fields.extend(q.to_bytes(&q.addf(&a, &a))); let encoded = q.to_bytes(&a); extended_fields.extend([u8::from(q.zero() == q.zero()), u8::from(q.one() == q.one()), u8::from(a == q.u64_to_element(23)), u8::from(q.bytes_to_element(&encoded).is_ok())]);
    record(&mut out, 15, &extended_fields);
    let lch = Lch14::new(&gf, &subfield);
    let mut fft_values: Vec<_> = (1..=8).map(|i| gf.u128_to_element(i)).collect(); lch.fft(3, 1, &mut fft_values);
    let mut coding_values = Vec::new(); for value in &fft_values { coding_values.extend(gf.to_bytes(value)); } lch.ifft(3, 1, &mut fft_values); for value in &fft_values { coding_values.extend(gf.to_bytes(value)); } record(&mut out, 20, &coding_values);
    let mut rs_values: Vec<_> = (1..=5).map(|i| gf.u128_to_element(i)).collect(); rs_values.resize(13, gf.zero()); let rs = Lch14ReedSolomon::new(5, 13, &gf, &subfield); rs.interpolate(&mut rs_values);
    let mut rs_output = Vec::new(); for value in &rs_values { rs_output.extend(gf.to_bytes(value)); } record(&mut out, 21, &rs_output);
    let mut rs_boundary: Vec<_> = (1..=8).map(|i| gf.u128_to_element(i)).collect(); let rs_identity = Lch14ReedSolomon::new(8, 8, &gf, &subfield); rs_identity.interpolate(&mut rs_boundary); let mut rs_boundary_output = Vec::new(); for value in &rs_boundary { rs_boundary_output.extend(gf.to_bytes(value)); } record(&mut out, 24, &rs_boundary_output);
    let mut rs_three: Vec<_> = (1..=3).map(|i| gf.u128_to_element(i * 17)).collect(); rs_three.resize(8, gf.zero()); let rs_three_to_eight = Lch14ReedSolomon::new(3, 8, &gf, &subfield); rs_three_to_eight.interpolate(&mut rs_three); let mut rs_three_output = Vec::new(); for value in &rs_three { rs_three_output.extend(gf.to_bytes(value)); } record(&mut out, 25, &rs_three_output);
    let mut basis_values = Vec::new(); for value in &GF2_16_BASIS_V1 { basis_values.extend(gf.to_bytes(&gf.u128_to_element(*value))); } record(&mut out, 22, &basis_values);
    let mut short_fft = vec![gf.one(), gf.zero(), gf.zero(), gf.zero()]; lch.fft(2, 0, &mut short_fft); let mut extra_coding = Vec::new(); for value in &short_fft { extra_coding.extend(gf.to_bytes(value)); } lch.ifft(2, 0, &mut short_fft); for value in &short_fft { extra_coding.extend(gf.to_bytes(value)); } record(&mut out, 23, &extra_coding);
    let curve = RuntimeSecp256r1::new(&f); let generator = ec::projective(&curve, &f, curve.g()); let doubled = ec::double(&curve, &f, &generator); let tripled = ec::scalar_mul(&curve, &f, 256, &RuntimeNat::from_u64(3), &generator);
    let mut curve_values = Vec::new(); for point in [&generator, &doubled, &tripled] { let (x, y) = ec::affine(&f, point); curve_values.extend(f.to_bytes(&x)); curve_values.extend(f.to_bytes(&y)); } record(&mut out, 30, &curve_values);
    let scalar_two = ec::scalar_mul(&curve, &f, 256, &RuntimeNat::from_u64(2), &generator); let mut order_minus_one = curve.order().to_limbs(); order_minus_one[0] -= 1; let scalar_boundary = ec::scalar_mul(&curve, &f, 256, &RuntimeNat::from_limbs(&order_minus_one), &generator); let mut curve_scalars = Vec::new(); for point in [&scalar_two, &scalar_boundary] { let (x, y) = ec::affine(&f, point); curve_scalars.extend(f.to_bytes(&x)); curve_scalars.extend(f.to_bytes(&y)); } record(&mut out, 32, &curve_scalars);
    let added = ec::add(&curve, &f, &generator, &scalar_two); let (x, y) = ec::affine(&f, &added); let mut curve_add = f.to_bytes(&x); curve_add.extend(f.to_bytes(&y)); record(&mut out, 35, &curve_add);
    let seeded = ec::scalar_mul_bytes(&curve, &f, &[0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01], &generator); let (x, y) = ec::affine(&f, &seeded); let mut seeded_curve = f.to_bytes(&x); seeded_curve.extend(f.to_bytes(&y)); record(&mut out, 33, &seeded_curve);
    let mut negative = generator.clone(); negative.1 = f.neg(&negative.1); let (x, y) = ec::affine(&f, &negative); let mut curve_law = f.to_bytes(&x); curve_law.extend(f.to_bytes(&y)); record(&mut out, 31, &curve_law);
    let identity = ec::zero(&f); record(&mut out, 34, &[u8::from(identity.2 == f.zero())]);
    for count in [4usize, 5] {
        let leaves: Vec<_> = (1..=count).map(|index| { let mut digest = Digest::default(); digest.data[0] = index as u8; digest }).collect();
        let heap = MerkleHeap::new(&leaves); let root = heap.root(); let positions = [1usize, count - 1];
        let mut proof = heap.generate_proof(&positions); let opened = [(positions[0], leaves[positions[0]]), (positions[1], leaves[positions[1]])];
        let mut value = root.data.to_vec(); for node in &proof { value.extend(node.data); }
        value.push(u8::from(verify_proof(count, &root, &proof, &opened).is_ok()));
        proof.push(Digest::default()); value.push(u8::from(verify_proof(count, &root, &proof, &opened).is_ok()));
        record(&mut out, if count == 4 { 40 } else { 41 }, &value);
    }
    struct CounterRng { next: u8 }
    impl RandomEngine for CounterRng { fn bytes(&mut self, len: usize) -> Vec<u8> { (0..len).map(|_| { let value = self.next; self.next = self.next.wrapping_add(1); value }).collect() } }
    let mut merkle_rng = CounterRng { next: 0 };
    let (commitment, commitment_root) = merkle_commit(4, &mut merkle_rng, |_index, sha| sha.update([0xa5, 0x5a]));
    let commitment_positions = [1usize, 3]; let mut commitment_proof = merkle_open(&commitment, &commitment_positions);
    let mut commitment_value = commitment_root.data.to_vec(); for nonce in &commitment_proof.nonce { commitment_value.extend(nonce.bytes); } for node in &commitment_proof.path { commitment_value.extend(node.data); }
    commitment_value.push(u8::from(merkle_verify(4, &commitment_root, &commitment_positions, &commitment_proof, |_r, _index, sha| sha.update([0xa5, 0x5a])).is_ok()));
    commitment_proof.path.push(Digest::default());
    commitment_value.push(u8::from(merkle_verify(4, &commitment_root, &commitment_positions, &commitment_proof, |_r, _index, sha| sha.update([0xa5, 0x5a])).is_ok()));
    record(&mut out, 42, &commitment_value);
    let circuit_field = CompileP256Field::new();
    let raw = RawCircuit { ninput: 2, npublic_input: 1, noutput: 2, logv: 1, subfield_boundary: 1,
        constants: vec![circuit_field.one(), circuit_field.zero()],
        layers: vec![Layer::new(2, 1, vec![TermDelta { g: 0, h: [0, 1], k_index: 0 }, TermDelta { g: 1, h: [1, 0], k_index: 1 }], vec![vec![0, 1]], vec![0])] };
    let circuit = ProtoCircuit { id: compute_id(&circuit_field, &raw), raw };
    let circuit_writer = CircuitWriter::new(&circuit_field, FieldID::P256); let lfc1 = circuit_writer.to_bytes_lfc1(&circuit); let mut lfc2 = circuit_writer.to_bytes_lfc2(&circuit);
    let mut circuit_value = lfc1.clone(); circuit_value.extend(&lfc2); circuit_value.extend(circuit.id);
    let circuit_reader = CircuitReader::new(&circuit_field, FieldID::P256);
    circuit_value.push(u8::from(circuit_reader.from_bytes(&lfc1, true).is_ok())); circuit_value.push(u8::from(circuit_reader.from_bytes(&lfc2, true).is_ok())); lfc2.push(0); circuit_value.push(u8::from(matches!(circuit_reader.from_bytes(&lfc2, true), Ok((_, remaining)) if remaining.is_empty()))); lfc2.pop(); lfc2.insert(4, 0x80); circuit_value.push(u8::from(circuit_reader.from_bytes(&lfc2, true).is_ok())); let mut truncated_lfc1 = lfc1.clone(); truncated_lfc1.pop(); circuit_value.push(u8::from(circuit_reader.from_bytes(&truncated_lfc1, true).is_ok())); let mut trailing_lfc1 = lfc1.clone(); trailing_lfc1.push(0); circuit_value.push(u8::from(matches!(circuit_reader.from_bytes(&trailing_lfc1, true), Ok((_, remaining)) if remaining.is_empty())));
    record(&mut out, 50, &circuit_value);
    let ligero_interpolator = Lch14InterpolatorFactory::new(&gf, &subfield);
    let ligero_geometry = LigeroParam::new(8, 2, LigeroConfig { rateinv: 4, nreq: 2, block_enc: 64 }, &ligero_interpolator);
    record(&mut out, 60, &[ligero_geometry.geom.block as u8, ligero_geometry.geom.dblock as u8, ligero_geometry.geom.block_enc as u8, ligero_geometry.w as u8, ligero_geometry.geom.nrow as u8, ligero_geometry.geom.nreq as u8, ligero_geometry.geom.mc_pathlen as u8]);
    let mut ligero_w: Vec<_> = (0..ligero_geometry.nw).map(|_| gf.sample(|count| merkle_rng.bytes(count))).collect();
    let ligero_lqc: Vec<_> = (0..ligero_geometry.nq).map(|index| LigeroQuadraticConstraint { x: 0, y: 0, z: 2 * index + 1 }).collect();
    for constraint in &ligero_lqc { ligero_w[constraint.z] = gf.mulf(&ligero_w[constraint.x], &ligero_w[constraint.y]); }
    let mut ligero_transcript = Transcript::new(b"test");
    let (ligero_prover, ligero_commitment) = LigeroProver::commit(0, &ligero_w, ligero_geometry, &mut ligero_transcript, &ligero_lqc, &ligero_interpolator, &mut merkle_rng, &gf, &subfield);
    record(&mut out, 61, &ligero_commitment.root.data);
    let ligero_b = vec![gf.zero()]; let ligero_statement = Digest { data: [0xba, 0xad, 0xf0, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
    let ligero_proof = ligero_prover.prove(&ligero_b, &mut ligero_transcript, &[], &ligero_statement, &ligero_lqc, &ligero_interpolator, &gf);
    let mut ligero_proof_value = ligero_commitment.root.data.to_vec(); ligero_proof_value.push(ligero_proof.merkle.path.len() as u8); record(&mut out, 62, &ligero_proof_value);
    let ligero_verify_geometry = LigeroParam::new(8, 2, LigeroConfig { rateinv: 4, nreq: 2, block_enc: 64 }, &ligero_interpolator); let mut ligero_verify_transcript = Transcript::new(b"test"); let mut ligero_verifier = LigeroVerifier::new(&mut ligero_verify_transcript, &ligero_verify_geometry);
    ligero_verifier.receive_commitment(&ligero_commitment); let ligero_ok = ligero_verifier.verify(&ligero_b, &ligero_commitment, &ligero_proof, &[], &ligero_statement, &ligero_lqc, &ligero_interpolator, &gf).is_ok(); let mut ligero_tampered = ligero_proof.clone(); ligero_tampered.merkle.path[0].data[0] ^= 1; let mut ligero_tampered_transcript = Transcript::new(b"test"); let mut ligero_tampered_verifier = LigeroVerifier::new(&mut ligero_tampered_transcript, &ligero_verify_geometry); ligero_tampered_verifier.receive_commitment(&ligero_commitment); let ligero_tampered_ok = ligero_tampered_verifier.verify(&ligero_b, &ligero_commitment, &ligero_tampered, &[], &ligero_statement, &ligero_lqc, &ligero_interpolator, &gf).is_ok(); record(&mut out, 63, &[u8::from(ligero_ok), u8::from(ligero_tampered_ok)]);
    if fs::write(&args[2], out).is_err() { std::process::exit(66); }
}
