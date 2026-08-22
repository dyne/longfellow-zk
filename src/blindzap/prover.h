// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_PROVER_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_PROVER_H_
#include <array>
#include <memory>
#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "blindzap/envelope.h"
#include "circuits/blindzap/blindzap_circuit.h"
#include "circuits/blindzap/blindzap_witness.h"
#include "circuits/bip340/bip340_guard.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "util/byte_cursor.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
namespace proofs {
using BlindzapField = Fp256k1Base; using BlindzapEC = P256k1; using BlindzapBackend = CompilerBackend<BlindzapField>; using BlindzapLogic = Logic<BlindzapField, BlindzapBackend>; using BlindzapRelation = BlindzapCircuitV1<BlindzapLogic, BlindzapField, BlindzapEC>;
template <size_t Keys>
inline std::unique_ptr<Circuit<BlindzapField>> BlindzapBuildCircuit(QuadCircuit<BlindzapField>* q) { BlindzapBackend b(q); BlindzapLogic l(&b,p256k1_base); BlindzapMultiCircuitV1<BlindzapLogic, BlindzapField, BlindzapEC, Keys> r(l,p256k1); std::array<std::array<BlindzapLogic::EltW,20>, Keys> p; for(auto& key:p)for(auto& x:key)x=l.eltw_input(); q->private_input(); std::array<typename BlindzapRelation::Witness, Keys> w; for(auto& x:w)x.input(l); auto symbol_scope=q->assertion_scope("blindzap/programs/relations"); r.assert_programs(p,w); return q->mkcircuit(1); }
inline std::unique_ptr<Circuit<BlindzapField>> BlindzapBuildCircuit(QuadCircuit<BlindzapField>* q) { return BlindzapBuildCircuit<1>(q); }
inline size_t BlindzapBlock(const Circuit<BlindzapField>& c, const QuadCircuit<BlindzapField>& q) { return c.ninputs-c.npub_in+q.nquad_terms_+1; }
template <size_t Keys>
inline const std::array<uint8_t, 32>& BlindzapExpectedCircuitDigest() {
  static const std::array<uint8_t, 32> digest = [] {
    QuadCircuit<BlindzapField> q(p256k1_base);
    auto circuit = BlindzapBuildCircuit<Keys>(&q);
    return BlindzapCircuitDigest(*circuit, p256k1_base, SECP_ID);
  }();
  return digest;
}
inline bool BlindzapProofSupported(const BlindzapEnvelopeV1& envelope) {
  std::vector<std::array<uint8_t, 20>> programs;
  if (!BlindzapDistinctPrograms(envelope.statement, &programs)) return false;
  switch (programs.size()) {
    case 1: return BlindzapProofIdentityMatches(
        envelope.proof, BlindzapExpectedCircuitDigest<1>());
    case 2: return BlindzapProofIdentityMatches(
        envelope.proof, BlindzapExpectedCircuitDigest<2>());
    default: return false;
  }
}
template <size_t Keys>
inline bool BlindzapProveKeys(const std::vector<std::array<uint8_t, 32>>& secrets, BlindzapStatementV1 statement, BlindzapEnvelopeV1* out) { std::vector<std::array<uint8_t,20>> programs; if(!out || secrets.size()!=Keys || !BlindzapDistinctPrograms(statement,&programs) || programs.size()!=Keys)return false; std::array<BlindzapWitnessV1<BlindzapField,BlindzapEC>,Keys> witnesses; for(size_t i=0;i<Keys;++i) { bool found=false; for(size_t j=0;j<Keys;++j) { BlindzapWitnessV1<BlindzapField,BlindzapEC> candidate; if(!candidate.compute(p256k1,secrets[j].data(),secrets[j].size()))return false; if(candidate.program()==programs[i]) { if(found)return false; witnesses[i]=candidate; found=true; } } if(!found)return false; } QuadCircuit<BlindzapField> q(p256k1_base); auto c=BlindzapBuildCircuit<Keys>(&q); const size_t block=BlindzapBlock(*c,q); if(!check_crt_block_enc<CRT256<BlindzapField>>(block).empty())return false; auto in=std::make_unique<Dense<BlindzapField>>(1,c->ninputs); { DenseFiller<BlindzapField> f(*in); f.push_back(p256k1_base.one()); BitPluckerEncoder<BlindzapField,8> encoder(p256k1_base); for(const auto& program:programs)for(auto x:program)f.push_back(encoder.encode(x)); for(const auto& witness:witnesses)witness.fill_witness(f); } using CF=CrtConvolutionFactory<CRT256<BlindzapField>,BlindzapField>; using RS=ReedSolomonFactory<BlindzapField,CF>; CF cf(p256k1_base); RS rs(cf,p256k1_base); ZkProof<BlindzapField> p(*c,4,128,block); ZkProver<BlindzapField,RS> prover(*c,p256k1_base,rs); SecureRandomEngine rng; BlindzapEnvelopeV1 e; e.statement=std::move(statement); e.proof.circuit_digest=BlindzapExpectedCircuitDigest<Keys>(); const auto seed=BlindzapTranscriptSeed(e.statement,e.proof); Transcript t(seed.data(),seed.size()); prover.commit(p,*in,t,rng); if(!prover.prove(p,*in,t))return false; p.write(e.proof.bytes,p256k1_base); *out=std::move(e); return true; }
inline bool BlindzapProve(const uint8_t* secret, size_t n, BlindzapStatementV1 statement, BlindzapEnvelopeV1* out) { if(!secret || n!=32 || !BlindzapStatementValid(statement))return false; std::array<uint8_t,32> key{}; std::memcpy(key.data(),secret,32); const bool result=BlindzapProveKeys<1>({key},std::move(statement),out); volatile uint8_t* wipe=key.data(); for(size_t i=0;i<key.size();++i)wipe[i]=0; return result; }
template <size_t Keys>
inline bool BlindzapVerifyKeys(const BlindzapEnvelopeV1& e) { std::vector<std::array<uint8_t,20>> programs; if(!BlindzapDistinctPrograms(e.statement,&programs) || programs.size()!=Keys)return false; QuadCircuit<BlindzapField> q(p256k1_base); auto c=BlindzapBuildCircuit<Keys>(&q); if(!BlindzapProofIdentityMatches(e.proof,BlindzapExpectedCircuitDigest<Keys>()))return false; const size_t block=BlindzapBlock(*c,q); using CF=CrtConvolutionFactory<CRT256<BlindzapField>,BlindzapField>; using RS=ReedSolomonFactory<BlindzapField,CF>; CF cf(p256k1_base); RS rs(cf,p256k1_base); ZkProof<BlindzapField> p(*c,4,128,block); ByteCursor rb(e.proof.bytes.data(),e.proof.bytes.size()); if(!p.read(rb,p256k1_base) || rb.remaining()!=0)return false; Dense<BlindzapField> pub(1,c->npub_in); { DenseFiller<BlindzapField> f(pub); f.push_back(p256k1_base.one()); BitPluckerEncoder<BlindzapField,8> enc(p256k1_base); for(const auto& program:programs)for(auto x:program)f.push_back(enc.encode(x)); } const auto seed=BlindzapTranscriptSeed(e.statement,e.proof); Transcript t(seed.data(),seed.size()); ZkVerifier<BlindzapField,RS> v(*c,rs,4,128,block,p256k1_base); v.recv_commitment(p,t); return v.verify(p,pub,t); }
inline bool BlindzapVerifyProof(const BlindzapEnvelopeV1& e) { std::vector<std::array<uint8_t,20>> p; if(!BlindzapDistinctPrograms(e.statement,&p))return false; switch(p.size()) { case 1:return BlindzapVerifyKeys<1>(e); case 2:return BlindzapVerifyKeys<2>(e); default:return false; } }
}
#endif
