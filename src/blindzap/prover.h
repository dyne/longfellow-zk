// Copyright 2026 Google LLC.
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
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
namespace proofs {
using BlindzapField = Fp256k1Base; using BlindzapEC = P256k1; using BlindzapBackend = CompilerBackend<BlindzapField>; using BlindzapLogic = Logic<BlindzapField, BlindzapBackend>; using BlindzapRelation = BlindzapCircuitV1<BlindzapLogic, BlindzapField, BlindzapEC>;
inline std::unique_ptr<Circuit<BlindzapField>> BlindzapBuildCircuit(QuadCircuit<BlindzapField>* q) { BlindzapBackend b(q); BlindzapLogic l(&b,p256k1_base); BlindzapRelation r(l,p256k1); std::array<BlindzapLogic::EltW,20> p; for(auto& x:p)x=l.eltw_input(); q->private_input(); BlindzapRelation::Witness w; w.input(l); r.assert_program(p,w); return q->mkcircuit(1); }
inline size_t BlindzapBlock(const Circuit<BlindzapField>& c, const QuadCircuit<BlindzapField>& q) { return c.ninputs-c.npub_in+q.nquad_terms_+1; }
inline bool BlindzapProve(const uint8_t* secret, size_t n, BlindzapStatementV1 statement, BlindzapEnvelopeV1* out) { BlindzapWitnessV1<BlindzapField,BlindzapEC> w; if(!out||!w.compute(p256k1,secret,n))return false; statement.claims.resize(1); statement.claims[0].program=w.program(); QuadCircuit<BlindzapField> q(p256k1_base); auto c=BlindzapBuildCircuit(&q); const size_t block=BlindzapBlock(*c,q); if(!check_crt_block_enc<CRT256<BlindzapField>>(block).empty())return false; auto in=std::make_unique<Dense<BlindzapField>>(1,c->ninputs); { DenseFiller<BlindzapField> f(*in); f.push_back(p256k1_base.one()); BitPluckerEncoder<BlindzapField,8> e(p256k1_base); for(auto x:w.program())f.push_back(e.encode(x)); w.fill_witness(f); } using CF=CrtConvolutionFactory<CRT256<BlindzapField>,BlindzapField>; using RS=ReedSolomonFactory<BlindzapField,CF>; CF cf(p256k1_base); RS rs(cf,p256k1_base); ZkProof<BlindzapField> p(*c,4,128,block); ZkProver<BlindzapField,RS> prover(*c,p256k1_base,rs); SecureRandomEngine rng; BlindzapEnvelopeV1 e; e.statement=std::move(statement); e.proof.circuit_digest=BlindzapCircuitDigest(*c,p256k1_base,SECP_ID); const auto seed=BlindzapTranscriptSeed(e.statement,e.proof); Transcript t(seed.data(),seed.size()); prover.commit(p,*in,t,rng); if(!prover.prove(p,*in,t))return false; p.write(e.proof.bytes,p256k1_base); *out=std::move(e); return true; }
inline bool BlindzapVerifyProof(const BlindzapEnvelopeV1& e) { if(e.statement.claims.size()!=1)return false; QuadCircuit<BlindzapField> q(p256k1_base); auto c=BlindzapBuildCircuit(&q); if(!BlindzapProofIdentityMatches(e.proof,BlindzapCircuitDigest(*c,p256k1_base,SECP_ID)))return false; const size_t block=BlindzapBlock(*c,q); using CF=CrtConvolutionFactory<CRT256<BlindzapField>,BlindzapField>; using RS=ReedSolomonFactory<BlindzapField,CF>; CF cf(p256k1_base); RS rs(cf,p256k1_base); ReadBuffer rb(e.proof.bytes.data(),e.proof.bytes.size()); ZkProof<BlindzapField> p(*c,4,128,block); if(!p.read(rb,p256k1_base))return false; Dense<BlindzapField> pub(1,c->npub_in); { DenseFiller<BlindzapField> f(pub); f.push_back(p256k1_base.one()); BitPluckerEncoder<BlindzapField,8> enc(p256k1_base); for(auto x:e.statement.claims[0].program)f.push_back(enc.encode(x)); } const auto seed=BlindzapTranscriptSeed(e.statement,e.proof); Transcript t(seed.data(),seed.size()); ZkVerifier<BlindzapField,RS> v(*c,rs,4,128,block,p256k1_base); v.recv_commitment(p,t); return v.verify(p,pub,t); }
}
#endif
