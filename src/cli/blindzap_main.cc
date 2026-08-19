#include <array>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <chrono>
#include <string>
#include <vector>
#include "blindzap/envelope.h"
#include "blindzap/prover.h"
#include "blindzap/verifier.h"
#include "blindzap/bitcoin_core.h"

namespace {
constexpr int kUsage = 64, kData = 65;
int Usage() { std::cerr << "usage: blindzap challenge create --network N --purpose P | blindzap prove --network N --purpose P --snapshot HASH --output FILE | blindzap verify FILE --bitcoin-cli PATH | blindzap inspect FILE\n"; return kUsage; }
bool Read(const std::string& path, std::vector<uint8_t>* out) { std::ifstream in(path, std::ios::binary); if (!in) return false; out->assign(std::istreambuf_iterator<char>(in), {}); return in.good() || in.eof(); }
bool WriteAtomic(const std::string& path, const std::vector<uint8_t>& bytes) { const std::string tmp=path+".tmp"; { std::ofstream out(tmp, std::ios::binary|std::ios::trunc); if(!out) return false; out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); if(!out) return false; } return std::rename(tmp.c_str(),path.c_str())==0; }
bool SecretFromStdin(std::array<uint8_t,32>* secret) { std::string hex; if(!std::getline(std::cin,hex) || hex.size()!=64) return false; auto nibble=[](char c)->int { return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1; }; for(size_t i=0;i<32;++i) { int a=nibble(hex[2*i]),b=nibble(hex[2*i+1]); if(a<0||b<0) return false; (*secret)[i]=static_cast<uint8_t>((a<<4)|b); } return true; }
bool Network(const std::string& s, proofs::BlindzapNetwork* n) { if(s=="mainnet") *n=proofs::BlindzapNetwork::kMainnet; else if(s=="testnet") *n=proofs::BlindzapNetwork::kTestnet; else if(s=="regtest") *n=proofs::BlindzapNetwork::kRegtest; else return false; return true; }
bool Hex32(const std::string& hex, std::array<uint8_t,32>* out) { if(hex.size()!=64) return false; auto n=[](char c)->int{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;}; for(size_t i=0;i<32;++i){int a=n(hex[2*i]),b=n(hex[2*i+1]);if(a<0||b<0)return false;(*out)[i]=uint8_t((a<<4)|b);}return true; }
int PrintResult(proofs::BlindzapVerifyResult result) { std::cout << "{\"result\":\"" << proofs::BlindzapVerifyResultName(result) << "\",\"exit_code\":" << proofs::BlindzapVerifyExitCode(result) << "}\n"; return proofs::BlindzapVerifyExitCode(result); }
}
int main(int argc, char** argv) {
  if(argc>1 && std::string(argv[1])=="--help") { std::cout<<"BlindZap proof-of-control CLI\n"; return 0; }
  for(int i=1;i<argc;++i) if(std::string(argv[i])=="--secret" || std::string(argv[i]).rfind("--secret=",0)==0) { std::cerr<<"secret material is accepted only from stdin\n"; return kUsage; }
  if(argc==3 && std::string(argv[1])=="inspect") { std::vector<uint8_t> wire; proofs::BlindzapEnvelopeV1 e; if(!Read(argv[2],&wire)||!proofs::DecodeBlindzapEnvelope(wire,&e)) { std::cerr<<"invalid BlindZap envelope\n"; return kData; } std::cout<<proofs::BlindzapInspectJson(e)<<'\n'; return 0; }
  if(argc==7 && std::string(argv[1])=="challenge" && std::string(argv[2])=="create" && std::string(argv[3])=="--network" && std::string(argv[5])=="--purpose") { proofs::BlindzapNetwork n; if(!Network(argv[4],&n)||std::string(argv[6]).empty()) return Usage(); std::cout<<"{\"network\":\""<<argv[4]<<"\",\"purpose\":\""<<argv[6]<<"\"}\n"; return 0; }
  if(argc==5 && std::string(argv[1])=="verify" && std::string(argv[3])=="--bitcoin-cli") { std::vector<uint8_t> wire; proofs::BlindzapEnvelopeV1 e; if(!Read(argv[2],&wire)||!proofs::DecodeBlindzapEnvelope(wire,&e)) return PrintResult(proofs::BlindzapVerifyResult::kMalformedStatement); const std::string executable=argv[4]; if(executable.empty() || executable.find('\0') != std::string::npos) return Usage(); proofs::BitcoinCoreCurrentTipProvider provider(executable,e.statement.network); proofs::BlindzapVerifierConfig c; c.provider=&provider; c.verify_proof=[](const proofs::BlindzapEnvelopeV1& x){return proofs::BlindzapVerifyProof(x);}; c.policy.now=static_cast<uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())); c.policy.verifier="blindzap-cli"; c.policy.purpose=e.statement.purpose; c.policy.consume_nonce=[](const std::array<uint8_t,32>&){return true;}; return PrintResult(proofs::VerifyBlindzap(wire,c).result); }
  if(argc==10 && std::string(argv[1])=="prove" && std::string(argv[2])=="--network" && std::string(argv[4])=="--purpose" && std::string(argv[6])=="--snapshot" && std::string(argv[8])=="--output") { proofs::BlindzapNetwork n; std::array<uint8_t,32> secret{}, snapshot{}; if(!Network(argv[3],&n)||std::string(argv[5]).empty()||!Hex32(argv[7],&snapshot)||!SecretFromStdin(&secret)) { std::cerr<<"expected explicit 32-byte snapshot and one 32-byte hexadecimal secret on stdin\n"; return kUsage; } proofs::BlindzapStatementV1 s; s.network=n; s.verifier="blindzap-cli"; s.purpose=argv[5]; s.has_snapshot=true; s.snapshot=snapshot; s.expires_at=UINT64_MAX; proofs::BlindzapEnvelopeV1 e; const bool ok=proofs::BlindzapProve(secret.data(),secret.size(),s,&e); std::fill(secret.begin(),secret.end(),0); std::vector<uint8_t> wire; if(!ok||!proofs::EncodeBlindzapEnvelope(e,&wire)||!WriteAtomic(argv[9],wire)) { std::cerr<<"proof generation failed\n"; return 2; } std::cout<<"{\"result\":\"proof_created\"}\n"; return 0; }
  return Usage();
}
