// Copyright © 2018 yukiymd. All rights reserved.

#include <iostream>
#include <fstream>
#include <vector>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/serializablehelper.h"

#define ERRLOG(msg) std::cerr << "!!!!! "               \
                              << __FILE__ << ", "       \
                              << __LINE__ << ", "       \
                              << __FUNCTION__ << ": "   \
                              << msg << "\n";

using namespace lbcrypto;


int main() {
  std::cout << "STEP 1: Contexts Creation" << "\n";
  uint64_t p = 65537;
  double sigma = 3.2;
  double rootHermiteFactor = 1.006;
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          p, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED, 3);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(PRE);
  cc->Enable(MULTIPARTY);

  std::cout << "STEP 2: Key-generation" << "\n";
  LPKeyPair<DCRTPoly> kp = cc->KeyGen();
  cc->EvalMultKeyGen(kp.secretKey);
  const std::vector<int> index1 = {0, 1, 2, 3, 4, -4, -3, -2, -1};
  cc->EvalAtIndexKeyGen(kp.secretKey, index1);

  std::cout << "STEP 3: Encryption" << "\n";
  // int32_t n =
  //     cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2;
  std::vector<uint64_t> intvec = {1, 2, 4, 8, 16};
  // std::cout << "   Init data: ";
  // for (auto i = intvec.begin(); i < intvec.end(); i++)
  //   std::cout << *i << " ";
  // std::cout << "\n";
  Ciphertext<DCRTPoly> cintvec = cc->Encrypt(kp.publicKey,
                                             cc->MakePackedPlaintext(intvec));


  std::cout << "STEP 4: Copy CC" << "\n";
  Serialized ser;
  if (!cc->Serialize(&ser)) {
    ERRLOG("Failed to serialize cc");
    exit(1);
  }
  CryptoContext<DCRTPoly> cc_copy =
      CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ser);

  std::cout << "STEP 5: EvalAtIndex" << "\n";
  Ciphertext<DCRTPoly> mult = cc_copy->EvalMult(cintvec, cintvec);
  Ciphertext<DCRTPoly> sum = cc_copy->EvalAtIndex(cintvec, index1[0]);
  for (int i = 1; i < index1.size(); i++)
    sum = cc_copy->EvalAdd(sum, cc_copy->EvalAtIndex(cintvec, index1[i]));

  std::cerr << "STEP 6: Undefined operation" << "\n";
  auto cintvec1 = cc_copy->EvalAtIndex(cintvec, 2);
  auto cintvec2 = cc_copy->EvalAtIndex(cintvec1, -4);
  auto cintvec3 = cc_copy->EvalAdd(cintvec1, cintvec2);

  std::cout << "FINAL STEP: Decryption" << "\n";
  Plaintext result;
  cc->Decrypt(kp.secretKey, mult, &result);
  result->SetLength(5);
  std::cout << "   Multiplicated vec : " << result << "\n";
  cc->Decrypt(kp.secretKey, sum, &result);
  result->SetLength(5);
  std::cout << "   Sum vec           : " << result << "\n";
  std::cout << "   Sum               : "
            << result->GetPackedValue()[0] << "\n";
  cc->Decrypt(kp.secretKey, cintvec1, &result);
  result->SetLength(5);
  std::cout << "   cintvec1          : " << result << "\n";
  cc->Decrypt(kp.secretKey, cintvec2, &result);
  result->SetLength(5);
  std::cout << "   cintvec2          : " << result << "\n";
  cc->Decrypt(kp.secretKey, cintvec3, &result);
  result->SetLength(5);
  std::cout << "   cintvec3          : " << result << "\n";
  std::cout << "===== DONE =====" << "\n";

  return 0;
}
