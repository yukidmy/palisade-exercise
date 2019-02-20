// Copyright © 2018 yukiymd. All rights reserved.

#include <iostream>
#include <fstream>
#include <vector>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/serializablehelper.h"

using namespace lbcrypto;


int main() {
  std::cout << "STEP 1: Contexts Creation" << "\n";
  uint64_t p = 65537;
  double sigma = 3.2;
  double rootHermiteFactor = 1.006;
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          p, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED,3);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(PRE);
  cc->Enable(MULTIPARTY);

  std::cout << "STEP 2: Key-generation" << "\n";
  std::string ccPath = "tmp/cc";
  LPKeyPair<DCRTPoly> kp = cc->KeyGen();
  cc->EvalMultKeyGen(kp.secretKey);

  std::cout << "STEP 3: Encryption" << "\n";
  int32_t n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2;
  std::vector<uint64_t> intvec = {1, 2, 4, 8, 16};
  std::cout << "   Init data: ";
  for (auto i = intvec.begin(); i < intvec.end(); i++)
    std::cout << *i << " ";
  std::cout << "\n";
  // intvec.resize(n);
  // intvec[n-1] = n-1;
  // intvec[n-2] = n-2;
  // intvec[n-3] = n-3;
  Ciphertext<DCRTPoly> cintvec = cc->Encrypt(kp.publicKey,
                                             cc->MakePackedPlaintext(intvec));

  std::cout << "STEP 4: EvalAtIndex" << "\n";
  Ciphertext<DCRTPoly> mult = cc->EvalMult(cintvec, cintvec);
  const std::vector<int> index1 = {0, 1, 2, 3, 4};
  cc->EvalAtIndexKeyGen(kp.secretKey, index1);
  Ciphertext<DCRTPoly> sum = cc->EvalAtIndex(cintvec, index1[0]);
  for (int i = 1; i < index1.size(); i++)
    sum = cc->EvalAdd(sum, cc->EvalAtIndex(cintvec, index1[i]));

  // std::cout << "STEP 5: EvalAutomorphism" << "\n";
  // const std::vector<usint> index2 = {1, 3, 5, 7, 9};
  // auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, index2);
  // auto permuted1 = cc->EvalAutomorphism(cintvec, 1, *evalKeys);
  // auto permuted3 = cc->EvalAutomorphism(cintvec, 3, *evalKeys);
  // auto permuted5 = cc->EvalAutomorphism(cintvec, 5, *evalKeys);
  // auto permuted7 = cc->EvalAutomorphism(cintvec, 7, *evalKeys);
  // auto permuted9 = cc->EvalAutomorphism(cintvec, 9, *evalKeys);

  std::cout << "FINAL STEP: Decryption" << "\n";
  Plaintext result;
  cc->Decrypt(kp.secretKey, mult, &result);
  result->SetLength(5);
  std::cout << "   Multiplicated data : " << result << "\n";
  cc->Decrypt(kp.secretKey, sum, &result);
  result->SetLength(5);
  std::cout << "   Decrypted data     : " << result << "\n";
  std::cout << "   Sum                : "
            << result->GetPackedValue()[0] << "\n";
  // cc->Decrypt(kp.secretKey, permuted1, &result);
  // std::cout << "   Permuted data 1:  " << result << "\n";
  // cc->Decrypt(kp.secretKey, permuted3, &result);
  // std::cout << "   Permuted data 3:  " << result << "\n";
  // cc->Decrypt(kp.secretKey, permuted5, &result);
  // std::cout << "   Permuted data 5:  " << result << "\n";
  // cc->Decrypt(kp.secretKey, permuted7, &result);
  // std::cout << "   Permuted data 7:  " << result << "\n";
  // cc->Decrypt(kp.secretKey, permuted9, &result);
  // std::cout << "   Permuted data 9:  " << result << "\n";
  std::cout << "===== DONE =====" << "\n";

  return 0;
}
