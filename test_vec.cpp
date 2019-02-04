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

  std::cout << "STEP 3: Encryption" << "\n";
  int32_t n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2;
  std::vector<int32_t> index = {0, 1, 2, 3, 4};
  cc->EvalAtIndexKeyGen(kp.secretKey, index);
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

  std::cout << "STEP 4: Calculation" << "\n";
  Ciphertext<DCRTPoly> sum = cc->EvalAtIndex(cintvec, index[0]);
  for (int i = 1; i < index.size(); i++)
    sum = cc->EvalAdd(sum, cc->EvalAtIndex(cintvec, index[i]));

  std::cout << "STEP 5: Decryption" << "\n";
  Plaintext result;
  cc->Decrypt(kp.secretKey, cintvec, &result);
  // result->SetLength(5);
  std::cout << "   Decrypted data: " << result << "\n";
  cc->Decrypt(kp.secretKey, sum, &result);
  std::cout << "   Sum: " << result << "\n";

  std::cout << "--- DONE ---" << "\n";

  return 0;
}
