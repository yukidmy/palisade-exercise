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
  uint64_t ptm = 15361;
  float securityLevel = 0.1;
  float dist = 1.006;

  // One of these value should be non-zero, and the others should be zero.
  int numAdds = 1, numMults = 0, numKeySwitches = 0;

  std::cerr << "Generating cc ..." << std::endl
            << "  plaintextModulus = " << ptm << "\n"
            << "  securityLevel = " << securityLevel << "\n"
            << "  dist = " << dist << "\n"
            << "  numAdds = " << numAdds << "\n"
            << "  numMults = " << numMults << "\n"
            << "  numKeySwitches = " << numKeySwitches << "\n";
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          ptm, securityLevel, dist, numAdds, numMults, numKeySwitches);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  std::cout << "STEP 2: Key-generation" << "\n";
  LPKeyPair<DCRTPoly> kp = cc->KeyGen();
  cc->EvalMultKeyGen(kp.secretKey);

  std::cout << "STEP 3: Encryption" << "\n";
  int num = 1;
  Ciphertext<DCRTPoly> ctxt = cc->Encrypt(kp.publicKey,
                                          cc->MakeIntegerPlaintext(num));

  std::cout << "STEP 4: Over calculation" << "\n";
  Ciphertext<DCRTPoly> validResult = ctxt + ctxt;
  Ciphertext<DCRTPoly> invalidResult = validResult;
  num += 1;
  for (int i = 0; i < 10000 - 2; i++) {
    invalidResult += ctxt;
    num += 1;
    // invalidResult *= invalidResult;
  }

  std::cout << "FINAL STEP: Decryption" << "\n";
  Plaintext result;
  cc->Decrypt(kp.secretKey, validResult, &result);
  std::cout << "   Valid Result\n"
            << "      expected: 2, obtained: " << result << "\n";
  cc->Decrypt(kp.secretKey, invalidResult, &result);
  std::cout << "   Invalid Result\n"
            << "      expected: " << num << ", obtained: " << result << "\n";
  std::cout << "===== DONE =====" << "\n";

  return 0;
}
