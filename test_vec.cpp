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
  CryptoContext<Poly> cc = CryptoContextHelper::getNewContext("BFV1");
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(PRE);
  cc->Enable(MULTIPARTY);

  std::cout << "STEP 2: Key-generation" << "\n";
  std::string ccPath = "tmp/cc";
  LPKeyPair<Poly> kp = cc->KeyGen();

  std::cout << "STEP 3: Encryption" << "\n";
  std::vector<int> intvec = {0, 1, 2};
  std::cout << "   Init data: ";
  std::vector<CiphertextImpl<Poly>> ctxtvec;
  for (auto i = intvec.begin(); i < intvec.end(); i++) {
    std::cout << *i << " ";
    ctxtvec.push_back(*(cc->Encrypt(kp.publicKey,
                                    cc->MakeIntegerPlaintext(*i))));
  }
  std::cout << "\n";

  std::cout << "STEP 4: Serialization & Deserialization" << "\n";
  Serialized ser;
  SerializeVector<CiphertextImpl<Poly>>("ctxtvec", "CiphertextImpl",
                                        ctxtvec, &ser);
  SerialItem::ConstMemberIterator itr = ser.FindMember("ctxtvec");
  if (itr == ser.MemberEnd()) {
    std::cout << "   Can't find ctxtvec" << "\n";
    return 1;
  }
  ctxtvec.clear();
  // Does not work
  DeserializeVector("ctxtvec", "CiphertextImpl", itr, &ctxtvec);

  std::cout << "STEP 5: Calculation" << "\n";
  int num = 1;
  Plaintext ptxt = cc->MakeIntegerPlaintext(num);
  std::vector<Ciphertext<Poly>> results;
  for (auto i = ctxtvec.begin(); i < ctxtvec.end(); ++i) {
    Ciphertext<Poly> ctxt = cc->EvalAdd(Ciphertext<Poly>(&(*i)), ptxt);
    results.push_back(ctxt);
  }

  std::cout << "STEP 6: Decryption" << "\n";
  Plaintext result;
  std::cout << "   Init+" << num << " data: {";
  std::cout << results.size() << "\n";
  for (auto i = results.begin(); i < results.end(); ++i) {
    cc->Decrypt(kp.secretKey, (*i), &result);
    std::cout << result << " ";
  }
  std::cout << "\n";

  std::cout << "--- DONE ---" << "\n";

  return 0;
}
