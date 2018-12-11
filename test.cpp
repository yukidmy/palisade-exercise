// Copyright © 2018 yukiymd. All rights reserved.

#include <iostream>
#include <fstream>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/serializablehelper.h"

using namespace lbcrypto;


int main() {
  std::cout << "STEP 1: Contexts Creation" << "\n";
  CryptoContext<Poly> cc1 = CryptoContextHelper::getNewContext("BFV1");
  cc1->Enable(ENCRYPTION);
  cc1->Enable(SHE);
  cc1->Enable(PRE);
  cc1->Enable(MULTIPARTY);

  std::cout << "STEP 2: Key-generation" << "\n";
  std::string ccPath = "tmp/cc";
  LPKeyPair<Poly> kp1 = cc1->KeyGen();

  std::cout << "STEP 3: Context Duplication" << "\n";
  Serialized ser1;
  if (!cc1->Serialize(&ser1)) {
    std::cout << "   Serialization failed ..." << "\n";
    return 1;
  }
  if (!SerializableHelper::WriteSerializationToFile(ser1, ccPath)) {
    std::cout << "   Writing failed ..." << "\n";
    return 1;
  }
  Serialized ser2;
  if (!SerializableHelper::ReadSerializationFromFile(ccPath, &ser2)) {
    std::cout << "   Reading failed ..." << "\n";
    return 1;
  }
  CryptoContext<Poly> cc2 =
      CryptoContextFactory<Poly>::DeserializeAndCreateContext(ser2);

  std::cout << "STEP 4: Encryption" << "\n";
  int num1 = 1;
  Plaintext plaintext1 = cc1->MakeIntegerPlaintext(num1);
  Ciphertext<Poly> ciphertext1 = cc1->Encrypt(kp1.publicKey, plaintext1);

  std::cout << "STEP 5: Calculation" << "\n";
  int num2 = 2;
  Plaintext plaintext2 = cc2->MakeIntegerPlaintext(num2);
  Ciphertext<Poly> ciphertext3 = cc2->EvalAdd(ciphertext1, plaintext2);

  std::cout << "STEP 6: Decryption" << "\n";
  Plaintext plaintext3;
  cc1->Decrypt(kp1.secretKey, ciphertext3, &plaintext3);
  std::cout << "   " << num1 << " + "  << num2 << " = " << plaintext3 << "\n";


  std::cout << "STEP 7: Security Check" << "\n";
  LPKeyPair<Poly> kp2 = cc2->KeyGen();
  Plaintext plaintext4;
  std::cout << "   !!! Expected to fail !!!" << "\n";
  try {
    cc2->Decrypt(kp2.secretKey, ciphertext3, &plaintext4);
    std::cout << "   " << num1 << " + "  << num2 << " = " << plaintext4 << "\n";
    cc2->Decrypt(kp2.secretKey, ciphertext3, &plaintext4);
    std::cout << "   " << num1 << " + "  << num2 << " = " << plaintext4 << "\n";
  } catch (exception e) {
    std::cout << "   Decryption failed ..." << "\n";
  }

  std::cout << "--- DONE ---" << "\n";

  return 0;
}
