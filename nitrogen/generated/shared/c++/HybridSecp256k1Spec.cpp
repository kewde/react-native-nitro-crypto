///
/// HybridSecp256k1Spec.cpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2025 Marc Rousavy @ Margelo
///

#include "HybridSecp256k1Spec.hpp"

namespace margelo::nitro::nitrocrypto {

  void HybridSecp256k1Spec::loadHybridMethods() {
    // load base methods/properties
    HybridObject::loadHybridMethods();
    // load custom methods/properties
    registerHybrids(this, [](Prototype& prototype) {
      prototype.registerHybridMethod("privateKeyIsValid", &HybridSecp256k1Spec::privateKeyIsValid);
      prototype.registerHybridMethod("privateKeyToPublicKey", &HybridSecp256k1Spec::privateKeyToPublicKey);
      prototype.registerHybridMethod("publicKeyIsValid", &HybridSecp256k1Spec::publicKeyIsValid);
      prototype.registerHybridMethod("publicKeyConvert", &HybridSecp256k1Spec::publicKeyConvert);
      prototype.registerHybridMethod("xOnlyIsValid", &HybridSecp256k1Spec::xOnlyIsValid);
      prototype.registerHybridMethod("privateKeyTweakAdd", &HybridSecp256k1Spec::privateKeyTweakAdd);
      prototype.registerHybridMethod("privateKeyTweakSubtract", &HybridSecp256k1Spec::privateKeyTweakSubtract);
      prototype.registerHybridMethod("privateKeyTweakNegate", &HybridSecp256k1Spec::privateKeyTweakNegate);
      prototype.registerHybridMethod("publicKeyTweakAddPoint", &HybridSecp256k1Spec::publicKeyTweakAddPoint);
      prototype.registerHybridMethod("publicKeyTweakAddScalar", &HybridSecp256k1Spec::publicKeyTweakAddScalar);
      prototype.registerHybridMethod("publicKeyTweakMultiply", &HybridSecp256k1Spec::publicKeyTweakMultiply);
      prototype.registerHybridMethod("xOnlyTweakAdd", &HybridSecp256k1Spec::xOnlyTweakAdd);
      prototype.registerHybridMethod("ecdsaSignHash", &HybridSecp256k1Spec::ecdsaSignHash);
      prototype.registerHybridMethod("ecdsaVerifyHash", &HybridSecp256k1Spec::ecdsaVerifyHash);
      prototype.registerHybridMethod("schnorrSign", &HybridSecp256k1Spec::schnorrSign);
      prototype.registerHybridMethod("schnorrVerify", &HybridSecp256k1Spec::schnorrVerify);
    });
  }

} // namespace margelo::nitro::nitrocrypto
