#pragma once

#include "HybridSecp256k1Spec.hpp"
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include <jsi/jsi.h>

namespace margelo::nitro::nitrocrypto {

const std::string ERR_INVALID_PRIVATE_KEY_LENGTH = "invalid private key length";
const std::string ERR_INVALID_PRIVATE_KEY = "invalid private key";
const std::string ERR_INVALID_PUBLIC_KEY_LENGTH = "invalid public key length";
const std::string ERR_INVALID_PUBLIC_KEY = "invalid public key";
const std::string ERR_FAILED_CREATE_PUBLIC_KEY = "failed to create public key";
const std::string ERR_FAILED_SERIALIZE_PUBLIC_KEY =
    "failed to serialize public key";
const std::string ERR_INVALID_TWEAK_LENGTH = "invalid tweak length";
const std::string ERR_INVALID_TWEAK = "invalid tweak";
const std::string ERR_FAILED_TWEAKING_PRIVATE_KEY =
    "failed to tweak private key";
const std::string ERR_FAILED_NEGATING_TWEAK = "failed to negate tweak";
const std::string ERR_FAILED_NEGATING_PRIVATE_KEY =
    "failed to negate private key";
const std::string ERR_INVALID_TWEAK_PUBLIC_KEY_LENGTH =
    "invalid tweak public key length";
const std::string ERR_INVALID_TWEAK_PUBLIC_KEY = "invalid tweak public key";
const std::string ERR_FAILED_ADD_TWEAK_PUBLIC_KEY_TO_PUBLIC_KEY =
    "failed to add tweak point to public key";
const std::string ERR_FAILED_ADD_TWEAK_TO_PUBLIC_KEY =
    "failed to add tweak to public key";
const std::string ERR_INVALID_HASH_LENGTH = "invalid hash length";
const std::string ERR_INVALID_EXTRA_ENTROPY_LENGTH =
    "invalid extraEntropy length";
const std::string ERR_FAILED_SIGNING_HASH = "failed to sign hash";
const std::string ERR_FAILED_SERIALIZE_SIGNATURE =
    "failed to serialize signature";
const std::string ERR_FAILED_DESERIALIZE_SIGNATURE =
    "failed to deserialize signature";
const std::string ERR_INVALID_SIGNATURE_LENGTH = "invalid signature length";

class HybridSecp256k1 : public HybridSecp256k1Spec {
public:
  HybridSecp256k1();
  virtual ~HybridSecp256k1();

private:
  secp256k1_context *ctx;

public:
  bool
  privateKeyIsValid(const std::shared_ptr<ArrayBuffer> &privateKey) override;
  std::shared_ptr<ArrayBuffer>
  privateKeyToPublicKey(const std::shared_ptr<ArrayBuffer> &privateKey,
                        bool compressed) override;
  bool publicKeyIsValid(const std::shared_ptr<ArrayBuffer> &publicKey,
                        bool compressed) override;
  std::shared_ptr<ArrayBuffer>
  publicKeyConvert(const std::shared_ptr<ArrayBuffer> &publicKey,
                   bool compressed) override;
  bool xOnlyIsValid(const std::shared_ptr<ArrayBuffer> &xOnly) override;
  std::shared_ptr<ArrayBuffer>
  privateKeyTweakAdd(const std::shared_ptr<ArrayBuffer> &privateKey,
                     const std::shared_ptr<ArrayBuffer> &tweak) override;
  std::shared_ptr<ArrayBuffer>
  privateKeyTweakSubtract(const std::shared_ptr<ArrayBuffer> &privateKey,
                          const std::shared_ptr<ArrayBuffer> &tweak) override;
  std::shared_ptr<ArrayBuffer> privateKeyTweakNegate(
      const std::shared_ptr<ArrayBuffer> &privateKey) override;
  std::shared_ptr<ArrayBuffer>
  publicKeyTweakAddPoint(const std::shared_ptr<ArrayBuffer> &publicKey,
                         const std::shared_ptr<ArrayBuffer> &tweakPoint,
                         bool compressed) override;
  std::shared_ptr<ArrayBuffer>
  publicKeyTweakAddScalar(const std::shared_ptr<ArrayBuffer> &publicKey,
                          const std::shared_ptr<ArrayBuffer> &tweak,
                          bool compressed) override;
  std::shared_ptr<ArrayBuffer>
  publicKeyTweakMultiply(const std::shared_ptr<ArrayBuffer> &publicKey,
                         const std::shared_ptr<ArrayBuffer> &tweak,
                         bool compressed) override;
  std::shared_ptr<ArrayBuffer>
  xOnlyTweakAdd(const std::shared_ptr<ArrayBuffer> &xOnly,
                const std::shared_ptr<ArrayBuffer> &tweak,
                bool compressed) override;
  std::shared_ptr<ArrayBuffer> ecdsaSignHash(
      const std::shared_ptr<ArrayBuffer> &hash,
      const std::shared_ptr<ArrayBuffer> &privateKey, bool der, bool recovery,
      const std::optional<std::shared_ptr<ArrayBuffer>> &extraEntropy) override;
  bool ecdsaVerifyHash(const std::shared_ptr<ArrayBuffer> &signature,
                       const std::shared_ptr<ArrayBuffer> &hash,
                       const std::shared_ptr<ArrayBuffer> &publicKey) override;
  std::shared_ptr<ArrayBuffer> schnorrSign(
      const std::shared_ptr<ArrayBuffer> &message,
      const std::shared_ptr<ArrayBuffer> &privateKey,
      const std::optional<std::shared_ptr<ArrayBuffer>> &extraEntropy) override;
  bool schnorrVerify(const std::shared_ptr<ArrayBuffer> &signature,
                     const std::shared_ptr<ArrayBuffer> &message,
                     const std::shared_ptr<ArrayBuffer> &xOnly) override;
};

} // namespace margelo::nitro::nitrocrypto
