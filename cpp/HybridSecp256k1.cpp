#include "HybridSecp256k1.hpp"
#include <memory> // Needed for std::shared_ptr

namespace margelo::nitro::nitrocrypto {

HybridSecp256k1::HybridSecp256k1() : HybridObject(TAG) {
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  // TODO: allow randomizing context using secp256k1_context_randomize()
}

HybridSecp256k1::~HybridSecp256k1() { secp256k1_context_destroy(this->ctx); }

bool HybridSecp256k1::privateKeyIsValid(
    const std::shared_ptr<ArrayBuffer> &privateKey) {
  if (privateKey->size() != 32) {
    return 0;
  }

  return 1 == secp256k1_ec_seckey_verify(this->ctx, privateKey->data());
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::privateKeyToPublicKey(
    const std::shared_ptr<ArrayBuffer> &privateKey, bool compressed) {
  if (privateKey->size() != 32) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY_LENGTH);
  }

  if (!secp256k1_ec_seckey_verify(this->ctx, privateKey->data())) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY);
  }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_create(this->ctx, &pubkey, privateKey->data())) {
    throw std::runtime_error(ERR_FAILED_CREATE_PUBLIC_KEY);
  }

  size_t len = compressed ? 33 : 65;
  unsigned char serialized_pubkey[len];
  if (!secp256k1_ec_pubkey_serialize(
          this->ctx, serialized_pubkey, &len, &pubkey,
          compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
    throw std::runtime_error(ERR_FAILED_SERIALIZE_PUBLIC_KEY);
  }

  return ArrayBuffer::copy(serialized_pubkey, len);
}

bool HybridSecp256k1::publicKeyIsValid(
    const std::shared_ptr<ArrayBuffer> &publicKey, bool compressed) {
  if (publicKey->size() != 33 && publicKey->size() != 65) {
    return false;
  }

  secp256k1_pubkey pubkey;
  return 1 == secp256k1_ec_pubkey_parse(this->ctx, &pubkey, publicKey->data(),
                                        publicKey->size());
}

std::shared_ptr<ArrayBuffer>
HybridSecp256k1::publicKeyConvert(const std::shared_ptr<ArrayBuffer> &publicKey,
                                  bool compressed) {
  if (publicKey->size() != 33 && publicKey->size() != 65) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY_LENGTH);
  }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(this->ctx, &pubkey, publicKey->data(),
                                 publicKey->size())) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY);
  }

  size_t len = compressed ? 33 : 65;
  unsigned char serialized_pubkey[len];
  if (!secp256k1_ec_pubkey_serialize(
          this->ctx, serialized_pubkey, &len, &pubkey,
          compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
    throw std::runtime_error(ERR_FAILED_SERIALIZE_PUBLIC_KEY);
  }

  return ArrayBuffer::copy(serialized_pubkey, len);
}

bool HybridSecp256k1::xOnlyIsValid(const std::shared_ptr<ArrayBuffer> &xOnly) {
  if (xOnly->size() != 32) {
    return false;
  }

  secp256k1_xonly_pubkey pubkey;
  return 1 == secp256k1_xonly_pubkey_parse(this->ctx, &pubkey, xOnly->data());
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::privateKeyTweakAdd(
    const std::shared_ptr<ArrayBuffer> &privateKey,
    const std::shared_ptr<ArrayBuffer> &tweak) {
  if (privateKey->size() != 32) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY_LENGTH);
  }

  if (tweak->size() != 32) {
    throw std::runtime_error(ERR_INVALID_TWEAK_LENGTH);
  }

  // Validates the tweak
  if (!secp256k1_ec_seckey_verify(this->ctx, tweak->data())) {
    throw std::runtime_error(ERR_INVALID_TWEAK);
  }

  // We need to copy the private key and tweak into a new buffer because
  // secp256k1_ec_seckey_tweak_add modifies the input buffer in place.
  auto private_key_result = ArrayBuffer::copy(privateKey->data(), 32);
  // TODO: overwrite ^this data on delete to prevent it from lingering in memory

  // Validates both the input private key is valid & the resulting private key
  // after tweaking.
  if (!secp256k1_ec_seckey_tweak_add(this->ctx, private_key_result->data(),
                                     tweak->data())) {
    throw std::runtime_error(ERR_FAILED_TWEAKING_PRIVATE_KEY);
  }

  return private_key_result;
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::privateKeyTweakSubtract(
    const std::shared_ptr<ArrayBuffer> &privateKey,
    const std::shared_ptr<ArrayBuffer> &tweak) {

  if (privateKey->size() != 32) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY_LENGTH);
  }

  if (tweak->size() != 32) {
    throw std::runtime_error(ERR_INVALID_TWEAK_LENGTH);
  }

  unsigned char bytes_tweak[32];
  memcpy(bytes_tweak, tweak->data(), 32);
  // TODO: overwrite ^this data on delete to prevent it from lingering in memory

  // Validates the tweak (no overflow & not zero) & negates it in place
  if (!secp256k1_ec_seckey_negate(this->ctx, bytes_tweak)) {
    throw std::runtime_error(ERR_FAILED_NEGATING_TWEAK);
  }

  // Validate the negated tweak , this should technically be redunant but just
  // in case. secp256k1_ec_seckey_negate validates no overflow & not zero before
  // negating
  if (!secp256k1_ec_seckey_verify(this->ctx, bytes_tweak)) {
    throw std::runtime_error(ERR_INVALID_TWEAK);
  }

  // We need to copy the private key and tweak into a new buffer because
  // secp256k1_ec_seckey_tweak_add modifies the input buffer in place.
  auto private_key_result = ArrayBuffer::copy(privateKey->data(), 32);
  // TODO: overwrite ^this data on delete to prevent it from lingering in memory

  // Validates both the input private key is valid & the resulting private key
  // after tweaking.
  if (!secp256k1_ec_seckey_tweak_add(this->ctx, private_key_result->data(),
                                     bytes_tweak)) {
    throw std::runtime_error(ERR_FAILED_TWEAKING_PRIVATE_KEY);
  }

  return private_key_result;
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::privateKeyTweakNegate(
    const std::shared_ptr<ArrayBuffer> &privateKey) {
  if (privateKey->size() != 32) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY_LENGTH);
  }

  // We need to copy the private key into a new buffer because
  // secp256k1_ec_seckey_negate modifies the input buffer in place.
  auto private_key_result = ArrayBuffer::copy(privateKey->data(), 32);
  // TODO: overwrite ^this data on delete to prevent it from lingering in memory

  // Validates the private key (no overflow & not zero) & negates it in place
  if (!secp256k1_ec_seckey_negate(this->ctx, private_key_result->data())) {
    throw std::runtime_error(ERR_FAILED_NEGATING_PRIVATE_KEY);
  }

  // Validate the negated private key, this should technically be redunant but
  // just in case. secp256k1_ec_seckey_negate validates no overflow & not zero
  // before negating
  if (!secp256k1_ec_seckey_verify(this->ctx, private_key_result->data())) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY);
  }

  return private_key_result;
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::publicKeyTweakAddPoint(
    const std::shared_ptr<ArrayBuffer> &publicKey,
    const std::shared_ptr<ArrayBuffer> &tweakPoint, bool compressed) {
  if (publicKey->size() != 33 && publicKey->size() != 65) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY_LENGTH);
  }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(this->ctx, &pubkey, publicKey->data(),
                                 publicKey->size())) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY);
  }

  if (tweakPoint->size() != 33 && tweakPoint->size() != 65) {
    throw std::runtime_error(ERR_INVALID_TWEAK_PUBLIC_KEY_LENGTH);
  }

  secp256k1_pubkey tweakkey;
  if (!secp256k1_ec_pubkey_parse(this->ctx, &tweakkey, tweakPoint->data(),
                                 tweakPoint->size())) {
    throw std::runtime_error(ERR_INVALID_TWEAK_PUBLIC_KEY);
  }

  // Combine the public key and the tweak point into a new public key.
  // Also validates the tweak isn't the negated value of the public key
  secp256k1_pubkey pubkey_combined;
  const secp256k1_pubkey *pubkeys[2] = {&pubkey, &tweakkey};
  if (!secp256k1_ec_pubkey_combine(this->ctx, &pubkey_combined, pubkeys, 2)) {
    throw std::runtime_error(ERR_FAILED_ADD_TWEAK_PUBLIC_KEY_TO_PUBLIC_KEY);
  }

  size_t len = compressed ? 33 : 65;
  unsigned char serialized_pubkey[len];
  if (!secp256k1_ec_pubkey_serialize(
          this->ctx, serialized_pubkey, &len, &pubkey_combined,
          compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
    throw std::runtime_error(ERR_FAILED_SERIALIZE_PUBLIC_KEY);
  }

  return ArrayBuffer::copy(serialized_pubkey, len);
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::publicKeyTweakAddScalar(
    const std::shared_ptr<ArrayBuffer> &publicKey,
    const std::shared_ptr<ArrayBuffer> &tweak, bool compressed) {
  if (publicKey->size() != 33 && publicKey->size() != 65) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY_LENGTH);
  }

  if (tweak->size() != 32) {
    throw std::runtime_error(ERR_INVALID_TWEAK_LENGTH);
  }

  // Validates the tweak
  if (!secp256k1_ec_seckey_verify(this->ctx, tweak->data())) {
    throw std::runtime_error(ERR_INVALID_TWEAK);
  }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(this->ctx, &pubkey, publicKey->data(),
                                 publicKey->size())) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY);
  }

  // Adds the tweak to the public key in place
  if (!secp256k1_ec_pubkey_tweak_add(this->ctx, &pubkey, tweak->data())) {
    throw std::runtime_error(ERR_FAILED_ADD_TWEAK_TO_PUBLIC_KEY);
  }

  size_t len = compressed ? 33 : 65;
  unsigned char serialized_pubkey[len];
  if (!secp256k1_ec_pubkey_serialize(
          this->ctx, serialized_pubkey, &len, &pubkey,
          compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
    throw std::runtime_error(ERR_FAILED_SERIALIZE_PUBLIC_KEY);
  }

  return ArrayBuffer::copy(serialized_pubkey, len);
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::publicKeyTweakMultiply(
    const std::shared_ptr<ArrayBuffer> &publicKey,
    const std::shared_ptr<ArrayBuffer> &tweak, bool compressed) {
  if (publicKey->size() != 33 && publicKey->size() != 65) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY_LENGTH);
  }

  if (tweak->size() != 32) {
    throw std::runtime_error(ERR_INVALID_TWEAK_LENGTH);
  }

  // Validates the tweak
  if (!secp256k1_ec_seckey_verify(this->ctx, tweak->data())) {
    throw std::runtime_error(ERR_INVALID_TWEAK);
  }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(this->ctx, &pubkey, publicKey->data(),
                                 publicKey->size())) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY);
  }

  // Multiplies the tweak to the public key in place
  if (!secp256k1_ec_pubkey_tweak_mul(this->ctx, &pubkey, tweak->data())) {
    throw std::runtime_error(ERR_FAILED_ADD_TWEAK_TO_PUBLIC_KEY);
  }

  size_t len = compressed ? 33 : 65;
  unsigned char serialized_pubkey[len];
  if (!secp256k1_ec_pubkey_serialize(
          this->ctx, serialized_pubkey, &len, &pubkey,
          compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
    throw std::runtime_error(ERR_FAILED_SERIALIZE_PUBLIC_KEY);
  }

  return ArrayBuffer::copy(serialized_pubkey, len);
}

std::shared_ptr<ArrayBuffer>
HybridSecp256k1::xOnlyTweakAdd(const std::shared_ptr<ArrayBuffer> &xOnly,
                               const std::shared_ptr<ArrayBuffer> &tweak,
                               bool compressed) {
  if (xOnly->size() != 32) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY_LENGTH);
  }

  if (tweak->size() != 32) {
    throw std::runtime_error(ERR_INVALID_TWEAK_LENGTH);
  }

  // Validates the tweak
  if (!secp256k1_ec_seckey_verify(this->ctx, tweak->data())) {
    throw std::runtime_error(ERR_INVALID_TWEAK);
  }

  secp256k1_xonly_pubkey xonly_pubkey;
  if (!secp256k1_xonly_pubkey_parse(this->ctx, &xonly_pubkey, xOnly->data())) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY);
  }

  // Adds the tweak to the public key in place
  secp256k1_pubkey pubkey;
  if (!secp256k1_xonly_pubkey_tweak_add(this->ctx, &pubkey, &xonly_pubkey,
                                        tweak->data())) {
    throw std::runtime_error(ERR_FAILED_ADD_TWEAK_TO_PUBLIC_KEY);
  }

  size_t len = compressed ? 33 : 65;
  unsigned char serialized_pubkey[len];
  if (!secp256k1_ec_pubkey_serialize(
          this->ctx, serialized_pubkey, &len, &pubkey,
          compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
    throw std::runtime_error(ERR_FAILED_SERIALIZE_PUBLIC_KEY);
  }

  return ArrayBuffer::copy(serialized_pubkey, len);
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::ecdsaSignHash(
    const std::shared_ptr<ArrayBuffer> &hash,
    const std::shared_ptr<ArrayBuffer> &privateKey, bool der, bool recovery,
    const std::optional<std::shared_ptr<ArrayBuffer>> &extraEntropy) {
  if (hash->size() != 32) {
    throw std::runtime_error(ERR_INVALID_HASH_LENGTH);
  }

  if (privateKey->size() != 32) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY_LENGTH);
  }

  if (extraEntropy) {
    if ((*extraEntropy)->size() != 32) {
      throw std::runtime_error(ERR_INVALID_EXTRA_ENTROPY_LENGTH);
    }
  }

  // Validates the private key
  if (!secp256k1_ec_seckey_verify(this->ctx, privateKey->data())) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY);
  }

  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_sign(this->ctx, &sig, hash->data(), privateKey->data(),
                            NULL,
                            extraEntropy ? (*extraEntropy)->data() : NULL)) {
    throw std::runtime_error(ERR_FAILED_SIGNING_HASH);
  }

  if (der) {
    // DER signatures are variable length, but 73 bytes is the maximum length
    size_t len = 73;
    unsigned char serialized_sig[len];
    // len gets updated to the actual length of the serialized signature
    if (!secp256k1_ecdsa_signature_serialize_der(this->ctx, serialized_sig,
                                                 &len, &sig)) {
      throw std::runtime_error(ERR_FAILED_SERIALIZE_SIGNATURE);
    }

    return ArrayBuffer::copy(serialized_sig, len);
  } else {
    size_t len = 64;
    unsigned char serialized_sig[len];
    if (!secp256k1_ecdsa_signature_serialize_compact(this->ctx, serialized_sig,
                                                     &sig)) {
      throw std::runtime_error(ERR_FAILED_SERIALIZE_SIGNATURE);
    }

    return ArrayBuffer::copy(serialized_sig, len);
  }
}

bool HybridSecp256k1::ecdsaVerifyHash(
    const std::shared_ptr<ArrayBuffer> &signature,
    const std::shared_ptr<ArrayBuffer> &hash,
    const std::shared_ptr<ArrayBuffer> &publicKey) {
  // Validate the signature length for a compact signature
  if (signature->size() != 64) {
    throw std::runtime_error(ERR_INVALID_SIGNATURE_LENGTH);
  }

  if (hash->size() != 32) {
    throw std::runtime_error(ERR_INVALID_HASH_LENGTH);
  }

  if (publicKey->size() != 33 && publicKey->size() != 65) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY_LENGTH);
  }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(this->ctx, &pubkey, publicKey->data(),
                                 publicKey->size())) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY);
  }

  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature->data())) {
    throw std::runtime_error(ERR_FAILED_DESERIALIZE_SIGNATURE);
  }

  return 1 == secp256k1_ecdsa_verify(this->ctx, &sig, hash->data(), &pubkey);
}

std::shared_ptr<ArrayBuffer> HybridSecp256k1::schnorrSign(
    const std::shared_ptr<ArrayBuffer> &message,
    const std::shared_ptr<ArrayBuffer> &privateKey,
    const std::optional<std::shared_ptr<ArrayBuffer>> &extraEntropy) {
  if (message->size() != 32) {
    throw std::runtime_error(ERR_INVALID_HASH_LENGTH);
  }

  if (privateKey->size() != 32) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY_LENGTH);
  }

  if (extraEntropy) {
    if ((*extraEntropy)->size() != 32) {
      throw std::runtime_error(ERR_INVALID_EXTRA_ENTROPY_LENGTH);
    }
  }

  // Parse private key to keypair, this validates it as well
  secp256k1_keypair keypair;
  // TODO: overwrite ^this data on delete to prevent it from lingering in memory
  if (!secp256k1_keypair_create(this->ctx, &keypair, privateKey->data())) {
    throw std::runtime_error(ERR_INVALID_PRIVATE_KEY);
  }

  unsigned char signature[64];
  if (!secp256k1_schnorrsig_sign32(
          this->ctx, signature, message->data(), &keypair,
          extraEntropy ? (*extraEntropy)->data() : NULL)) {
    throw std::runtime_error(ERR_FAILED_SIGNING_HASH);
  }

  return ArrayBuffer::copy(signature, 64);
}

bool HybridSecp256k1::schnorrVerify(
    const std::shared_ptr<ArrayBuffer> &signature,
    const std::shared_ptr<ArrayBuffer> &message,
    const std::shared_ptr<ArrayBuffer> &xOnly) {
  // Validate the signature length for a compact signature
  if (signature->size() != 64) {
    throw std::runtime_error(ERR_INVALID_SIGNATURE_LENGTH);
  }

  if (message->size() != 32) {
    throw std::runtime_error(ERR_INVALID_HASH_LENGTH);
  }

  if (xOnly->size() != 32) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY_LENGTH);
  }

  secp256k1_xonly_pubkey xonly_pubkey;
  if (!secp256k1_xonly_pubkey_parse(this->ctx, &xonly_pubkey, xOnly->data())) {
    throw std::runtime_error(ERR_INVALID_PUBLIC_KEY);
  }

  return 1 == secp256k1_schnorrsig_verify(this->ctx, signature->data(),
                                          message->data(), message->size(),
                                          &xonly_pubkey);
}

} // namespace margelo::nitro::nitrocrypto
