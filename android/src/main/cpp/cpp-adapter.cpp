#include <jni.h>
#include "NitroCryptoOnLoad.hpp"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return margelo::nitro::nitrocrypto::initialize(vm);
}
