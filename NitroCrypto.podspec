require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "NitroCrypto"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported, :visionos => 1.0 }
  s.source       = { :git => "https://github.com/mrousavy/nitro.git", :tag => "#{s.version}" }

  s.source_files = [
    # Implementation (Swift)
    "ios/**/*.{swift}",
    # Autolinking/Registration (Objective-C++)
    "ios/**/*.{m,mm}",
    # Implementation (C++ objects)
    "cpp/**/*.{hpp,cpp}",
    # libsecp256k1 dependency (C)
    "cpp/secp256k1/{include}/*.{h}",
  ]

  # Include the precompiled static library
  s.vendored_libraries = "cpp/secp256k1/build/ios/libsecp256k1.a"
  
  # Link the static library at runtime
  s.libraries = "secp256k1"
  
  s.static_framework = true

  s.pod_target_xcconfig = {
    # C++ compiler flags, mainly for folly.
    "GCC_PREPROCESSOR_DEFINITIONS" => "$(inherited) FOLLY_NO_CONFIG FOLLY_CFG_NO_COROUTINES"
    # libsecp256k1 flags
    # "OTHER_CFLAGS" => "$(inherited) -DUSE_NUM_NONE=1 -DUSE_FIELD_INV_BUILTIN=1 -DUSE_SCALAR_INV_BUILTIN=1 -DUSE_FIELD_10X26=1 -DUSE_SCALAR_8X32=1 -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1"
  }

  load 'nitrogen/generated/ios/NitroCrypto+autolinking.rb'
  add_nitrogen_files(s)

  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'
  install_modules_dependencies(s)
end
