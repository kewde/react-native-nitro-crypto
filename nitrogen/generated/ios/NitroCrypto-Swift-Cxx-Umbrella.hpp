///
/// NitroCrypto-Swift-Cxx-Umbrella.hpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2025 Marc Rousavy @ Margelo
///

#pragma once

// Forward declarations of C++ defined types


// Include C++ defined types


// C++ helpers for Swift
#include "NitroCrypto-Swift-Cxx-Bridge.hpp"

// Common C++ types used in Swift
#include <NitroModules/ArrayBufferHolder.hpp>
#include <NitroModules/AnyMapHolder.hpp>
#include <NitroModules/HybridContext.hpp>
#include <NitroModules/RuntimeError.hpp>

// Forward declarations of Swift defined types


// Include Swift defined types
#if __has_include("NitroCrypto-Swift.h")
// This header is generated by Xcode/Swift on every app build.
// If it cannot be found, make sure the Swift module's name (= podspec name) is actually "NitroCrypto".
#include "NitroCrypto-Swift.h"
// Same as above, but used when building with frameworks (`use_frameworks`)
#elif __has_include(<NitroCrypto/NitroCrypto-Swift.h>)
#include <NitroCrypto/NitroCrypto-Swift.h>
#else
#error NitroCrypto's autogenerated Swift header cannot be found! Make sure the Swift module's name (= podspec name) is actually "NitroCrypto", and try building the app first.
#endif
