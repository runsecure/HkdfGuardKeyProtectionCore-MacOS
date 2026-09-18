//
//  HkdfGuardKeyProtectionEnclave.h
//  HkdfGuardKeyProtectionEnclave
//

#import <Foundation/Foundation.h>

//! Project version number for HkdfGuardKeyProtectionEnclave.
FOUNDATION_EXPORT double HkdfGuardKeyProtectionEnclaveVersionNumber;

//! Project version string for HkdfGuardKeyProtectionEnclave.
FOUNDATION_EXPORT const unsigned char HkdfGuardKeyProtectionEnclaveVersionString[];

// In this header, import any public headers of the framework that should be
// visible to Objective-C consumers, e.g.:
// #import <HkdfGuardKeyProtectionEnclave/PublicHeader.h>

#ifndef HKDFGUARD_MACOS_H
#define HKDFGUARD_MACOS_H

#include <stdint.h>

// Status codes returned by both functions below:
//    0  success
//   -1  invalidInputLength     (dek_len or wrapped_len is wrong)
//   -2  outputBufferTooSmall   (*out_len is set to the required size)
//   -3  keyUnavailable         (Secure Enclave key could not be obtained)
//   -4  publicKeyUnavailable
//   -5  encryptionFailed
//   -6  decryptionFailed       (also returned for a wrong/mismatched service)
//   -7  unexpectedOutputLength
//   -8  missingServiceIdentifier (service was NULL or an empty string)

// `service` must be a non-empty, null-terminated UTF-8 string identifying
// the calling application. Each distinct service string gets its own,
// independent Secure Enclave key — wrapping under one service's identifier
// and unwrapping under a different one will fail, by design.
int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek,
    int32_t dek_len,
    uint8_t* out,
    int32_t* out_len
);

int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped,
    int32_t wrapped_len,
    uint8_t* out,
    int32_t* out_len
);

#endif
