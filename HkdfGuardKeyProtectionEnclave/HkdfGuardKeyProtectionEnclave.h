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

int32_t hkdfguard_wrap_dek(
    const uint8_t* dek,
    int32_t dek_len,
    uint8_t* out,
    int32_t* out_len
);

int32_t hkdfguard_unwrap_dek(
    const uint8_t* dek,
    int32_t dek_len,
    uint8_t* out,
    int32_t* out_len
);

#endif
