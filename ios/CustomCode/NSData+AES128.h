//
//  NSData+AES128.h
//  Electron-Cash
//
//  Created by calin on 9/20/18.
//  Copyright © 2018 Calin Culianu. All rights reserved.
//
//  MIT License
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (AES128)

// Encrypt data, padding with PKCS#7 bytes. Returns nil on error.
- (NSData *)AES128EncryptWithKey:(NSData * __nonnull)key initializationVector:(NSData * __nullable)iv;

// Decrypts, returns nil on error.
- (NSData *)AES128DecryptWithKey:(NSData * __nonnull)key initializationVector:(NSData * __nullable)iv;
// Decrypts but doesn't strip the PKCS#7 padding from the returned data.
- (NSData *)AES128DecryptWithKey:(NSData * __nonnull)key initializationVector:(NSData * __nullable)iv keepPadding:(BOOL)keepPadding;

@end

NS_ASSUME_NONNULL_END
