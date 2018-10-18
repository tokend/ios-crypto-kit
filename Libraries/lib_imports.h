#ifndef openssl_h
#define openssl_h

// libsodium
#import <libsodium/core.h>
#import <libsodium/crypto_auth_hmacsha256.h>
#import <libsodium/crypto_pwhash_scryptsalsa208sha256.h>
#import <libsodium/crypto_sign.h>
#import <libsodium/randombytes.h>

// OpenSSL
#import <openssl/aes.h>
#import <openssl/evp.h>
#import <openssl/sha.h>

#endif /* openssl_h */
