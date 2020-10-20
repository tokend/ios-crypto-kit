import Foundation

/// Provides functionality that allows to encrypt data with AES256 in GCM mode.
public enum AES256 {
    
    public enum CryptoLibraryError: Error {
        case cryptoContextInitFailed
        case aes256gcmUnavailable
        case ivLengthAdjustFailed
        case ivOrKeyInitFailed
    }
    
    /// Errors that may occur while encrypting
    public enum AES256gcmEncryptError: Error {
        
        /// Case of failed encryption
        case failedToEncrypt
    }
    
    /// Method encrypts given message via AES256 GCM
    /// - Returns: `Data`
    /// - Parameters:
    ///     - message: Data to be encrypted
    ///     - key: Key which is used to encrypt
    ///     - iv: Initialization vector data
    public static func aes256gcmEncrypt(
        message: Data,
        key: Data,
        iv: Data
        ) throws -> Data {
        
        let result: Data = try message.withUnsafeBytes { (messagePtr: UnsafePointer<UInt8>) in
            let messageLength: Int32 = Int32(message.count)
            
            let result: Data = try key.withUnsafeBytes { (keyPtr: UnsafePointer<UInt8>) in
                
                let result: Data = try iv.withUnsafeBytes { (ivPtr: UnsafePointer<UInt8>) in
                    let ivLength = Int32(iv.count)
                    
                    let ctx = try self.initEncryptionContext(iv: ivPtr, ivLength: ivLength, key: keyPtr)
                    defer {
                        self.deinitCryptoContext(ctx)
                    }
                    
                    var resultData = try Common.getData(
                        capacity: Int(messageLength),
                        pointeeType: UInt8.self,
                        pointeeLengthType: Int32.self,
                        execute: { (buf, bufLength) in
                            guard EVP_EncryptUpdate(
                                ctx,
                                buf,
                                bufLength,
                                messagePtr,
                                messageLength
                                ) == 1 else {
                                    throw AES256gcmEncryptError.failedToEncrypt
                            }
                    })
                    
                    let finalData = try Common.getData(
                        capacity: 16,
                        pointeeType: UInt8.self,
                        pointeeLengthType: Int32.self,
                        execute: { (buf, bufLength) in
                            guard EVP_EncryptFinal_ex(
                                ctx,
                                buf,
                                bufLength
                                ) == 1 else {
                                    throw AES256gcmEncryptError.failedToEncrypt
                            }
                    })
                    
                    let tagData = try Common.getData(
                        capacity: Int(EVP_GCM_TLS_TAG_LEN),
                        alignment: UInt8.self,
                        execute: { (buf) in
                            guard EVP_CIPHER_CTX_ctrl(
                                ctx,
                                EVP_CTRL_GCM_GET_TAG,
                                EVP_GCM_TLS_TAG_LEN,
                                buf
                                ) == 1 else {
                                    throw AES256gcmEncryptError.failedToEncrypt
                            }
                    })
                    
                    resultData.append(finalData)
                    resultData.append(tagData)
                    
                    return resultData
                }
                
                return result
            }
            
            return result
        }
        
        return result
    }
    
    public enum AES256gcmDecryptError: Error {
        case failedToDecrypt
        case verificationFailed
    }
    
    /// Method encrypts given message with AES256 in GCM mode
    /// - Returns: `Data`
    /// - Parameters:
    ///     - cypherText: Data to be decrypted
    ///     - key: Key which was used to encrypt
    ///     - iv: Initialization vector data
    public static func aes256gcmDecrypt(
        cypherText: Data,
        key: Data,
        iv: Data
        ) throws -> Data {
        
        let cypherData = cypherText[0..<cypherText.count - Int(EVP_GCM_TLS_TAG_LEN)]
        var tagData = cypherText[cypherText.count - Int(EVP_GCM_TLS_TAG_LEN)..<cypherText.count]
        
        let result: Data = try cypherData.withUnsafeBytes { (cypherDataPtr: UnsafePointer<UInt8>) in
            let cypherDataLength: Int32 = Int32(cypherData.count)
            
            let result: Data = try tagData.withUnsafeMutableBytes { (tagDataPtr: UMPointer<UInt8>) in
                let tagDataRawPtr = UMRPointer(tagDataPtr)
                
                let result: Data = try key.withUnsafeBytes { (keyPtr: UnsafePointer<UInt8>) in

                    let result: Data = try iv.withUnsafeBytes { (ivPtr: UnsafePointer<UInt8>) in
                        let ivLength = Int32(iv.count)
                        
                        let ctx = try self.initDecryptionContext(iv: ivPtr, ivLength: ivLength, key: keyPtr)
                        defer {
                            self.deinitCryptoContext(ctx)
                        }
                        
                        var messageData = try Common.getData(
                            capacity: Int(cypherDataLength),
                            pointeeType: UInt8.self,
                            pointeeLengthType: Int32.self,
                            execute: { (buf, bufLength) in
                                guard EVP_DecryptUpdate(
                                    ctx,
                                    buf,
                                    bufLength,
                                    cypherDataPtr,
                                    cypherDataLength
                                    ) == 1 else {
                                        throw AES256gcmDecryptError.failedToDecrypt
                                }
                        })
                        
                        guard EVP_CIPHER_CTX_ctrl(
                            ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            EVP_GCM_TLS_TAG_LEN,
                            tagDataRawPtr
                            ) == 1 else {
                                throw AES256gcmDecryptError.verificationFailed
                        }
                        
                        let finalData = try Common.getData(
                            capacity: 16,
                            pointeeType: UInt8.self,
                            pointeeLengthType: Int32.self,
                            execute: { (buf, bufLength) in
                                guard EVP_DecryptFinal_ex(
                                    ctx,
                                    buf,
                                    bufLength
                                    ) > 0 else {
                                        throw AES256gcmDecryptError.verificationFailed
                                }
                        })
                        
                        messageData.append(finalData)
                        
                        return messageData
                    }
                    
                    return result
                }
                
                return result
            }
            
            return result
        }
        
        return result
    }
    
    // MARK: - Private
    
    private static func initEncryptionContext(
        iv: UnsafePointer<UInt8>,
        ivLength: Int32,
        key: UnsafePointer<UInt8>
        ) throws -> OpaquePointer {
        
        guard let ctx = EVP_CIPHER_CTX_new() else {
            throw CryptoLibraryError.cryptoContextInitFailed
        }
        
        let successCode: Int32 = 1
        
        guard EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil) == successCode else {
            throw CryptoLibraryError.aes256gcmUnavailable
        }
        
        guard EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, nil) == successCode else {
            throw CryptoLibraryError.ivLengthAdjustFailed
        }
        
        guard EVP_EncryptInit_ex(ctx, nil, nil, key, iv) == successCode else {
            throw CryptoLibraryError.ivOrKeyInitFailed
        }
        
        return ctx
    }
    
    private static func initDecryptionContext(
        iv: UnsafePointer<UInt8>,
        ivLength: Int32,
        key: UnsafePointer<UInt8>
        ) throws -> OpaquePointer {
        
        guard let ctx = EVP_CIPHER_CTX_new() else {
            throw CryptoLibraryError.cryptoContextInitFailed
        }
        
        let successCode: Int32 = 1
        
        guard EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil) == successCode else {
            throw CryptoLibraryError.aes256gcmUnavailable
        }
        
        guard EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, nil) == successCode else {
            throw CryptoLibraryError.ivLengthAdjustFailed
        }
        
        guard EVP_DecryptInit_ex(ctx, nil, nil, key, iv) == successCode else {
            throw CryptoLibraryError.ivOrKeyInitFailed
        }
        
        return ctx
    }
    
    private static func deinitCryptoContext(_ ctx: OpaquePointer) {
        EVP_CIPHER_CTX_free(ctx)
    }
}
