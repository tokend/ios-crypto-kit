import Foundation
import Clibsodium

public enum ECDSA {
    
    public static let signatureSize: Int = crypto_sign_ed25519_bytes()
    
    // MARK: - Public
    
    /// Error models which may occur while signing data
    public enum SignED25519Error: Error {
        
        /// Case of signing failure
        case signFailed
    }
    
    /// Method signs data with given key
    /// - Returns: `Data`
    /// - Parameters:
    ///     - data: Data to be signed
    ///     - keyData: Key used to sign
    public static func signED25519(
        data: Data,
        keyData: KeyData
        ) throws -> Data {
        
        let result: Data = try data.withUnsafeBytes { (dataPtr: UnsafePointer<UInt8>) in
            let dataLength: UInt64 = UInt64(data.count)
            
            let privateKeyData = keyData.getPrivateKeyData()
            let result: Data = try privateKeyData.withUnsafeBytes { (keyPtr: UnsafePointer<UInt8>) in
                
                let signature = try Common.getData(
                    capacity: self.signatureSize,
                    pointeeType: UInt8.self,
                    pointeeLengthType: UInt64.self,
                    execute: { (buf, bufLength) in
                        guard crypto_sign_ed25519_detached(
                            buf,
                            bufLength,
                            dataPtr,
                            dataLength,
                            keyPtr
                            ) == 0 else {
                                throw SignED25519Error.signFailed
                        }
                })
                
                return signature
            }
            
            return result
        }
        
        return result
    }
    
    /// Method verifies signature
    /// - Returns: `Bool`
    /// - Parameters:
    ///     - signatureData: Data to be verified
    ///     - messageData: Message to be signed
    ///     - publicKeyData: Public key used to sign message
    public static func verifyED25519(
        signatureData: Data,
        messageData: Data,
        publicKeyData: Data
        ) -> Bool {
        let result: Bool = signatureData.withUnsafeBytes { (signatureDataPtr: UnsafePointer<UInt8>) in
            let result: Bool = messageData.withUnsafeBytes { (messageDataPtr: UnsafePointer<UInt8>) in
                let messageLength: UInt64 = UInt64(messageData.count)
                
                let result: Bool = publicKeyData.withUnsafeBytes { (publicKeyDataPtr: UnsafePointer<UInt8>) in
                    
                    guard crypto_sign_ed25519_verify_detached(
                        signatureDataPtr,
                        messageDataPtr,
                        messageLength,
                        publicKeyDataPtr
                        ) == 0 else {
                            return false
                    }
                    
                    return true
                }
                
                return result
            }
            
            return result
        }
        
        return result
    }
}

extension ECDSA {
    
    /// Struct contains key pair data
    public struct KeyData {
        
        // MARK: - Static properties
        
        public static let seedSize: Int = crypto_sign_ed25519_seedbytes()
        public static let privateKeySize: Int = crypto_sign_ed25519_secretkeybytes()
        public static let publicKeySize: Int = crypto_sign_ed25519_publickeybytes()
        
        // MARK: - Private properties
        
        fileprivate let privateKeyData: Data
        fileprivate let publicKeyData: Data
        
        // MARK: -
        
        /// Errors that may occur while initializing key pair
        public enum KeyInitError: Error {
            
            /// Case of initializing key with the seed of wrong size
            case wrongSeedSize
            
            /// Case of failed initializing
            case initFailed
        }
        
        /// Inits new random key pair
        public init() throws {
            var publicKey: Data = Data()
            let privateKey = try Common.getData(
                capacity: ECDSA.KeyData.privateKeySize,
                pointeeType: UInt8.self,
                pointeeLengthType: Int.self,
                execute: { (privateBuf, privateBufLength) in
                    
                    let pubKey = try Common.getData(
                        capacity: ECDSA.KeyData.publicKeySize,
                        pointeeType: UInt8.self,
                        pointeeLengthType: Int.self,
                        execute: { (publicBuf, publicBufLength) in
                            
                            guard crypto_sign_ed25519_keypair(
                                publicBuf,
                                privateBuf
                                ) == 0 else {
                                    throw KeyInitError.initFailed
                            }
                            
                            publicBufLength.assign(repeating: ECDSA.KeyData.publicKeySize, count: 1)
                    })
                    
                    privateBufLength.assign(repeating: ECDSA.KeyData.privateKeySize, count: 1)
                    publicKey = pubKey
            })
            
            guard
                publicKey.count == KeyData.publicKeySize,
                privateKey.count == KeyData.privateKeySize else {
                    throw KeyData.KeyInitError.initFailed
            }
            
            self.privateKeyData = privateKey
            self.publicKeyData = publicKey
        }
        
        /// Inits key pair with given seed
        public init(seed: Data) throws {
            var publicKey: Data = Data()
            let privateKey: Data = try seed.withUnsafeBytes { (seedPtr: UnsafePointer<UInt8>) in
                let seedLength = seed.count
                
                guard seedLength == ECDSA.KeyData.seedSize else {
                    throw KeyInitError.wrongSeedSize
                }
                
                let privateKey = try Common.getData(
                    capacity: ECDSA.KeyData.privateKeySize,
                    pointeeType: UInt8.self,
                    pointeeLengthType: Int.self,
                    execute: { (privateBuf, privateBufLength) in
                        
                        let pubKey = try Common.getData(
                            capacity: ECDSA.KeyData.publicKeySize,
                            pointeeType: UInt8.self,
                            pointeeLengthType: Int.self,
                            execute: { (publicBuf, publicBufLength) in
                                
                                guard crypto_sign_ed25519_seed_keypair(
                                    publicBuf,
                                    privateBuf,
                                    seedPtr
                                    ) == 0 else {
                                        throw KeyInitError.initFailed
                                }
                                
                                publicBufLength.assign(repeating: ECDSA.KeyData.publicKeySize, count: 1)
                        })
                        
                        privateBufLength.assign(repeating: ECDSA.KeyData.privateKeySize, count: 1)
                        publicKey = pubKey
                })
                
                return privateKey
            }
            
            guard
                publicKey.count == KeyData.publicKeySize,
                privateKey.count == KeyData.privateKeySize else {
                    throw KeyData.KeyInitError.initFailed
            }
            
            self.privateKeyData = privateKey
            self.publicKeyData = publicKey
        }
        
        // MARK: - Public
        
        /// Method fetches private key data from key pair
        /// - Returns: `Data`
        public func getPrivateKeyData() -> Data {
            return self.privateKeyData
        }
        
        /// Method fetches public key data from key pair
        /// - Returns: `Data`
        public func getPublicKeyData() -> Data {
            return self.publicKeyData
        }
        
        /// Method fetches seed data from key pair
        /// - Returns: `Data`
        public func getSeedData() -> Data {
            let seed: Data = self.privateKeyData.withUnsafeBytes { (privateKeyPtr: UnsafePointer<UInt8>) in
                let seedSize = KeyData.seedSize
                
                let seed = Common.getSafeData(
                    capacity: seedSize,
                    pointeeType: UInt8.self,
                    execute: { (buf) in
                        _ = crypto_sign_ed25519_sk_to_seed(
                            buf,
                            privateKeyPtr
                        )
                })
                
                return seed
            }
            
            return seed
        }
    }
}
