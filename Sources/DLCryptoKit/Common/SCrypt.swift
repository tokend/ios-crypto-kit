import Foundation
import Clibsodium

public extension Common {
    
    /// Provides functionality which allows you to derive keys
    enum SCrypt {
        
        /// Error models that may occur while performing `SCrypt.scryptSalsa208sha256`
        public enum SCryptSalsa208sha256Error: Error {
            case hashFailed
        }
        
        /// Method derives key using given password and parameters
        /// then encrypts it via Salasa20 and SHA256
        /// - Returns: `Data`
        /// - Parameters:
        ///     - password: Data which is used to derive key
        ///     - salt: Data which is used to safeguard password
        ///     - n: CPU/memory cost parameter
        ///     - r: Blocksize parameter
        ///     - p: Parallelization parameter
        ///     - keyLength: Length of result key
        public static func scryptSalsa208sha256(
            password: Data,
            salt: Data,
            n: UInt64,
            r: UInt32,
            p: UInt32,
            keyLength: Int
            ) throws -> Data {
            
            let result: Data = try password.withUnsafeBytes { (pwdU8Ptr: UnsafePointer<UInt8>) in
                let passwordPtr = pwdU8Ptr
                let passwordLength: Int = password.count
                
                let result: Data = try salt.withUnsafeBytes { (saltU8Ptr: UnsafePointer<UInt8>) in
                    let saltPtr = saltU8Ptr
                    let saltLength: Int = salt.count
                    
                    let bufLength = keyLength
                    let buf: UMPointer<UInt8> = UMPointer<UInt8>.allocate(capacity: bufLength)
                    buf.initialize(repeating: 0, count: bufLength)
                    defer {
                        buf.deinitialize(count: bufLength)
                        buf.deallocate()
                    }
                    
                    let hashResult = crypto_pwhash_scryptsalsa208sha256_ll(
                        passwordPtr,
                        passwordLength,
                        saltPtr,
                        saltLength,
                        n,
                        r,
                        p,
                        buf,
                        bufLength
                    )
                    guard hashResult == 0 else {
                        throw SCryptSalsa208sha256Error.hashFailed
                    }
                    
                    let bufferPointer = UnsafeBufferPointer.init(start: buf, count: bufLength)
                    let result = Data.init(buffer: bufferPointer)
                    
                    return result
                }
                
                return result
            }
            
            return result
        }
    }
}
