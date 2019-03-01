import Foundation
import Clibsodium

public extension Common {
    
    /// Provides methods for hashing data using HMAC
    public enum HMAC {
        
        /// Error models that may occur while encrypting
        public enum HMACSHA256Error: Error {
            
            /// Case of failed
            case hashFailed
        }
        
        /// Method hashes data with HMAC-SHA256
        /// - Returns: `Data`
        /// - Parameters:
        ///     - data: Data to be hashed
        ///     - key: Encryption key
        public static func hmacsha256(
            data: Data,
            key: Data
            ) throws -> Data {
            
            let result: Data = try data.withUnsafeBytes { (dataU8Ptr: UnsafePointer<UInt8>) in
                let dataPtr = dataU8Ptr
                let dataLength: UInt64 = UInt64(data.count)
                
                let result: Data = try key.withUnsafeBytes { (keyU8Ptr: UnsafePointer<UInt8>) in
                    let keyPtr = keyU8Ptr
                    let keyLength: Int = key.count
                    
                    let bufLength = crypto_auth_hmacsha256_bytes()
                    let buf: UMPointer<UInt8> = UMPointer<UInt8>.allocate(capacity: bufLength)
                    buf.initialize(repeating: 0, count: bufLength)
                    defer {
                        buf.deinitialize(count: bufLength)
                        buf.deallocate()
                    }
                    
                    let hashResult = crypto_auth_hmacsha256(
                        buf,
                        dataPtr,
                        dataLength,
                        keyPtr
                    )
                    guard hashResult == 0 else {
                        throw HMACSHA256Error.hashFailed
                    }
                    
                    let bufferPointer = UnsafeBufferPointer.init(start: buf, count: bufLength)
                    let resultData = Data.init(buffer: bufferPointer)
                    
                    return resultData
                }
                
                return result
            }
            
            return result
        }
    }
}
