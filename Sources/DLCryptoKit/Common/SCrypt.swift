import Foundation

public extension Common {
    
    public enum SCrypt {
        
        public enum SCryptSalsa208sha256Error: Error {
            case hashFailed
        }
        
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
