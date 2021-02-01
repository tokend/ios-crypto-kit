import Foundation
import Ckeccaktiny

/// Provides functionality that allows to encrypt data with SHA3
public enum SHA3 {
    
    /// Method encrypts data with SHA3-224
    /// - Parameter data: Data to be encrypted
    /// - Returns: `Data`
    public static func sha224(data: Data) -> Data {
        return sha(
            data: data,
            len: 224 / 8,
            sha3Closure: { sha3_224($0, $1, $2, $3) }
        )
    }
    
    /// Method encrypts data with SHA3-256
    /// - Parameter data: Data to be encrypted
    /// - Returns: `Data`
    public static func sha256(data: Data) -> Data {
        return sha(
            data: data,
            len: 256 / 8,
            sha3Closure: { sha3_256($0, $1, $2, $3) }
        )
    }
    
    /// Method encrypts data with SHA3-384
    /// - Parameter data: Data to be encrypted
    /// - Returns: `Data`
    public static func sha384(data: Data) -> Data {
        return sha(
            data: data,
            len: 384 / 8,
            sha3Closure: { sha3_384($0, $1, $2, $3) }
        )
    }
    
    /// Method encrypts data with SHA3-512
    /// - Parameter data: Data to be encrypted
    /// - Returns: `Data`
    public static func sha512(data: Data) -> Data {
        return sha(
            data: data,
            len: 512 / 8,
            sha3Closure: { sha3_512($0, $1, $2, $3) }
        )
    }
    
    typealias SHAClosure = (UnsafeMutablePointer<UInt8>, Int, UnsafePointer<UInt8>, Int) -> Void
    static func sha(
        data: Data,
        len: Int,
        sha3Closure: SHAClosure
    ) -> Data {
        let nsData = data as NSData
        let input = nsData.bytes.bindMemory(to: UInt8.self, capacity: data.count)
        let result = UnsafeMutablePointer<UInt8>.allocate(capacity: len)
        sha3Closure(result, len, input, data.count)
        return Data(bytes: result, count: len)
    }
}
