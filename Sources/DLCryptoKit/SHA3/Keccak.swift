import Foundation
import Ckeccaktiny

/// Provides functionality that allows to encrypt data with Keccak
public enum Keccak {
    
    /// Method encrypts data with Keccak224
    /// - Parameter data: Data to be encrypted
    /// - Returns: `Data`
    public static func keccak224(data: Data) -> Data {
        return keccak(
            data: data,
            len: 224 / 8,
            keccakClosure: { keccak_224($0, $1, $2, $3) }
        )
    }
    
    /// Method encrypts data with Keccak256
    /// - Parameter data: Data to be encrypted
    /// - Returns: `Data`
    public static func keccak256(data: Data) -> Data {
        return keccak(
            data: data,
            len: 256 / 8,
            keccakClosure: { keccak_256($0, $1, $2, $3) }
        )
    }
    
    /// Method encrypts data with Keccak384
    /// - Parameter data: Data to be encrypted
    /// - Returns: `Data`
    public static func keccak384(data: Data) -> Data {
        return keccak(
            data: data,
            len: 384 / 8,
            keccakClosure: { keccak_384($0, $1, $2, $3) }
        )
    }
    
    /// Method encrypts data with Keccak512
    /// - Parameter data: Data to be encrypted
    /// - Returns: `Data`
    public static func keccak512(data: Data) -> Data {
        return keccak(
            data: data,
            len: 512 / 8,
            keccakClosure: { keccak_512($0, $1, $2, $3) }
        )
    }
    
    typealias KeccakClosure = (UnsafeMutablePointer<UInt8>, Int, UnsafePointer<UInt8>, Int) -> Void
    static func keccak(
        data: Data,
        len: Int,
        keccakClosure: KeccakClosure
    ) -> Data {
        let nsData = data as NSData
        let input = nsData.bytes.bindMemory(to: UInt8.self, capacity: data.count)
        let result = UnsafeMutablePointer<UInt8>.allocate(capacity: len)
        keccakClosure(result, len, input, data.count)
        return Data(bytes: result, count: len)
    }
}
