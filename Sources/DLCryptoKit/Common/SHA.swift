import Foundation

public extension Common {
    
    /// Provides methods for hashes data using SHA
    public enum SHA {
        
        /// Method encrypt data with SHA1
        /// - Returns: `Data`
        /// - Parameters:
        ///     - data: Data to be encrypted
        public static func sha1(data: Data) -> Data {
            let result: Data = data.withUnsafeBytes { (dataPointer: UnsafePointer<UInt8>) in
                let n: Int = data.count
                
                let hashLength = Int(SHA_DIGEST_LENGTH)
                let md: UMPointer<UInt8> = UMPointer<UInt8>.allocate(capacity: hashLength)
                md.initialize(repeating: 0, count: hashLength)
                defer {
                    md.deinitialize(count: hashLength)
                    md.deallocate()
                }
                
                let resultMd = SHA1(dataPointer, n, md)
                
                let bufferPointer = UnsafeBufferPointer.init(start: resultMd, count: hashLength)
                let result = Data.init(buffer: bufferPointer)
                
                return result
            }
            
            return result
        }
        
        /// Method encrypt data with SHA256
        /// - Returns: `Data`
        /// - Parameters:
        ///     - data: Data to be encrypted
        public static func sha256(data: Data) -> Data {
            let result: Data = data.withUnsafeBytes { (dataPointer: UnsafePointer<UInt8>) in
                let n: Int = data.count
                
                let hashLength = Int(SHA256_DIGEST_LENGTH)
                let md: UMPointer<UInt8> = UMPointer<UInt8>.allocate(capacity: hashLength)
                md.initialize(repeating: 0, count: hashLength)
                defer {
                    md.deinitialize(count: hashLength)
                    md.deallocate()
                }
                
                let resultMd = SHA256(dataPointer, n, md)
                
                let bufferPointer = UnsafeBufferPointer.init(start: resultMd, count: hashLength)
                let result = Data.init(buffer: bufferPointer)
                
                return result
            }
            
            return result
        }
    }
}
