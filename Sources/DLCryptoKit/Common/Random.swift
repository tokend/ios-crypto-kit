import Foundation

public extension Common {
    
    /// Provides functionality which allows you to generate random byte sequences
    public enum Random {
        
        /// Method generates random sequence of bytes
        /// - Returns: `Data`
        /// - Parameters:
        ///     - length: Length of byte sequence
        public static func generateRandom(length: Int) -> Data {
            let bufLength = length
            let buf: UMPointer<UInt8> = UMPointer<UInt8>.allocate(capacity: bufLength)
            buf.initialize(repeating: 0, count: bufLength)
            defer {
                buf.deinitialize(count: bufLength)
                buf.deallocate()
            }
            
            randombytes_buf(buf, bufLength)
            
            let bufferPointer = UnsafeBufferPointer.init(start: buf, count: bufLength)
            let result = Data.init(buffer: bufferPointer)
            
            return result
        }
    }
}
