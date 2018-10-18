import Foundation

public typealias UMPointer = UnsafeMutablePointer
public typealias UMRPointer = UnsafeMutableRawPointer

public enum Common {
    
    // MARK: - Public
    
    public static func getData<Pointee, PointeeLength: FixedWidthInteger>(
        capacity: Int,
        pointeeType: Pointee.Type,
        pointeeLengthType: PointeeLength.Type,
        execute: ((_ buf: UMPointer<Pointee>, _ bufLength: UMPointer<PointeeLength>) throws -> Void)
        ) throws -> Data {
        
        let buf: UMPointer<Pointee> = UMPointer<Pointee>.allocate(capacity: capacity)
        defer {
            buf.deinitialize(count: capacity)
            buf.deallocate()
        }
        
        let bufLengtPtr: UMPointer<PointeeLength> = UMPointer<PointeeLength>.allocate(capacity: 1)
        defer {
            bufLengtPtr.deinitialize(count: 1)
            bufLengtPtr.deallocate()
        }
        
        try execute(buf, bufLengtPtr)
        
        let bufferPointer = UnsafeBufferPointer.init(start: buf, count: Int(bufLengtPtr.pointee))
        let resultData = Data.init(buffer: bufferPointer)
        
        return resultData
    }
    
    public static func getData<Alignment>(
        capacity: Int,
        alignment: Alignment.Type,
        execute: ((_ buf: UMRPointer) throws -> Void)
        ) throws -> Data {
        
        let alignmentValue = MemoryLayout<Alignment>.alignment
        
        let buf: UMRPointer = UMRPointer.allocate(byteCount: capacity, alignment: alignmentValue)
        defer {
            buf.deallocate()
        }
        
        try execute(buf)
        
        let resultData = Data.init(bytes: buf, count: capacity)
        
        return resultData
    }
    
    public static func getSafeData<Pointee>(
        capacity: Int,
        pointeeType: Pointee.Type,
        execute: ((_ buf: UMPointer<Pointee>) -> Void)
        ) -> Data {
        
        let buf: UMPointer<Pointee> = UMPointer<Pointee>.allocate(capacity: capacity)
        defer {
            buf.deinitialize(count: capacity)
            buf.deallocate()
        }
        
        execute(buf)
        
        let bufferPointer = UnsafeBufferPointer.init(start: buf, count: capacity)
        let resultData = Data.init(buffer: bufferPointer)
        
        return resultData
    }
}
