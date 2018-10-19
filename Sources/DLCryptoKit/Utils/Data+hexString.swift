import Foundation

extension Data {
    
    /// Method transforms `Data` model to hex `String`
    /// - Returns: Hex string
    public func hexadecimal() -> String {
        return map { String(format: "%02x", $0) }.joined(separator: "")
    }
}
