import Foundation

extension Data {
    public func hexadecimal() -> String {
        return map { String(format: "%02x", $0) }.joined(separator: "")
    }
}
