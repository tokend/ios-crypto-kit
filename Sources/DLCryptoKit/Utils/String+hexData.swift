import Foundation

extension String {
    
    /// Inits string with hex encoded data string
    /// - Returns: `String?`
    /// - Parameters:
    ///     - encoding: String encoding. Default is `UTF8`.
    public init?(hexadecimal string: String, encoding: String.Encoding = .utf8) {
        guard let data = string.hexadecimal() else {
            return nil
        }
        
        self.init(data: data, encoding: encoding)
    }
    
    /// Method converts string to hex format
    /// - Returns: `String?`
    /// - Parameters:
    ///     - encoding: String encoding
    public func hexadecimalString(encoding: String.Encoding = .utf8) -> String? {
        return self.data(using: encoding)?.hexadecimal()
    }
    
    /// Method converts string to hex and transforms to data
    /// - Returns: `Data?`
    public func hexadecimal() -> Data? {
        var data = Data(capacity: self.lengthOfBytes(using: .utf8) / 2)
        
        let regex = try? NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex?.enumerateMatches(in: self, range: NSRange(0 ..< utf16.count), using: { (match, _, _) in
            let byteString = (self as NSString).substring(with: match!.range)
            var num = UInt8(byteString, radix: 16)!
            data.append(&num, count: 1)
        })
        
        guard data.count > 0 else {
            return nil
        }
        
        return data
    }
}
