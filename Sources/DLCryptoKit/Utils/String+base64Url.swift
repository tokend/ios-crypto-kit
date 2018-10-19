import Foundation

extension String {
    
    /// Method transforms string from base 64 url to base 64 string
    /// - Returns: `String`
    public func base64UrlToBase64String() -> String {
        var base64 = self
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return base64
    }
    
    /// Method transforms string from base 64 string to base 64 url
    /// - Returns: `String`
    public func base64StringToBase64Url() -> String {
        var base64 = self
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return base64
    }
}
