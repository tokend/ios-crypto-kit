import Foundation

public enum TokenDKDF {
    
    public static let deriveKeyMasterKeyWalletId: String    = "WALLET_ID"
    public static let deriveKeyMasterKeyWalletKey: String   = "WALLET_KEY"
    
    public static let supportedEncryptionVersions: [Int] = [1]
    
    public enum DeriveKeyError: Error {
        case unsupportedEncryptionVersion
        case stringEncodingFailed
    }
    
    public static func deriveKey(
        login: String,
        password: String,
        salt: Data,
        masterKey: String,
        n: UInt64,
        r: UInt32,
        p: UInt32,
        encryptionVersion: Int = 1,
        keyLength: Int
        ) throws -> Data {
        
        guard self.supportedEncryptionVersions.contains(encryptionVersion) else {
            throw DeriveKeyError.unsupportedEncryptionVersion
        }
        
        guard
            let loginData = login.data(using: .utf8),
            let passwordData = password.data(using: .utf8),
            let masterKeyData = masterKey.data(using: .utf8)
            else {
                throw DeriveKeyError.stringEncodingFailed
        }
        
        let encryptionVersionData = Data.init(repeating: UInt8(encryptionVersion), count: 1)
        
        var composedRawSaltData = Data.init(capacity: encryptionVersionData.count + salt.count + loginData.count)
        composedRawSaltData.append(encryptionVersionData)
        composedRawSaltData.append(salt)
        composedRawSaltData.append(loginData)
        
        let composedSalt = Common.SHA.sha256(data: composedRawSaltData)
        let keyScrypted = try Common.SCrypt.scryptSalsa208sha256(
            password: passwordData,
            salt: composedSalt,
            n: n,
            r: r,
            p: p,
            keyLength: keyLength
        )
        let key = try Common.HMAC.hmacsha256(data: masterKeyData, key: keyScrypted)
        
        return key
    }
}
