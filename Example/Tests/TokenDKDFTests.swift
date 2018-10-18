import XCTest
import DLCryptoKit

class TokenDKDFTests: XCTestCase {
    
    let login = "oleg@tokend.org"
    let password = "qwe123"
    let salt = Data(base64Encoded: "67ufG1N/Rf+j2ugDaXaopw==")!
    let n: UInt64 = 4096
    let r: UInt32 = 8
    let p: UInt32 = 1
    let keyLength = 32
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testDeriveWalletId() {
        let masterKey = TokenDKDF.deriveKeyMasterKeyWalletId
        
        let expectedKey = "96319900eff4dcc51beabd55200aa0f29490191ede16d26cd6adcc2554416dc3"
        
        let derivedKey: String
        do {
            derivedKey = try TokenDKDF.deriveKey(
                login: self.login,
                password: self.password,
                salt: self.salt,
                masterKey: masterKey,
                n: self.n,
                r: self.r,
                p: self.p,
                keyLength: self.keyLength
                ).hexadecimal()
        } catch let error {
            if let deriveError = error as? TokenDKDF.DeriveKeyError {
                switch deriveError {
                    
                case .stringEncodingFailed:
                    XCTAssert(false, "string encoding failed")
                    
                case .unsupportedEncryptionVersion:
                    XCTAssert(false, "unsupported encryption version")
                }
            } else {
                XCTAssert(false, "derive error: \(error.localizedDescription)")
            }
            return
        }
        
        XCTAssert(derivedKey.caseInsensitiveCompare(expectedKey) == .orderedSame, "DeriveWalletId failed")
    }
}
