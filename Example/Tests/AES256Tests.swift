import XCTest
import DLCryptoKit

class AES256Tests: XCTestCase {
    
    let message = "TokenD is awesome".data(using: .utf8)!
    let cipherText = "7056bd62af0a6d574a5b8bb1b0da278bdd36b5ef529a14164cd7db716e8556f3f8".hexadecimal()!
    let key = "2e0c7a28545d4c53a1f4b9ef82245d7da853c7f0b0ae949040faedaa60c23c0b".hexadecimal()!
    let iv = Data(base64Encoded: "dcDptDqlQv7tWIT2")!
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testAES256gcmEncrypt() {
        do {
            let result = try AES256.aes256gcmEncrypt(
                message: self.message,
                key: self.key,
                iv: self.iv
                ).hexadecimal()
            
            let expected = self.cipherText.hexadecimal()
            
            XCTAssert(result.caseInsensitiveCompare(expected) == .orderedSame, "AES256gcmEncrypt failed")
            
        } catch let error {
            XCTAssert(false, "Encrypt failed: \(error.localizedDescription)")
        }
    }
    
    func testAES256gcmDecrypt() {
        do {
            let result = try AES256.aes256gcmDecrypt(
                cypherText: self.cipherText,
                key: self.key,
                iv: self.iv
                ).hexadecimal()
            
            let expected = self.message.hexadecimal()
            
            XCTAssert(result.caseInsensitiveCompare(expected) == .orderedSame, "AES256gcmDecrypt failed")
            
        } catch let error {
            XCTAssert(false, "Decrypt failed: \(error.localizedDescription)")
        }
    }
}
