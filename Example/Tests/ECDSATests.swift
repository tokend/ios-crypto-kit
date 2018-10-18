import XCTest
import DLCryptoKit

// swiftlint:disable line_length force_try

class ECDSATests: XCTestCase {
    
    let seedData: Data = Data(bytes: [UInt8].init(0..<32))
    let keyData = try! ECDSA.KeyData(seed: Data(bytes: [UInt8].init(0..<32)))
    let publicKey = "03A107BFF3CE10BE1D70DD18E74BC09967E4D6309BA50D5F1DDC8664125531B8".hexadecimal()!
    let message = "TokenD is awesome".data(using: .utf8)!
    let signature = "B0B890056CCBA3B3188EFF742F581EC08F0540706C9AA83B2B669E58F5E488DD892FD543F9C9182F6E6CBA013D3953CADD2D9EDF2938A45918F063FCA01A0B0A".hexadecimal()!
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testRandomKey() {
        do {
            let keyDataSeed1 = try ECDSA.KeyData().getSeedData().hexadecimal()
            let keyDataSeed2 = try ECDSA.KeyData().getSeedData().hexadecimal()
            
            XCTAssert(keyDataSeed1.caseInsensitiveCompare(keyDataSeed2) != .orderedSame, "keyDataSeed1 == keyDataSeed2")
            
        } catch let error {
            XCTAssert(false, "Random key failed: \(error.localizedDescription)")
        }
    }
    
    func testKeyFromSeed() {
        do {
            let keyData = try ECDSA.KeyData(seed: Data(bytes: [UInt8].init(0..<32)))
            
            let publicKeyResult = keyData.getPublicKeyData().hexadecimal()
            let expected = publicKey.hexadecimal()
            
            XCTAssert(publicKeyResult.caseInsensitiveCompare(expected) == .orderedSame, "ECDSA key from seed failed")
            
        } catch let error {
            XCTAssert(false, "From seed failed: \(error.localizedDescription)")
        }
    }
    
    func testKeyGetSeed() {
        let seed = self.keyData.getSeedData().hexadecimal()
        let expected = self.seedData.hexadecimal()
        
        XCTAssert(seed.caseInsensitiveCompare(expected) == .orderedSame, "ECDSA key get seed failed")
    }
    
    func testSign() {
        do {
            let result = try ECDSA.signED25519(
                data: self.message,
                keyData: self.keyData
                ).hexadecimal()
            
            let expected = self.signature.hexadecimal()
            
            XCTAssert(result.caseInsensitiveCompare(expected) == .orderedSame, "ECDSA.signED25519 failed")
            
        } catch let error {
            XCTAssert(false, "Sign failed: \(error.localizedDescription)")
        }
    }
    
    func testVerify() {
        let result = ECDSA.verifyED25519(
            signatureData: self.signature,
            messageData: self.message,
            publicKeyData: self.publicKey
        )
        
        XCTAssert(result, "Verify failed")
    }
}

// swiftlint:enable enable force_try
