import XCTest
import DLCryptoKit

class CommonTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSHA1() {
        guard
            let testString1 = "Test string".data(using: .utf8),
            let testString2 = "Test string other".data(using: .utf8)
            else {
                print("test strings encode failed")
                return
        }
        
        let expectedHash1 = "18AF819125B70879D36378431C4E8D9BFA6A2599"
        let expectedHash2 = "C046DCB785C75613DB685C144EE1813C71321C62"
        
        let hash1 = Common.SHA.sha1(data: testString1).hexadecimal()
        let hash2 = Common.SHA.sha1(data: testString2).hexadecimal()
        
        XCTAssert(hash1.caseInsensitiveCompare(expectedHash1) == .orderedSame, "SHA1 failed 1")
        XCTAssert(hash2.caseInsensitiveCompare(expectedHash2) == .orderedSame, "SHA1 failed 2")
    }
    
    func testSHA256() {
        guard
            let testString1 = "Test string".data(using: .utf8),
            let testString2 = "Test string other".data(using: .utf8)
            else {
                print("test strings encode failed")
                return
        }
        
        let expectedHash1 = "A3E49D843DF13C2E2A7786F6ECD7E0D184F45D718D1AC1A8A63E570466E489DD"
        let expectedHash2 = "70E9C4D76323EAB94D7F2CC3F1AF5B348CBAB0427E0503DF6C6E7EB3C7EA3758"
        
        let hash1 = Common.SHA.sha256(data: testString1).hexadecimal()
        let hash2 = Common.SHA.sha256(data: testString2).hexadecimal()
        
        XCTAssert(hash1.caseInsensitiveCompare(expectedHash1) == .orderedSame, "SHA256 failed 1")
        XCTAssert(hash2.caseInsensitiveCompare(expectedHash2) == .orderedSame, "SHA256 failed 2")
    }
    
    func testRandom() {
        let random1 = Common.Random.generateRandom(length: 16)
        let random2 = Common.Random.generateRandom(length: 16)
        let random3 = Common.Random.generateRandom(length: 32)
        
        XCTAssert(random1.count == random2.count, "random1.count != random2.count")
        XCTAssert(random1.count != random3.count, "random1.count == random2.count")
        XCTAssert(random1 != random2 && random2 != random3 && random3 != random1, "Received same random result")
    }
}
