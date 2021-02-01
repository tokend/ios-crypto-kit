import XCTest
import DLCryptoKit

class SHA3Tests: XCTestCase {
    
    func testSha3_224() {
        
        guard let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = SHA3.sha224(data: data)
        XCTAssertEqual(digest.hexadecimal(), "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33")
    }
    
    func testSha3_256() {
        
        guard let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = SHA3.sha256(data: data)
        XCTAssertEqual(digest.hexadecimal(), "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")
    }
    
    func testSha3_384() {
        
        guard let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = SHA3.sha384(data: data)
        XCTAssertEqual(digest.hexadecimal(), "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22")
    }
    
    func testSha3_512() {
        
        guard let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = SHA3.sha512(data: data)
        XCTAssertEqual(digest.hexadecimal(), "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e")
    }
}
