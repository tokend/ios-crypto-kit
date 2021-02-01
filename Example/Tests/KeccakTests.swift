import XCTest
import DLCryptoKit

class KeccakTests: XCTestCase {
    
    func testKeccak256OnData() {
        guard let data = "hello".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = Keccak.keccak256(data: data)
        XCTAssertEqual(digest.base64EncodedString(), "HIr/lQaFwu1LwxdPNHIoe1bZUXuclIEnMZoJp6Nt6sg=")
    }
    
    func testKeccak224() {
        
        guard let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = Keccak.keccak224(data: data)
        XCTAssertEqual(digest.hexadecimal(), "e51faa2b4655150b931ee8d700dc202f763ca5f962c529eae55012b6")
    }
    
    func testKeccak256() {
        
        guard let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = Keccak.keccak256(data: data)
        XCTAssertEqual(digest.hexadecimal(), "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371")
    }
    
    func testKeccak384() {
        
        guard let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = Keccak.keccak384(data: data)
        XCTAssertEqual(digest.hexadecimal(), "b41e8896428f1bcbb51e17abd6acc98052a3502e0d5bf7fa1af949b4d3c855e7c4dc2c390326b3f3e74c7b1e2b9a3657")
    }
    
    func testKeccak512() {
        
        guard let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".data(using: String.Encoding.utf8)
        else {
            XCTFail("Cannot init data")
            return
        }
        
        let digest : Data = Keccak.keccak512(data: data)
        XCTAssertEqual(digest.hexadecimal(), "6aa6d3669597df6d5a007b00d09c20795b5c4218234e1698a944757a488ecdc09965435d97ca32c3cfed7201ff30e070cd947f1fc12b9d9214c467d342bcba5d")
    }
}
