import Cheetah
import XCTest
@testable import JWT

class JWTTests: XCTestCase {
    func testExample() throws {
        let json: JSONObject = [
            "awesome": true
        ]
        
        let secret = [UInt8]("kaaaaaaas".utf8)
        
        let signed = try JSONWebSignature(headers: [JSONWebSignature.Header(verifiedBy: .HS256) ], payload: json, secret: secret).sign()
        
        print(String(bytes: signed, encoding: .utf8))
        
        let signature = try JSONWebSignature(from: signed, verifyingWith: secret)
        XCTAssertEqual(json, signature.payload)
    }


    static var allTests: [(String, (JWTTests) -> () throws -> Void)] = [
        ("testExample", testExample),
    ]
}
