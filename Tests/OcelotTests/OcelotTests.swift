import Cheetah
import XCTest
@testable import Ocelot

class OcelotTests: XCTestCase {
    func testExample() throws {
        let json: JSONObject = [
            "awesome": true
        ]
        
        let secret = [UInt8]("kaaaaaaas".utf8)
        
        let signed = try JSONWebSignature(headers: [JSONWebSignature.Header(verifiedBy: .HS256) ], payload: json, secret: secret).sign()
        
        let signature = try JSONWebSignature(from: signed, verifyingWith: secret)
        XCTAssertEqual(json, signature.payload)
        
        let message = AuthenticationMessage(token: "donotuseastaticstring")
        
        let jws = try JWSEncoder.sign(message, signedBy: secret, using: .hs256())
        
        let messageCopy = try JWSDecoder.decode(AuthenticationMessage.self, from: jws, verifying: secret)
        
        XCTAssertEqual(message.token, messageCopy.token)
    }

    static var allTests: [(String, (OcelotTests) -> () throws -> Void)] = [
        ("testExample", testExample),
    ]
}

struct AuthenticationMessage : Codable {
    var token: String
}
