import Cheetah

/// Encodes encodables into a JWT message signed with the secret and header
public class JWSEncoder {
    /// Encodes an Encodable into a JWS message signed with the secret
    ///
    /// Uses the algorithm and relevant information in the header
    ///
    /// Usage:
    /// ```swift
    /// struct AuthenticationMessage {
    ///    var token: String
    /// }
    ///
    /// let message = AuthenticationMessage(token: "donotuseastaticstring")
    ///
    /// let JWS = JWSEncoder.encode(message, signedBy: "supersecretkey", using: .hs256())
    /// ```
    public static func encode(_ value: Encodable, signedBy secret: String, using header: JSONWebSignature.Header) throws -> JSONWebSignature {
        return try self.encode(value, signedBy: [UInt8](secret.utf8), using: header)
    }
    
    /// Encodes an Encodable into a JWS message signed with the secret
    ///
    /// Uses the algorithm and relevant information in the header
    ///
    /// Usage:
    /// ```swift
    /// struct AuthenticationMessage {
    ///    var token: String
    /// }
    ///
    /// let message = AuthenticationMessage(token: "donotuseastaticstring")
    ///
    /// let JWS = JWSEncoder.encode(message, signedBy: [0x03, 0x61, 0x61, 0x82, 0x12, 0x14, 0x72, 0x41, 0x61, 0x84], using: .hs256())
    /// ```
    public static func encode(_ value: Encodable, signedBy secret: [UInt8], using header: JSONWebSignature.Header) throws -> JSONWebSignature {
        let object = try JSONEncoder().encode(value )
        
        return JSONWebSignature(headers: [
            header
        ], payload: object, secret: secret)
    }
    
    /// Encodes an Encodable into a JWS message signed with the secret
    ///
    /// Uses the algorithm and relevant information in the header
    ///
    /// Usage:
    /// ```swift
    /// struct AuthenticationMessage {
    ///    var token: String
    /// }
    ///
    /// let message = AuthenticationMessage(token: "donotuseastaticstring")
    ///
    /// let JWSEncodedString = JWSEncoder.sign(message, signedBy: "supersecretkey", using: .hs256())
    /// ```
    public static func sign(_ value: Encodable, signedBy secret: String, using header: JSONWebSignature.Header) throws -> String {
        guard let string = String(bytes: try self.encode(value, signedBy: [UInt8](secret.utf8), using: header).sign(), encoding: .utf8) else {
            throw JWTError.unsupported
        }
        
        return string
    }
    
    /// Encodes an Encodable into a JWS message signed with the secret
    ///
    /// Uses the algorithm and relevant information in the header
    ///
    /// Usage:
    /// ```swift
    /// struct AuthenticationMessage {
    ///    var token: String
    /// }
    ///
    /// let message = AuthenticationMessage(token: "donotuseastaticstring")
    ///
    /// let JWSEncodedUTF8String = JWSEncoder.sign(message, signedBy: [0x03, 0x61, 0x61, 0x82, 0x12, 0x14, 0x72, 0x41, 0x61, 0x84], using: .hs256())
    /// ```
    public static func sign(_ value: Encodable, signedBy secret: [UInt8], using header: JSONWebSignature.Header) throws -> [UInt8] {
        let object = try JSONEncoder().encode(value )
        
        return try JSONWebSignature(headers: [
            header
        ], payload: object, secret: secret).sign()
    }
}

/// Decodes a JWS
public class JWSDecoder {
    public static func decode<T : Decodable>(_ type: T.Type, from object: JSONWebSignature) throws -> T {
        return try JSONDecoder().decode(type, from: object.payload)
    }
    
    public static func decode<T : Decodable>(_ type: T.Type, from string: String, verifying secret: String) throws -> T {
        return try self.decode(type, from: [UInt8](string.utf8), verifying: [UInt8](secret.utf8))
    }
    
    public static func decode<T : Decodable>(_ type: T.Type, from string: String, verifying secret: [UInt8]) throws -> T {
        return try self.decode(type, from: [UInt8](string.utf8), verifying: secret)
    }
    
    public static func decode<T : Decodable>(_ type: T.Type, from bytes: [UInt8], verifying secret: [UInt8]) throws -> T {
        let object = try JSONWebSignature(from: bytes, verifyingWith: secret)
        
        return try JSONDecoder().decode(type, from: object.payload)
    }
}
