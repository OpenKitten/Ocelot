import CryptoKitten
import Cheetah
import Foundation

fileprivate let jwsFields = ["typ", "cty", "alg", "jku", "jwk", "kid"]

/// Errors related to JWT
enum JWTError : Error {
    /// Happens when deserialization isn't possible according to spec
    case invalidJWS
    
    /// If the JOSE header is invalid
    ///
    /// Primarily when the critical fields array contains invalid fields
    case invalidJOSE
    
    /// If the signature validation reported an incorrect signature
    case invalidSignature
    
    /// An unsupported feature
    case unsupported
}

/// JSON Web Signature (signature based JSON Web Token)
public struct JSONWebSignature {
    /// The header of a JSON Web Signature
    public struct Header {
        /// The algorithm to use for signing
        public enum Algorithm : String {
            /// HMAC SHA256
            case HS256
            
            /// HMAC SHA384
            case HS384
            
            /// HMAC SHA512
            case HS512
            
            internal func sign(_ data: [UInt8], with secret: [UInt8]) throws -> [UInt8] {
                switch self {
                case .HS256:
                    return HMAC<SHA256>.authenticate(message: data, withKey: secret)
                case .HS384:
                    return HMAC<SHA384>.authenticate(message: data, withKey: secret)
                case .HS512:
                    return HMAC<SHA512>.authenticate(message: data, withKey: secret)
                }
            }
        }
        
        /// The hashing algorithm used for verification
        public var alg: Algorithm
        
        /// Defines what kind of message described by this header
        public var signatureType: String?
        
        /// The type of payload described by this header
        public var payloadType: String?

        var jsonWebKeySetURL: String?
//        var jsonWebKey: JSONWebKey?
        var keyID: String?
        
        /// All fields that *must* be contained and recognized in this header
        var criticalFields = [String]()
        
        /// Additional fields
        var additionalFields: JSONObject
        
        /// Creates a basic header that signs using the provided algorithm
        public init(verifiedBy algorithm: Algorithm) {
            self.alg = algorithm
            self.additionalFields = JSONObject()
        }
        
        /// Deserializes a header from a JSONObject
        public init(_ object: JSONObject) throws {
            var object = object

            guard let algName = String(object["alg"]), let alg = Algorithm(rawValue: algName) else {
                throw JWTError.invalidJOSE
            }

            self.alg = alg
            self.signatureType = String(object["typ"])
            self.payloadType = String(object["cty"])

            if let array = JSONArray(object["crit"]) {
                for value in array {
                    guard let value = String(value) else {
                        throw JWTError.invalidJOSE
                    }

                    guard jwsFields.contains(value) else {
                        throw JWTError.invalidJOSE
                    }

                    criticalFields.append(value)
                }
            }
            // TODO: Check `crit`?

            object.removeValue(forKey: "typ")
            object.removeValue(forKey: "cty")
            object.removeValue(forKey: "crit")
            object.removeValue(forKey: "alg")

            self.additionalFields = object
        }

        public func serializeProtectedHeader() -> JSONObject {
            return [
                "alg": alg.rawValue,
                "typ": signatureType,
                "cty": payloadType,
                "crit": criticalFields.count > 0 ? criticalFields : nil
            ]
        }
    }
    
    /// The headers linked to this message
    ///
    /// A Web Token can be signed by multiple headers
    ///
    /// Currently we don't support anything other than 1 header
    public var headers: [Header]
    
    /// The JSON payload within this message
    public var payload: JSONObject
    
    /// The secret that is used by all authorized parties to sign messages
    private var secret: [UInt8]
    
    /// Signs the message and returns the UTF8 encoded String of this message
    public func signedString(_ header: Header? = nil) throws -> String {
        let signed = try sign(header)
        
        guard let string = String(bytes: signed, encoding: .utf8) else {
            throw JWTError.unsupported
        }
        
        return string
    }
    
    /// Signs the message and returns the UTF8 of this message
    ///
    /// Can be transformed into a String like so:
    ///
    /// ```swift
    /// let signed = try jws.sign()
    /// let signedString = String(bytes: signed, encoding: .utf8)
    /// ```
    public func sign(_ header: Header? = nil) throws -> [UInt8] {
        let usedHeader: Header
        
        if let header = header {
            usedHeader = header
        } else {
            guard let header = headers.first else {
                throw JWTError.unsupported
            }
            
            usedHeader = header
        }
        
        let headerData = usedHeader.serializeProtectedHeader().serialize()
        let encodedHeader = [UInt8](Base64.encode(headerData).utf8)
        let encodedPayload =  [UInt8](Base64.encode(payload.serialize()).utf8)
        
        return encodedHeader + [0x2e] + encodedPayload + [0x2e] + [UInt8](Base64.encode(try usedHeader.alg.sign(encodedHeader + [0x2e] + encodedPayload, with: secret)).utf8)
    }
    
    /// Creates a new JSON Web Signature from predefined data
    public init(headers: [Header], payload: JSONObject, secret: [UInt8]) {
        self.headers = headers
        self.payload = payload
        self.secret = secret
    }
    
    /// Parses a JWT String into a JSON Web Signature
    ///
    /// Verifies using the provided secret
    ///
    /// - throws: When the signature is invalid or the JWT is invalid
    public init(from string: String, verifyingWith secret: [UInt8]) throws {
        try self.init(from: [UInt8](string.utf8), verifyingWith: secret)
    }
    
    /// Parses a JWT UTF8 String into a JSON Web Signature
    ///
    /// Verifies using the provided secret
    ///
    /// - throws: When the signature is invalid or the JWT is invalid
    public init(from string: [UInt8], verifyingWith secret: [UInt8]) throws {
        let parts = string.split(separator: 0x2e)

        self.secret = secret

        switch parts.count {
        case 3:
            let jsonString = try Base64.decode(Array(parts[0]))
            let payloadString = try Base64.decode(Array(parts[1]))
            
            let headerObject = try JSONObject(from: jsonString)
            let payloadObject = try JSONObject(from: payloadString)
            
            let header = try Header(headerObject)
            
            self.headers = []
            self.payload = payloadObject

            guard try sign(header) == string else {
                throw JWTError.invalidSignature
            }
        default:
            throw JWTError.invalidJWS
        }
    }
}

extension JSONWebSignature.Header {
    /// Creates a simple HMAC SHA256 header
    public static func hs256() -> JSONWebSignature.Header {
        return JSONWebSignature.Header(verifiedBy: .HS256)
    }
    
    /// Creates a simple HMAC SHA384 header
    public static func hs384() -> JSONWebSignature.Header {
        return JSONWebSignature.Header(verifiedBy: .HS384)
    }
    
    /// Creates a simple HMAC SHA512 header
    public static func hs512() -> JSONWebSignature.Header {
        return JSONWebSignature.Header(verifiedBy: .HS512)
    }
}
