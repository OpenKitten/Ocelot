import CryptoSwift
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

public struct JSONWebSignature {
    struct JSONWebKey {
        
    }

    public struct Header {
        public enum Algorithm : String {
            // HMAC SHA256
            case HS256
            case HS384
            case HS512

            case none

            internal func sign(_ data: [UInt8], with secret: [UInt8]) throws -> [UInt8] {
                switch self {
                case .HS256:
                    return try HMAC(key: secret, variant: .sha256).authenticate(data)
                case .HS384:
                    return try HMAC(key: secret, variant: .sha384).authenticate(data)
                case .HS512:
                    return try HMAC(key: secret, variant: .sha512).authenticate(data)
                case .none:
                    return data
                }
            }
        }
        
        public var alg: Algorithm
        public var signatureType: String?
        public var payloadType: String?

        var jsonWebKeySetURL: String?
        var jsonWebKey: JSONWebKey?
        var keyID: String?
        
        var criticalFields = [String]()
        var additionalFields: JSONObject
        
        public init(verifiedBy algorithm: Algorithm) {
            self.alg = algorithm
            self.additionalFields = JSONObject()
        }

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

    public var headers: [Header]
    public var payload: JSONObject
    private var secret: [UInt8]

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
    
    public init(headers: [Header], payload: JSONObject, secret: [UInt8]) {
        self.headers = headers
        self.payload = payload
        self.secret = secret
    }
    
    public init(from string: String, verifyingWith secret: [UInt8]) throws {
        try self.init(from: [UInt8](string.utf8), verifyingWith: secret)
    }

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
    public static func hs256() -> JSONWebSignature.Header {
        return JSONWebSignature.Header(verifiedBy: .HS256)
    }
    
    public static func hs384() -> JSONWebSignature.Header {
        return JSONWebSignature.Header(verifiedBy: .HS384)
    }
    
    public static func hs512() -> JSONWebSignature.Header {
        return JSONWebSignature.Header(verifiedBy: .HS512)
    }
}
