import Cheetah

class JWSEncoder {
    public static func encode(_ value: Encodable, signedBy secret: String, using header: JSONWebSignature.Header) throws -> JSONWebSignature {
        return try self.encode(value, signedBy: [UInt8](secret.utf8), using: header)
    }
    
    public static func encode(_ value: Encodable, signedBy secret: [UInt8], using header: JSONWebSignature.Header) throws -> JSONWebSignature {
        let object = try JSONEncoder().encode(value )
        
        return JSONWebSignature(headers: [
            header
        ], payload: object, secret: secret)
    }
}

class JWSDecoder {
    public func decode<T : Decodable>(_ type: T.Type, from object: JSONWebSignature) throws -> T {
        return try JSONDecoder().decode(type, from: object.payload)
    }
}
