import Cheetah

class JWSEncoder : Encoder {
    public func encode(_ value: Encodable, signedBy secret: [UInt8], using header: JSONWebSignature.Header) throws -> JSONWebSignature {
        let object = try JSONEncoder.encode(value)
        
        return JSONWebSignature(headers: [
            header
        ], payload: object, secret: secret)
    }
}
