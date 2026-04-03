import Foundation
import CryptoKit
import Security

enum DPoPUtils {
  static func base64UrlEncode(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func base64UrlDecode(_ value: String) -> Data? {
    let remainder = value.count % 4
    let padded = remainder == 0 ? value : value + String(repeating: "=", count: 4 - remainder)
    let base64 = padded
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    return Data(base64Encoded: base64)
  }

  static func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
  }

  static func hashAccessToken(_ accessToken: String) -> String {
    let data = Data(accessToken.utf8)
    return base64UrlEncode(sha256(data))
  }

  static func jsonData(_ object: Any) throws -> Data {
    if #available(iOS 11.0, *) {
      return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
    return try JSONSerialization.data(withJSONObject: object, options: [])
  }

  static func derToJose(_ derSignature: Data, partLength: Int = 32) throws -> Data {
    let bytes = [UInt8](derSignature)
    guard !bytes.isEmpty, bytes[0] == 0x30 else {
      throw DPoPError.invalidDerSignature
    }

    var index = 1
    let (_, seqLengthBytes) = try readDerLength(bytes, startIndex: index)
    index += seqLengthBytes

    guard index < bytes.count, bytes[index] == 0x02 else {
      throw DPoPError.invalidDerSignature
    }

    index += 1
    let (rLength, rLengthBytes) = try readDerLength(bytes, startIndex: index)
    index += rLengthBytes
    let rEnd = index + rLength
    guard rEnd <= bytes.count else {
      throw DPoPError.invalidDerSignature
    }
    let r = Data(bytes[index..<rEnd])
    index = rEnd

    guard index < bytes.count, bytes[index] == 0x02 else {
      throw DPoPError.invalidDerSignature
    }

    index += 1
    let (sLength, sLengthBytes) = try readDerLength(bytes, startIndex: index)
    index += sLengthBytes
    let sEnd = index + sLength
    guard sEnd <= bytes.count else {
      throw DPoPError.invalidDerSignature
    }
    let s = Data(bytes[index..<sEnd])

    let rFixed = try toUnsignedFixedLength(r, length: partLength)
    let sFixed = try toUnsignedFixedLength(s, length: partLength)
    return rFixed + sFixed
  }

  static func getPublicCoordinates(fromRawPublicKey raw: Data) throws -> (x: String, y: String) {
    guard raw.count == 65, raw.first == 0x04 else {
      throw DPoPError.invalidPublicKey
    }

    let x = raw.subdata(in: 1..<33)
    let y = raw.subdata(in: 33..<65)
    return (base64UrlEncode(x), base64UrlEncode(y))
  }

  static func getPublicKeyThumbprint(kty: String, crv: String, x: String, y: String) -> String {
    let canonical = "{\"crv\":\"\(crv)\",\"kty\":\"\(kty)\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
    return base64UrlEncode(sha256(Data(canonical.utf8)))
  }

  static func toRawPublicKey(_ publicKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      throw DPoPError.securityError(error?.takeRetainedValue())
    }

    guard publicKeyData.count == 65, publicKeyData.first == 0x04 else {
      throw DPoPError.invalidPublicKey
    }

    return publicKeyData
  }

  static func toDerPublicKey(_ publicKey: SecKey) throws -> Data {
    let raw = try toRawPublicKey(publicKey)
    let cryptoKey = try P256.Signing.PublicKey(x963Representation: raw)
    return cryptoKey.derRepresentation
  }

  static func isProofBoundToPublicKey(_ proof: String, publicKey: SecKey) throws -> Bool {
    let parts = proof.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3 else {
      throw DPoPError.invalidProofFormat
    }

    guard let headerData = base64UrlDecode(String(parts[0])) else {
      throw DPoPError.invalidProofFormat
    }

    let json = try JSONSerialization.jsonObject(with: headerData, options: [])
    guard let header = json as? [String: Any],
          let jwk = header["jwk"] as? [String: Any],
          let kty = jwk["kty"] as? String,
          let crv = jwk["crv"] as? String,
          let x = jwk["x"] as? String,
          let y = jwk["y"] as? String else {
      throw DPoPError.invalidProofFormat
    }

    let coordinates = try getPublicCoordinates(fromRawPublicKey: try toRawPublicKey(publicKey))
    return kty == "EC" && crv == "P-256" && x == coordinates.x && y == coordinates.y
  }

  private static func readDerLength(_ input: [UInt8], startIndex: Int) throws -> (Int, Int) {
    guard startIndex < input.count else {
      throw DPoPError.invalidDerSignature
    }

    let first = Int(input[startIndex])
    if (first & 0x80) == 0 {
      return (first, 1)
    }

    let lengthBytesCount = first & 0x7F
    guard lengthBytesCount > 0, lengthBytesCount <= 4, startIndex + lengthBytesCount < input.count else {
      throw DPoPError.invalidDerSignature
    }

    var length = 0
    for index in 0..<lengthBytesCount {
      length = (length << 8) | Int(input[startIndex + 1 + index])
    }

    return (length, 1 + lengthBytesCount)
  }

  private static func toUnsignedFixedLength(_ value: Data, length: Int) throws -> Data {
    let bytes = [UInt8](value)
    if bytes.count == length {
      return value
    }

    if bytes.count == length + 1, bytes.first == 0x00 {
      return Data(bytes.dropFirst())
    }

    if bytes.count < length {
      return Data(repeating: 0, count: length - bytes.count) + value
    }

    throw DPoPError.invalidDerSignature
  }
}

enum DPoPError: LocalizedError {
  case invalidDerSignature
  case invalidPublicKey
  case invalidProofFormat
  case keyNotFound(alias: String)
  case notHardwareBacked(alias: String)
  case securityError(CFError?)

  var errorDescription: String? {
    switch self {
    case .invalidDerSignature:
      return "Invalid DER signature format"
    case .invalidPublicKey:
      return "Invalid P-256 public key"
    case .invalidProofFormat:
      return "Invalid DPoP proof format"
    case .keyNotFound(let alias):
      return "Key pair not found for alias: \(alias)"
    case .notHardwareBacked(let alias):
      return "Key pair is not hardware-backed for alias: \(alias)"
    case .securityError(let error):
      return (error as Error?)?.localizedDescription ?? "Security framework error"
    }
  }
}
