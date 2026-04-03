import Foundation
import Security
import React

final class DPoPModule {
  static let shared = DPoPModule()

  private let keyStore = DPoPKeyStore()
  private let defaultAlias = "react-native-dpop"
  private let unknownSecureEnclaveFallbackReason = "UNKNOWN"
  private let unavailableSecureEnclaveFallbackReason = "UNAVAILABLE"

  private init() {}

  func resolveAlias(_ alias: String?) -> String {
    guard let alias, !alias.isEmpty else {
      return defaultAlias
    }
    return alias
  }

  func assertHardwareBacked(alias: String?) throws {
    let effectiveAlias = resolveAlias(alias)
    guard keyStore.hasKeyPair(alias: effectiveAlias) else {
      throw DPoPError.keyNotFound(alias: effectiveAlias)
    }

    guard keyStore.isHardwareBacked(alias: effectiveAlias) else {
      throw DPoPError.notHardwareBacked(alias: effectiveAlias)
    }
  }

  func deleteKeyPair(alias: String?) throws {
    try keyStore.deleteKeyPair(alias: resolveAlias(alias))
  }

  func getKeyInfo(alias: String?) -> [String: Any] {
    let effectiveAlias = resolveAlias(alias)
    let secureEnclaveAvailable = keyStore.isSecureEnclaveAvailable()
    let keyInfo = keyStore.getKeyInfo(alias: effectiveAlias)
    let secureEnclaveBacked = secureEnclaveAvailable && keyInfo.insideSecureHardware
    let fallbackReason = resolveSecureEnclaveFallbackReason(
      secureEnclaveAvailable: secureEnclaveAvailable,
      secureEnclaveBacked: secureEnclaveBacked,
      hasKeyPair: keyInfo.hasKeyPair,
      fallbackReason: keyStore.getSecureEnclaveFallbackReason(alias: effectiveAlias)
    )
    let secureEnclaveFallbackReason: Any = fallbackReason ?? NSNull()

    if !keyInfo.hasKeyPair {
      return [
        "alias": effectiveAlias,
        "hasKeyPair": false,
        "hardware": [
          "ios": [
            "secureEnclaveAvailable": secureEnclaveAvailable,
            "secureEnclaveBacked": false,
            "securityLevel": NSNull(),
            "securityLevelName": "SOFTWARE",
            "secureEnclaveFallbackReason": secureEnclaveFallbackReason
          ]
        ]
      ]
    }

    let securityLevel = secureEnclaveBacked ? 2 : 1
    let securityLevelName = secureEnclaveBacked ? "SECURE_ENCLAVE" : "SOFTWARE"

    return [
      "alias": keyInfo.alias,
      "algorithm": keyInfo.algorithm,
      "curve": keyInfo.curve,
      "hasKeyPair": true,
      "insideSecureHardware": secureEnclaveBacked,
      "hardware": [
        "ios": [
          "secureEnclaveAvailable": secureEnclaveAvailable,
          "secureEnclaveBacked": secureEnclaveBacked,
          "securityLevel": securityLevel,
          "securityLevelName": securityLevelName,
          "secureEnclaveFallbackReason": secureEnclaveFallbackReason
        ]
      ]
    ]
  }

  private func resolveSecureEnclaveFallbackReason(
    secureEnclaveAvailable: Bool,
    secureEnclaveBacked: Bool,
    hasKeyPair: Bool,
    fallbackReason: String?
  ) -> String? {
    if let fallbackReason {
      return fallbackReason
    }

    if hasKeyPair && !secureEnclaveAvailable {
      return unavailableSecureEnclaveFallbackReason
    }

    if hasKeyPair && !secureEnclaveBacked {
      return unknownSecureEnclaveFallbackReason
    }

    return nil
  }

  func getPublicKeyDer(alias: String?) throws -> String {
    let effectiveAlias = resolveAlias(alias)
    if !keyStore.hasKeyPair(alias: effectiveAlias) {
      try keyStore.generateKeyPair(alias: effectiveAlias)
    }
    let keyPair = try keyStore.getKeyPair(alias: effectiveAlias)
    return DPoPUtils.base64UrlEncode(try DPoPUtils.toDerPublicKey(keyPair.publicKey))
  }

  func getPublicKeyJwk(alias: String?) throws -> [String: Any] {
    let effectiveAlias = resolveAlias(alias)
    if !keyStore.hasKeyPair(alias: effectiveAlias) {
      try keyStore.generateKeyPair(alias: effectiveAlias)
    }
    let keyPair = try keyStore.getKeyPair(alias: effectiveAlias)
    let coordinates = try DPoPUtils.getPublicCoordinates(fromRawPublicKey: try DPoPUtils.toRawPublicKey(keyPair.publicKey))
    return [
      "kty": "EC",
      "crv": "P-256",
      "x": coordinates.x,
      "y": coordinates.y
    ]
  }

  func getPublicKeyRaw(alias: String?) throws -> String {
    let effectiveAlias = resolveAlias(alias)
    if !keyStore.hasKeyPair(alias: effectiveAlias) {
      try keyStore.generateKeyPair(alias: effectiveAlias)
    }
    let keyPair = try keyStore.getKeyPair(alias: effectiveAlias)
    return DPoPUtils.base64UrlEncode(try DPoPUtils.toRawPublicKey(keyPair.publicKey))
  }

  func getPublicKeyThumbprint(alias: String?) throws -> String {
    let effectiveAlias = resolveAlias(alias)
    if !keyStore.hasKeyPair(alias: effectiveAlias) {
      try keyStore.generateKeyPair(alias: effectiveAlias)
    }
    let keyPair = try keyStore.getKeyPair(alias: effectiveAlias)
    let coordinates = try DPoPUtils.getPublicCoordinates(fromRawPublicKey: try DPoPUtils.toRawPublicKey(keyPair.publicKey))
    return DPoPUtils.getPublicKeyThumbprint(kty: "EC", crv: "P-256", x: coordinates.x, y: coordinates.y)
  }

  func hasKeyPair(alias: String?) -> Bool {
    keyStore.hasKeyPair(alias: resolveAlias(alias))
  }

  func isBoundToAlias(proof: String, alias: String?) throws -> Bool {
    let effectiveAlias = resolveAlias(alias)
    if !keyStore.hasKeyPair(alias: effectiveAlias) {
      try keyStore.generateKeyPair(alias: effectiveAlias)
    }
    let keyPair = try keyStore.getKeyPair(alias: effectiveAlias)
    return try DPoPUtils.isProofBoundToPublicKey(proof, publicKey: keyPair.publicKey)
  }

  func rotateKeyPair(alias: String?) throws {
    try keyStore.generateKeyPair(alias: resolveAlias(alias))
  }

  func signWithDPoPPrivateKey(payload: String, alias: String?) throws -> String {
    let effectiveAlias = resolveAlias(alias)
    if !keyStore.hasKeyPair(alias: effectiveAlias) {
      try keyStore.generateKeyPair(alias: effectiveAlias)
    }
    let keyPair = try keyStore.getKeyPair(alias: effectiveAlias)
    var error: Unmanaged<CFError>?
    guard let derSignature = SecKeyCreateSignature(
      keyPair.privateKey,
      .ecdsaSignatureMessageX962SHA256,
      Data(payload.utf8) as CFData,
      &error
    ) as Data? else {
      throw DPoPError.securityError(error?.takeRetainedValue())
    }
    let joseSignature = try DPoPUtils.derToJose(derSignature, partLength: 32)
    return DPoPUtils.base64UrlEncode(joseSignature)
  }

  func generateProof(
    htu: String,
    htm: String,
    nonce: String?,
    accessToken: String?,
    additional: [String: Any]?,
    kid: String?,
    jti: String?,
    iat: NSNumber?,
    alias: String?
  ) throws -> [String: Any] {
    let effectiveAlias = resolveAlias(alias)
    if !keyStore.hasKeyPair(alias: effectiveAlias) {
      try keyStore.generateKeyPair(alias: effectiveAlias)
    }
    let keyPair = try keyStore.getKeyPair(alias: effectiveAlias)
    let coordinates = try DPoPUtils.getPublicCoordinates(fromRawPublicKey: try DPoPUtils.toRawPublicKey(keyPair.publicKey))

    var jwk: [String: Any] = [
      "kty": "EC",
      "crv": "P-256",
      "x": coordinates.x,
      "y": coordinates.y
    ]

    var header: [String: Any] = [
      "typ": "dpop+jwt",
      "alg": "ES256",
      "jwk": jwk
    ]

    if let kid, !kid.isEmpty {
      header["kid"] = kid
    }

    let issuedAt = iat?.int64Value ?? Int64(Date().timeIntervalSince1970)
    let finalJti = (jti?.isEmpty == false) ? jti! : UUID().uuidString

    var payload: [String: Any] = [
      "jti": finalJti,
      "htm": htm.uppercased(),
      "htu": htu,
      "iat": issuedAt
    ]

    if let nonce, !nonce.isEmpty {
      payload["nonce"] = nonce
    }

    if let accessToken, !accessToken.isEmpty {
      payload["ath"] = DPoPUtils.hashAccessToken(accessToken)
    }

    if let additional {
      for (key, value) in additional {
        payload[key] = value
      }
    }

    let headerSegment = DPoPUtils.base64UrlEncode(try DPoPUtils.jsonData(header))
    let payloadSegment = DPoPUtils.base64UrlEncode(try DPoPUtils.jsonData(payload))
    let signingInput = "\(headerSegment).\(payloadSegment)"

    var error: Unmanaged<CFError>?
    guard let derSignature = SecKeyCreateSignature(
      keyPair.privateKey,
      .ecdsaSignatureMessageX962SHA256,
      Data(signingInput.utf8) as CFData,
      &error
    ) as Data? else {
      throw DPoPError.securityError(error?.takeRetainedValue())
    }
    let joseSignature = try DPoPUtils.derToJose(derSignature, partLength: 32)
    let jwt = "\(signingInput).\(DPoPUtils.base64UrlEncode(joseSignature))"

    let proofContext: [String: Any] = [
      "htu": payload["htu"] as? String ?? htu,
      "htm": payload["htm"] as? String ?? htm.uppercased(),
      "nonce": payload["nonce"] ?? NSNull(),
      "ath": payload["ath"] ?? NSNull(),
      "kid": header["kid"] ?? NSNull(),
      "jti": payload["jti"] as? String ?? finalJti,
      "iat": Double(issuedAt),
      "additional": additional ?? NSNull()
    ]

    return [
      "proof": jwt,
      "proofContext": proofContext
    ]
  }

}

@objc extension ReactNativeDPoP {
  static func moduleName() -> String! {
    "ReactNativeDPoP"
  }

  static func requiresMainQueueSetup() -> Bool {
    false
  }

  func assertHardwareBacked(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      try DPoPModule.shared.assertHardwareBacked(alias: alias)
      resolve(nil)
    } catch {
      reject("ERR_DPOP_ASSERT_HARDWARE_BACKED", error.localizedDescription, error)
    }
  }

  func deleteKeyPair(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      try DPoPModule.shared.deleteKeyPair(alias: alias)
      resolve(nil)
    } catch {
      reject("ERR_DPOP_DELETE_KEY_PAIR", error.localizedDescription, error)
    }
  }

  func getKeyInfo(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    resolve(DPoPModule.shared.getKeyInfo(alias: alias))
  }

  func getPublicKeyDer(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(try DPoPModule.shared.getPublicKeyDer(alias: alias))
    } catch {
      reject("ERR_DPOP_PUBLIC_KEY", error.localizedDescription, error)
    }
  }

  func getPublicKeyJwk(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(try DPoPModule.shared.getPublicKeyJwk(alias: alias))
    } catch {
      reject("ERR_DPOP_PUBLIC_KEY", error.localizedDescription, error)
    }
  }

  func getPublicKeyRaw(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(try DPoPModule.shared.getPublicKeyRaw(alias: alias))
    } catch {
      reject("ERR_DPOP_PUBLIC_KEY", error.localizedDescription, error)
    }
  }

  func getPublicKeyThumbprint(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(try DPoPModule.shared.getPublicKeyThumbprint(alias: alias))
    } catch {
      reject("ERR_DPOP_CALCULATE_THUMBPRINT", error.localizedDescription, error)
    }
  }

  func hasKeyPair(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    resolve(DPoPModule.shared.hasKeyPair(alias: alias))
  }

  func isBoundToAlias(_ proof: String, alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(try DPoPModule.shared.isBoundToAlias(proof: proof, alias: alias))
    } catch {
      reject("ERR_DPOP_IS_BOUND_TO_ALIAS", error.localizedDescription, error)
    }
  }

  func rotateKeyPair(_ alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      try DPoPModule.shared.rotateKeyPair(alias: alias)
      resolve(nil)
    } catch {
      reject("ERR_DPOP_ROTATE_KEY_PAIR", error.localizedDescription, error)
    }
  }

  func signWithDPoPPrivateKey(_ payload: String, alias: String?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(try DPoPModule.shared.signWithDPoPPrivateKey(payload: payload, alias: alias))
    } catch {
      reject("ERR_DPOP_SIGN_WITH_PRIVATE_KEY", error.localizedDescription, error)
    }
  }

  func generateProof(
    _ htu: String,
    htm: String,
    nonce: String?,
    accessToken: String?,
    additional: [String: Any]?,
    kid: String?,
    jti: String?,
    iat: Any?,
    alias: String?,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    do {
      let normalizedIat: NSNumber?
      if iat is NSNull {
        normalizedIat = nil
      } else {
        normalizedIat = iat as? NSNumber
      }

      resolve(
        try DPoPModule.shared.generateProof(
          htu: htu,
          htm: htm,
          nonce: nonce,
          accessToken: accessToken,
          additional: additional,
          kid: kid,
          jti: jti,
          iat: normalizedIat,
          alias: alias
        )
      )
    } catch {
      reject("ERR_DPOP_GENERATE_PROOF", error.localizedDescription, error)
    }
  }
}
