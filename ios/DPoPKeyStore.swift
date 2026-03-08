import Foundation
import Security

struct DPoPKeyPairReference {
  let privateKey: SecKey
  let publicKey: SecKey
}

struct DPoPKeyInfo {
  let alias: String
  let algorithm: String
  let curve: String
  let hasKeyPair: Bool
  let insideSecureHardware: Bool
}

final class DPoPKeyStore {
  private let secureEnclave = SecureEnclaveKeyStore()
  private let keychain = KeychainKeyStore()
  private let fallbackReasonDefaults = UserDefaults.standard
  private let fallbackReasonPrefix = "react_native_dpop_secure_enclave_fallback_reason_"
  private lazy var secureEnclaveAvailable = secureEnclave.isAvailable()

  func generateKeyPair(alias: String) throws {
    try deleteKeyPair(alias: alias)

    do {
      try secureEnclave.generateKeyPair(alias: alias)
      clearSecureEnclaveFallbackReason(alias: alias)
    } catch {
      storeSecureEnclaveFallbackReason(alias: alias, reason: mapSecureEnclaveFallbackReason(error))
      try keychain.generateKeyPair(alias: alias)
    }
  }

  func deleteKeyPair(alias: String) throws {
    try secureEnclave.deleteKeyPair(alias: alias)
    try keychain.deleteKeyPair(alias: alias)
    clearSecureEnclaveFallbackReason(alias: alias)
  }

  func hasKeyPair(alias: String) -> Bool {
    secureEnclave.hasKeyPair(alias: alias) || keychain.hasKeyPair(alias: alias)
  }

  func getKeyPair(alias: String) throws -> DPoPKeyPairReference {
    if secureEnclave.hasKeyPair(alias: alias) {
      return DPoPKeyPairReference(
        privateKey: try secureEnclave.getPrivateKey(alias: alias),
        publicKey: try secureEnclave.getPublicKey(alias: alias)
      )
    }

    if keychain.hasKeyPair(alias: alias) {
      return DPoPKeyPairReference(
        privateKey: try keychain.getPrivateKey(alias: alias),
        publicKey: try keychain.getPublicKey(alias: alias)
      )
    }

    throw DPoPError.keyNotFound(alias: alias)
  }

  func getKeyInfo(alias: String) -> DPoPKeyInfo {
    if secureEnclave.hasKeyPair(alias: alias) {
      return DPoPKeyInfo(
        alias: alias,
        algorithm: "EC",
        curve: "P-256",
        hasKeyPair: true,
        insideSecureHardware: true
      )
    }

    if keychain.hasKeyPair(alias: alias) {
      return DPoPKeyInfo(
        alias: alias,
        algorithm: "EC",
        curve: "P-256",
        hasKeyPair: true,
        insideSecureHardware: false
      )
    }

    return DPoPKeyInfo(
      alias: alias,
      algorithm: "EC",
      curve: "P-256",
      hasKeyPair: false,
      insideSecureHardware: false
    )
  }

  func isHardwareBacked(alias: String) -> Bool {
    secureEnclave.isHardwareBacked(alias: alias)
  }

  func isSecureEnclaveAvailable() -> Bool {
    secureEnclaveAvailable
  }

  func getSecureEnclaveFallbackReason(alias: String) -> String? {
    fallbackReasonDefaults.string(forKey: fallbackReasonKey(alias: alias))
  }

  private func storeSecureEnclaveFallbackReason(alias: String, reason: String) {
    fallbackReasonDefaults.set(reason, forKey: fallbackReasonKey(alias: alias))
  }

  private func clearSecureEnclaveFallbackReason(alias: String) {
    fallbackReasonDefaults.removeObject(forKey: fallbackReasonKey(alias: alias))
  }

  private func fallbackReasonKey(alias: String) -> String {
    "\(fallbackReasonPrefix)\(alias)"
  }

  private func mapSecureEnclaveFallbackReason(_ error: Error) -> String {
    let nsError = error as NSError

    if nsError.domain == NSOSStatusErrorDomain {
      switch nsError.code {
      case Int(errSecNotAvailable), Int(errSecUnimplemented):
        return "UNAVAILABLE"
      case Int(errSecAuthFailed), Int(errSecInteractionNotAllowed), Int(errSecUserCanceled):
        return "POLICY_REJECTED"
      default:
        return "PROVIDER_ERROR"
      }
    }

    return "UNKNOWN"
  }
}
