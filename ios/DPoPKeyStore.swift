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
  let strongBoxAvailable: Bool
  let strongBoxBacked: Bool
}

final class DPoPKeyStore {
  private let secureEnclave = SecureEnclaveKeyStore()
  private let keychain = KeychainKeyStore()

  func generateKeyPair(alias: String) throws {
    try deleteKeyPair(alias: alias)

    do {
      try secureEnclave.generateKeyPair(alias: alias)
    } catch {
      try keychain.generateKeyPair(alias: alias)
    }
  }

  func deleteKeyPair(alias: String) throws {
    try secureEnclave.deleteKeyPair(alias: alias)
    try keychain.deleteKeyPair(alias: alias)
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
        insideSecureHardware: true,
        strongBoxAvailable: false,
        strongBoxBacked: false
      )
    }

    if keychain.hasKeyPair(alias: alias) {
      return DPoPKeyInfo(
        alias: alias,
        algorithm: "EC",
        curve: "P-256",
        hasKeyPair: true,
        insideSecureHardware: false,
        strongBoxAvailable: false,
        strongBoxBacked: false
      )
    }

    return DPoPKeyInfo(
      alias: alias,
      algorithm: "EC",
      curve: "P-256",
      hasKeyPair: false,
      insideSecureHardware: false,
      strongBoxAvailable: false,
      strongBoxBacked: false
    )
  }

  func isHardwareBacked(alias: String) -> Bool {
    secureEnclave.isHardwareBacked(alias: alias)
  }
}
