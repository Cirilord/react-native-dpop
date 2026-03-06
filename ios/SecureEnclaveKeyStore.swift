import Foundation
import Security

final class SecureEnclaveKeyStore {
  private let service = "com.dpop.secureenclave"

  func generateKeyPair(alias: String) throws {
    try deleteKeyPair(alias: alias)

    let tag = keyTag(alias: alias)
    var error: Unmanaged<CFError>?

    guard let access = SecAccessControlCreateWithFlags(
      nil,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage,
      &error
    ) else {
      throw DPoPError.securityError(error?.takeRetainedValue())
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrLabel as String: service,
        kSecAttrAccessControl as String: access
      ]
    ]

    guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
      throw DPoPError.securityError(error?.takeRetainedValue())
    }
  }

  func deleteKeyPair(alias: String) throws {
    let tag = keyTag(alias: alias)

    let privateQuery: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
    ]

    let status = SecItemDelete(privateQuery as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
  }

  func getPrivateKey(alias: String) throws -> SecKey {
    let tag = keyTag(alias: alias)
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecReturnRef as String: true
    ]

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let key = result as! SecKey? else {
      throw DPoPError.keyNotFound(alias: alias)
    }
    return key
  }

  func getPublicKey(alias: String) throws -> SecKey {
    let privateKey = try getPrivateKey(alias: alias)
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw DPoPError.keyNotFound(alias: alias)
    }
    return publicKey
  }

  func hasKeyPair(alias: String) -> Bool {
    do {
      _ = try getPrivateKey(alias: alias)
      _ = try getPublicKey(alias: alias)
      return true
    } catch {
      return false
    }
  }

  func isHardwareBacked(alias: String) -> Bool {
    guard let attrs = try? attributes(alias: alias) else {
      return false
    }

    return (attrs[kSecAttrTokenID as String] as? String) == (kSecAttrTokenIDSecureEnclave as String)
  }

  private func attributes(alias: String) throws -> [String: Any] {
    let privateKey = try getPrivateKey(alias: alias)
    guard let attrs = SecKeyCopyAttributes(privateKey) as? [String: Any] else {
      return [:]
    }
    return attrs
  }

  private func keyTag(alias: String) -> Data {
    Data("\(service).\(alias)".utf8)
  }
}
