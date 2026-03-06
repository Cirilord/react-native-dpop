package com.reactnativedpop

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Calendar
import javax.security.auth.x500.X500Principal

internal data class KeyPairReference(
  val privateKey: PrivateKey,
  val publicKey: ECPublicKey
)

internal data class KeyStoreKeyInfo(
  val alias: String,
  val algorithm: String,
  val curve: String,
  val insideSecureHardware: Boolean,
  val securityLevel: Int?,
  val strongBoxAvailable: Boolean,
  val strongBoxBacked: Boolean
)

internal class DPoPKeyStore(private val context: Context) {
  companion object {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val EC_CURVE = "secp256r1"
  }

  private val keyStore: KeyStore by lazy {
    KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
  }

  fun deleteKeyPair(alias: String) {
    if (keyStore.containsAlias(alias)) {
      keyStore.deleteEntry(alias)
    }
  }

  fun generateKeyPair(alias: String): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw IllegalStateException("Key pair generation is not supported on API < 23")
    }

    if (keyStore.containsAlias(alias)) {
      keyStore.deleteEntry(alias)
    }

    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
    if (isStrongBoxEnabled()) {
      try {
        generator.initialize(buildSpec(alias, useStrongBox = true))
        generator.generateKeyPair()
        return true
      } catch (_: StrongBoxUnavailableException) {
        // Fallback to hardware-backed keystore when StrongBox is unavailable.
      } catch (_: ProviderException) {
        // Some devices expose StrongBox but fail during generation.
      }
    }

    generator.initialize(buildSpec(alias, useStrongBox = false))
    generator.generateKeyPair()
    return false
  }

  fun getKeyPair(alias: String): KeyPairReference {
    val privateKey = keyStore.getKey(alias, null) as? PrivateKey
      ?: throw IllegalStateException("Private key not found for alias: $alias")
    val publicKey = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey
      ?: throw IllegalStateException("Key pair not found for alias: $alias")
    return KeyPairReference(privateKey = privateKey, publicKey = publicKey)
  }

  fun hasKeyPair(alias: String): Boolean {
    val privateKey = keyStore.getKey(alias, null) as? PrivateKey
    val publicKey = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey
    return privateKey != null && publicKey != null
  }

  fun getKeyInfo(alias: String): KeyStoreKeyInfo {
    val keyPair = getKeyPair(alias)
    val keyFactory = KeyFactory.getInstance(keyPair.privateKey.algorithm, KEYSTORE_PROVIDER)
    val keyInfo = keyFactory.getKeySpec(keyPair.privateKey, KeyInfo::class.java)

    return KeyStoreKeyInfo(
      alias = alias,
      algorithm = keyPair.privateKey.algorithm,
      curve = "P-256",
      insideSecureHardware = keyInfo.isInsideSecureHardware,
      securityLevel = readSecurityLevel(keyInfo),
      strongBoxAvailable = isStrongBoxEnabled(),
      strongBoxBacked = readStrongBoxBacked(keyInfo)
    )
  }

  fun isHardwareBacked(alias: String): Boolean {
    val keyPair = getKeyPair(alias)
    val keyFactory = KeyFactory.getInstance(keyPair.privateKey.algorithm, KEYSTORE_PROVIDER)
    val keyInfo = keyFactory.getKeySpec(keyPair.privateKey, KeyInfo::class.java)
    return keyInfo.isInsideSecureHardware
  }

  private fun buildSpec(alias: String, useStrongBox: Boolean): KeyGenParameterSpec {
    val principal = X500Principal("CN=$alias")
    val start = Calendar.getInstance()
    val end = Calendar.getInstance().apply { add(Calendar.YEAR, 25) }

    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setCertificateSubject(principal)
      .setCertificateNotBefore(start.time)
      .setCertificateNotAfter(end.time)
      .setUserAuthenticationRequired(false)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      builder.setUnlockedDeviceRequired(true)
      if (useStrongBox) {
        builder.setIsStrongBoxBacked(true)
      }
    }

    return builder.build()
  }

  private fun isStrongBoxEnabled(): Boolean {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
      context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
  }

  private fun readSecurityLevel(keyInfo: KeyInfo): Int? {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
      return null
    }

    return try {
      val method = KeyInfo::class.java.getMethod("getSecurityLevel")
      method.invoke(keyInfo) as? Int
    } catch (_: Exception) {
      null
    }
  }

  private fun readStrongBoxBacked(keyInfo: KeyInfo): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
      return false
    }

    return try {
      val method = KeyInfo::class.java.getMethod("isStrongBoxBacked")
      method.invoke(keyInfo) as? Boolean ?: false
    } catch (_: Exception) {
      false
    }
  }
}
