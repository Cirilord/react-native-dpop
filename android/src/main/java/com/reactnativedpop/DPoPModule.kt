package com.reactnativedpop

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReactApplicationContext
import java.security.Signature
import java.util.UUID
import org.json.JSONObject

class DPoPModule(reactContext: ReactApplicationContext) :
  NativeReactNativeDPoPSpec(reactContext) {
  private val keyStore = DPoPKeyStore(reactContext)

  companion object {
    private const val DEFAULT_ALIAS = "react-native-dpop"
    const val NAME = NativeReactNativeDPoPSpec.NAME
    private const val UNKNOWN_STRONGBOX_FALLBACK_REASON = "UNKNOWN"
  }

  private fun resolveAlias(alias: String?): String {
    return alias ?: DEFAULT_ALIAS
  }

  private fun resolveStrongBoxFallbackReason(
    strongBoxAvailable: Boolean,
    strongBoxBacked: Boolean,
    fallbackReason: String?
  ): String? {
    if (fallbackReason != null) {
      return fallbackReason
    }

    return if (strongBoxAvailable && !strongBoxBacked) {
      UNKNOWN_STRONGBOX_FALLBACK_REASON
    } else {
      null
    }
  }

  override fun assertHardwareBacked(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        promise.reject("ERR_DPOP_ASSERT_HARDWARE_BACKED", "Key pair not found for alias: $effectiveAlias")
        return
      }

      if (!keyStore.isHardwareBacked(effectiveAlias)) {
        promise.reject("ERR_DPOP_ASSERT_HARDWARE_BACKED", "Key pair is not hardware-backed for alias: $effectiveAlias")
        return
      }

      promise.resolve(null)
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_ASSERT_HARDWARE_BACKED", e.message, e)
    }
  }

  override fun calculateThumbprint(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        keyStore.generateKeyPair(effectiveAlias)
      }

      val keyPair = keyStore.getKeyPair(effectiveAlias)
      val coordinates = DPoPUtils.getPublicCoordinates(keyPair.publicKey)
      val thumbprint = DPoPUtils.calculateThumbprint(
        kty = "EC",
        crv = "P-256",
        x = coordinates.first,
        y = coordinates.second
      )
      promise.resolve(thumbprint)
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_CALCULATE_THUMBPRINT", e.message, e)
    }
  }

  override fun deleteKeyPair(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      keyStore.deleteKeyPair(effectiveAlias)
      promise.resolve(null)
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_DELETE_KEY_PAIR", e.message, e)
    }
  }

  override fun getKeyInfo(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        val strongBoxAvailable = keyStore.isStrongBoxAvailable()
        val fallbackReason = resolveStrongBoxFallbackReason(
          strongBoxAvailable = strongBoxAvailable,
          strongBoxBacked = false,
          fallbackReason = keyStore.getStrongBoxFallbackReason(effectiveAlias)
        )
        val hardwareAndroid = Arguments.createMap().apply {
          putBoolean("strongBoxAvailable", strongBoxAvailable)
          putBoolean("strongBoxBacked", false)
          if (fallbackReason != null) {
            putString("strongBoxFallbackReason", fallbackReason)
          } else {
            putNull("strongBoxFallbackReason")
          }
        }
        val hardware = Arguments.createMap().apply {
          putMap("android", hardwareAndroid)
        }
        val result = Arguments.createMap().apply {
          putString("alias", effectiveAlias)
          putBoolean("hasKeyPair", false)
          putMap("hardware", hardware)
        }
        promise.resolve(result)
        return
      }

      val keyInfo = keyStore.getKeyInfo(effectiveAlias)
      val fallbackReason = resolveStrongBoxFallbackReason(
        strongBoxAvailable = keyInfo.strongBoxAvailable,
        strongBoxBacked = keyInfo.strongBoxBacked,
        fallbackReason = keyStore.getStrongBoxFallbackReason(effectiveAlias)
      )
      val hardwareAndroid = Arguments.createMap().apply {
        putBoolean("strongBoxAvailable", keyInfo.strongBoxAvailable)
        putBoolean("strongBoxBacked", keyInfo.strongBoxBacked)
        if (keyInfo.securityLevel != null) {
          putInt("securityLevel", keyInfo.securityLevel)
        }
        putString("securityLevelName", keyInfo.securityLevelName)
        if (fallbackReason != null) {
          putString("strongBoxFallbackReason", fallbackReason)
        } else {
          putNull("strongBoxFallbackReason")
        }
      }
      val hardware = Arguments.createMap().apply {
        putMap("android", hardwareAndroid)
      }
      val result = Arguments.createMap().apply {
        putString("alias", keyInfo.alias)
        putString("algorithm", keyInfo.algorithm)
        putString("curve", keyInfo.curve)
        putBoolean("hasKeyPair", true)
        putBoolean("insideSecureHardware", keyInfo.insideSecureHardware)
        putMap("hardware", hardware)
      }
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_GET_KEY_INFO", e.message, e)
    }
  }

  override fun getPublicKeyDer(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        keyStore.generateKeyPair(effectiveAlias)
      }

      val keyPair = keyStore.getKeyPair(effectiveAlias)
      promise.resolve(DPoPUtils.base64UrlEncode(keyPair.publicKey.encoded))
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_PUBLIC_KEY", e.message, e)
    }
  }

  override fun getPublicKeyJwk(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        keyStore.generateKeyPair(effectiveAlias)
      }

      val keyPair = keyStore.getKeyPair(effectiveAlias)
      val coordinates = DPoPUtils.getPublicCoordinates(keyPair.publicKey)
      val jwk = Arguments.createMap().apply {
        putString("kty", "EC")
        putString("crv", "P-256")
        putString("x", coordinates.first)
        putString("y", coordinates.second)
      }
      promise.resolve(jwk)
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_PUBLIC_KEY", e.message, e)
    }
  }

  override fun getPublicKeyRaw(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        keyStore.generateKeyPair(effectiveAlias)
      }

      val keyPair = keyStore.getKeyPair(effectiveAlias)
      val raw = DPoPUtils.toRawPublicKey(keyPair.publicKey)
      promise.resolve(DPoPUtils.base64UrlEncode(raw))
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_PUBLIC_KEY", e.message, e)
    }
  }

  override fun hasKeyPair(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      promise.resolve(keyStore.hasKeyPair(effectiveAlias))
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_HAS_KEY_PAIR", e.message, e)
    }
  }

  override fun isBoundToAlias(proof: String, alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        keyStore.generateKeyPair(effectiveAlias)
      }

      val keyPair = keyStore.getKeyPair(effectiveAlias)
      promise.resolve(DPoPUtils.isProofBoundToPublicKey(proof, keyPair.publicKey))
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_IS_BOUND_TO_ALIAS", e.message, e)
    }
  }

  override fun rotateKeyPair(alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      keyStore.generateKeyPair(effectiveAlias)
      promise.resolve(null)
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_ROTATE_KEY_PAIR", e.message, e)
    }
  }

  override fun signWithDPoPPrivateKey(payload: String, alias: String?, promise: Promise) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        keyStore.generateKeyPair(effectiveAlias)
      }

      val keyPair = keyStore.getKeyPair(effectiveAlias)
      val signature = Signature.getInstance("SHA256withECDSA").apply {
        initSign(keyPair.privateKey)
        update(payload.toByteArray(Charsets.UTF_8))
      }
      val joseSignature = DPoPUtils.derToJose(signature.sign(), partLength = 32)
      promise.resolve(DPoPUtils.base64UrlEncode(joseSignature))
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_SIGN_WITH_PRIVATE_KEY", e.message, e)
    }
  }

  override fun generateProof(
    htu: String,
    htm: String,
    nonce: String?,
    accessToken: String?,
    additional: ReadableMap?,
    kid: String?,
    jti: String?,
    iat: Double?,
    alias: String?,
    promise: Promise
  ) {
    try {
      val effectiveAlias = resolveAlias(alias)
      if (!keyStore.hasKeyPair(effectiveAlias)) {
        keyStore.generateKeyPair(effectiveAlias)
      }

      val keyPair = keyStore.getKeyPair(effectiveAlias)
      val coordinates = DPoPUtils.getPublicCoordinates(keyPair.publicKey)
      val jwk = JSONObject().apply {
        put("kty", "EC")
        put("crv", "P-256")
        put("x", coordinates.first)
        put("y", coordinates.second)
      }

      val header = JSONObject().apply {
        put("typ", "dpop+jwt")
        put("alg", "ES256")
        put("jwk", jwk)
        if (!kid.isNullOrBlank()) {
          put("kid", kid)
        }
      }

      val payload = JSONObject().apply {
        put("jti", if (jti.isNullOrBlank()) UUID.randomUUID().toString() else jti)
        put("htm", htm.uppercase())
        put("htu", htu)
        put("iat", iat?.toLong() ?: (System.currentTimeMillis() / 1000L))
      }

      if (!nonce.isNullOrBlank()) {
        payload.put("nonce", nonce)
      }

      if (!accessToken.isNullOrBlank()) {
        payload.put("ath", DPoPUtils.hashAccessToken(accessToken))
      }

      if (additional != null) {
        val additionalJson = DPoPUtils.toJsonObject(additional)
        val keys = additionalJson.keys()
        while (keys.hasNext()) {
          val key = keys.next()
          payload.put(key, additionalJson.get(key))
        }
      }

      val headerSegment = DPoPUtils.base64UrlEncode(header.toString().toByteArray(Charsets.UTF_8))
      val payloadSegment = DPoPUtils.base64UrlEncode(payload.toString().toByteArray(Charsets.UTF_8))
      val signingInput = "$headerSegment.$payloadSegment"

      val signature = Signature.getInstance("SHA256withECDSA").apply {
        initSign(keyPair.privateKey)
        update(signingInput.toByteArray(Charsets.UTF_8))
      }
      val joseSignature = DPoPUtils.derToJose(signature.sign(), partLength = 32)
      val jwt = "$signingInput.${DPoPUtils.base64UrlEncode(joseSignature)}"

      val proofContext = Arguments.createMap().apply {
        putString("htu", payload.optString("htu"))
        putString("htm", payload.optString("htm"))
        putString("nonce", if (payload.has("nonce")) payload.optString("nonce") else null)
        putString("ath", if (payload.has("ath")) payload.optString("ath") else null)
        putString("kid", if (header.has("kid")) header.optString("kid") else null)
        putString("jti", payload.optString("jti"))
        putDouble("iat", payload.optLong("iat").toDouble())
        if (additional != null) {
          putMap("additional", DPoPUtils.readableMapToWritableMap(additional))
        } else {
          putNull("additional")
        }
      }

      val result = Arguments.createMap().apply {
        putString("proof", jwt)
        putMap("proofContext", proofContext)
      }
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("ERR_DPOP_GENERATE_PROOF", e.message, e)
    }
  }
}
