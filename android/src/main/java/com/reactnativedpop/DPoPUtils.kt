package com.reactnativedpop

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReadableType
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import java.math.BigInteger
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

internal object DPoPUtils {
  internal fun base64UrlEncode(input: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(input)
  }

  internal fun derToJose(derSignature: ByteArray, partLength: Int = 32): ByteArray {
    if (derSignature.isEmpty() || derSignature[0].toInt() != 0x30) {
      throw IllegalArgumentException("Invalid DER signature format")
    }

    var index = 1
    val sequenceLength = readDerLength(derSignature, index)
    index += sequenceLength.second

    if (sequenceLength.first <= 0 || index + sequenceLength.first > derSignature.size) {
      throw IllegalArgumentException("Invalid DER sequence length")
    }

    if (derSignature[index].toInt() != 0x02) {
      throw IllegalArgumentException("Invalid DER integer marker for R")
    }
    index += 1
    val rLength = readDerLength(derSignature, index)
    index += rLength.second
    val rBytes = derSignature.copyOfRange(index, index + rLength.first)
    index += rLength.first

    if (derSignature[index].toInt() != 0x02) {
      throw IllegalArgumentException("Invalid DER integer marker for S")
    }
    index += 1
    val sLength = readDerLength(derSignature, index)
    index += sLength.second
    val sBytes = derSignature.copyOfRange(index, index + sLength.first)

    val r = toUnsignedFixedLength(BigInteger(1, rBytes), partLength)
    val s = toUnsignedFixedLength(BigInteger(1, sBytes), partLength)
    return r + s
  }

  internal fun getPublicCoordinates(publicKey: ECPublicKey): Pair<String, String> {
    val x = base64UrlEncode(toUnsignedFixedLength(publicKey.w.affineX, 32))
    val y = base64UrlEncode(toUnsignedFixedLength(publicKey.w.affineY, 32))
    return Pair(x, y)
  }

  internal fun getPublicKeyThumbprint(kty: String, crv: String, x: String, y: String): String {
    val canonicalJwk = """{"crv":"$crv","kty":"$kty","x":"$x","y":"$y"}"""
    val hash = MessageDigest.getInstance("SHA-256").digest(canonicalJwk.toByteArray(Charsets.UTF_8))
    return base64UrlEncode(hash)
  }

  internal fun hashAccessToken(accessToken: String): String {
    val hash = MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(Charsets.UTF_8))
    return base64UrlEncode(hash)
  }

  internal fun isProofBoundToPublicKey(proof: String, publicKey: ECPublicKey): Boolean {
    val segments = proof.split(".")
    if (segments.size != 3) {
      throw IllegalArgumentException("Invalid DPoP proof format")
    }

    val headerBytes = Base64.getUrlDecoder().decode(padBase64Url(segments[0]))
    val header = JSONObject(String(headerBytes, Charsets.UTF_8))
    val jwk = header.optJSONObject("jwk")
      ?: throw IllegalArgumentException("DPoP proof header does not contain jwk")

    val coordinates = getPublicCoordinates(publicKey)
    return (
      jwk.optString("kty") == "EC" &&
        jwk.optString("crv") == "P-256" &&
        jwk.optString("x") == coordinates.first &&
        jwk.optString("y") == coordinates.second
      )
  }

  internal fun readableMapToWritableMap(map: ReadableMap): WritableMap {
    val result = Arguments.createMap()
    val iterator = map.keySetIterator()
    while (iterator.hasNextKey()) {
      val key = iterator.nextKey()
      when (map.getType(key)) {
        ReadableType.Array -> result.putArray(key, readableArrayToWritableArray(map.getArray(key)!!))
        ReadableType.Boolean -> result.putBoolean(key, map.getBoolean(key))
        ReadableType.Map -> result.putMap(key, readableMapToWritableMap(map.getMap(key)!!))
        ReadableType.Null -> result.putNull(key)
        ReadableType.Number -> result.putDouble(key, map.getDouble(key))
        ReadableType.String -> result.putString(key, map.getString(key))
      }
    }
    return result
  }

  internal fun toJsonObject(map: ReadableMap): JSONObject {
    val result = JSONObject()
    val iterator = map.keySetIterator()
    while (iterator.hasNextKey()) {
      val key = iterator.nextKey()
      when (map.getType(key)) {
        ReadableType.Array -> result.put(key, toJsonArray(map.getArray(key)!!))
        ReadableType.Boolean -> result.put(key, map.getBoolean(key))
        ReadableType.Map -> result.put(key, toJsonObject(map.getMap(key)!!))
        ReadableType.Null -> result.put(key, JSONObject.NULL)
        ReadableType.Number -> result.put(key, map.getDouble(key))
        ReadableType.String -> result.put(key, map.getString(key))
      }
    }
    return result
  }

  internal fun toRawPublicKey(publicKey: ECPublicKey): ByteArray {
    val x = toUnsignedFixedLength(publicKey.w.affineX, 32)
    val y = toUnsignedFixedLength(publicKey.w.affineY, 32)
    return byteArrayOf(0x04) + x + y
  }

  private fun readableArrayToWritableArray(array: ReadableArray): WritableArray {
    val result = Arguments.createArray()
    for (index in 0 until array.size()) {
      when (array.getType(index)) {
        ReadableType.Array -> result.pushArray(readableArrayToWritableArray(array.getArray(index)!!))
        ReadableType.Boolean -> result.pushBoolean(array.getBoolean(index))
        ReadableType.Map -> result.pushMap(readableMapToWritableMap(array.getMap(index)!!))
        ReadableType.Null -> result.pushNull()
        ReadableType.Number -> result.pushDouble(array.getDouble(index))
        ReadableType.String -> result.pushString(array.getString(index))
      }
    }
    return result
  }

  private fun toJsonArray(array: ReadableArray): JSONArray {
    val result = JSONArray()
    for (index in 0 until array.size()) {
      when (array.getType(index)) {
        ReadableType.Array -> result.put(toJsonArray(array.getArray(index)!!))
        ReadableType.Boolean -> result.put(array.getBoolean(index))
        ReadableType.Map -> result.put(toJsonObject(array.getMap(index)!!))
        ReadableType.Null -> result.put(JSONObject.NULL)
        ReadableType.Number -> result.put(array.getDouble(index))
        ReadableType.String -> result.put(array.getString(index))
      }
    }
    return result
  }

  private fun padBase64Url(input: String): String {
    val remainder = input.length % 4
    return if (remainder == 0) {
      input
    } else {
      input + "=".repeat(4 - remainder)
    }
  }

  private fun readDerLength(input: ByteArray, startIndex: Int): Pair<Int, Int> {
    val first = input[startIndex].toInt() and 0xFF
    if ((first and 0x80) == 0) {
      return Pair(first, 1)
    }

    val lengthBytesCount = first and 0x7F
    if (lengthBytesCount == 0 || lengthBytesCount > 4) {
      throw IllegalArgumentException("Invalid DER length")
    }

    var length = 0
    for (i in 0 until lengthBytesCount) {
      length = (length shl 8) or (input[startIndex + 1 + i].toInt() and 0xFF)
    }
    return Pair(length, 1 + lengthBytesCount)
  }

  private fun toUnsignedFixedLength(value: BigInteger, length: Int): ByteArray {
    val signed = value.toByteArray()
    if (signed.size == length) {
      return signed
    }

    if (signed.size == length + 1 && signed[0].toInt() == 0) {
      return signed.copyOfRange(1, signed.size)
    }

    if (signed.size < length) {
      val output = ByteArray(length)
      System.arraycopy(signed, 0, output, length - signed.size, signed.size)
      return output
    }

    throw IllegalArgumentException("Coordinate is larger than expected length")
  }
}
