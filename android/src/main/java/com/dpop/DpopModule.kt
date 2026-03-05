package com.dpop

import com.facebook.react.bridge.ReactApplicationContext

class DpopModule(reactContext: ReactApplicationContext) :
  NativeDpopSpec(reactContext) {

  override fun multiply(a: Double, b: Double): Double {
    return a * b
  }

  companion object {
    const val NAME = NativeDpopSpec.NAME
  }
}
