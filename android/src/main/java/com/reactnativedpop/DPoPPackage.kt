package com.reactnativedpop

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

class DPoPPackage : BaseReactPackage() {
  override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? {
    return if (name == DPoPModule.NAME) {
      DPoPModule(reactContext)
    } else {
      null
    }
  }

  override fun getReactModuleInfoProvider() = ReactModuleInfoProvider {
    mapOf(
      DPoPModule.NAME to ReactModuleInfo(
        DPoPModule.NAME,
        DPoPModule::class.java.name,
        false,
        false,
        false,
        false,
        true
      )
    )
  }
}
