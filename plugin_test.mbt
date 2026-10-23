// CapWasm High-Level Plugin Sandbox and Extism ABI Test Suite

///|
test "plugin: config builder and vfs mount" {
  let policy = @capwasm.CapabilityPolicyBuilder::new()
    .allow_read_path("/workspace/input/")
    .allow_write_path("/workspace/output/")
    .allow_network_host("api.github.com")
    .build()

  let vfs = @capwasm.VirtualFileSystem::new()
  let content : Array[Byte] = [b'\x7b', b'\x7d']
  let _ = vfs.create_file("/workspace/input/config.json", content)

  let cfg = @capwasm.PluginConfig::new("plugin-test-1", policy).with_vfs(vfs)
  assert_eq(cfg.plugin_id, "plugin-test-1")
  assert_eq(cfg.vfs.exists("/workspace/input/config.json"), true)
}

///|
test "plugin: binary module loading and validation" {
  // Construct minimal valid WASM binary:
  // magic: \0asm, version: 1
  let wasm_bytes : Array[Byte] = [
    b'\x00', b'\x61', b'\x73', b'\x6d', // \0asm
     b'\x01', b'\x00', b'\x00', b'\x00', // version 1
  ]

  let policy = @capwasm.CapabilityPolicyBuilder::new().build()
  let cfg = @capwasm.PluginConfig::new("minimal-plugin", policy)
  let plugin_res = @capwasm.PluginInstance::load(cfg, wasm_bytes)
  assert_true(plugin_res is Ok(_))

  let plugin = match plugin_res {
    Ok(p) => p
    Err(_) => return
  }

  assert_eq(plugin.metrics.total_calls, 0)
  assert_eq(plugin.metrics.peak_memory_pages, 0)
}

///|
test "plugin: malformed binary rejected cleanly" {
  let invalid_bytes : Array[Byte] = [b'\xde', b'\xad', b'\xbe', b'\xef']
  let policy = @capwasm.CapabilityPolicyBuilder::new().build()
  let cfg = @capwasm.PluginConfig::new("corrupt-plugin", policy)
  let plugin_res = @capwasm.PluginInstance::load(cfg, invalid_bytes)
  assert_true(plugin_res is Err(@capwasm.SecurityError::Aborted(_)))
}

///|
test "plugin: metrics and audit logging" {
  let policy = @capwasm.CapabilityPolicyBuilder::new()
    .allow_read_path("/allowed/")
    .build()

  let vfs = @capwasm.VirtualFileSystem::new()
  let _ = vfs.create_file("/allowed/test.txt", [b'\x41', b'\x42'])
  let cfg = @capwasm.PluginConfig::new("audit-plugin", policy).with_vfs(vfs)

  let wasm_bytes : Array[Byte] = [
    b'\x00', b'\x61', b'\x73', b'\x6d', b'\x01', b'\x00', b'\x00', b'\x00',
  ]

  let plugin = match @capwasm.PluginInstance::load(cfg, wasm_bytes) {
    Ok(p) => p
    Err(_) => return
  }

  // Verify capability guard audit logs directly
  let _ = plugin.sec_guard.check_fs_read("/allowed/test.txt")
  let _ = plugin.sec_guard.check_fs_read("/forbidden/shadow")
  let _ = plugin.sec_guard.check_network("malicious.c2")

  let logs = plugin.get_audit_logs()
  assert_eq(logs.length(), 3)
  assert_eq(logs[0].allowed, true)
  assert_eq(logs[1].allowed, false)
  assert_eq(logs[2].allowed, false)
}

///|
test "plugin: instance reset reinitializes cleanly" {
  let wasm_bytes : Array[Byte] = [
    b'\x00', b'\x61', b'\x73', b'\x6d', b'\x01', b'\x00', b'\x00', b'\x00',
  ]

  let policy = @capwasm.CapabilityPolicyBuilder::new().build()
  let cfg = @capwasm.PluginConfig::new("reset-plugin", policy)
  let plugin = match @capwasm.PluginInstance::load(cfg, wasm_bytes) {
    Ok(p) => p
    Err(_) => return
  }

  assert_eq(plugin.reset(), Ok(()))
}
