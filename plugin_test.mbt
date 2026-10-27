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

///|
test "extism: kernel memory allocator, block reuse, and quota enforcement" {
  let policy = @capwasm.CapabilityPolicyBuilder::new()
    .max_memory_pages(2)
    .build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("extism-alloc-test", policy)
  let mem = match
    @capwasm.LinearMemory::new(@capwasm.Limits::{ min: 1, max: Some(4), }) {
    Ok(m) => m
    Err(_) => return
  }
  let kernel = @capwasm.ExtismKernel::new()

  // Allocate 64 bytes -> starts at heap base 8192
  let off1 = match kernel.alloc(mem, Some(sec_guard), 64L) {
    Ok(o) => o
    Err(_) => 0L
  }
  assert_eq(off1, 8192L)
  assert_eq(kernel.block_length(off1), 64L)

  // Free and re-allocate 32 bytes -> reuses block at 8192
  kernel.free(off1)
  assert_eq(kernel.block_length(off1), 0L)
  let off2 = match kernel.alloc(mem, Some(sec_guard), 32L) {
    Ok(o) => o
    Err(_) => 0L
  }
  assert_eq(off2, 8192L)

  // Request allocation exceeding 2-page (128 KiB) capability ceiling -> denied (returns 0L)
  let huge = match kernel.alloc(mem, Some(sec_guard), 200000L) {
    Ok(o) => o
    Err(_) => -1L
  }
  assert_eq(huge, 0L)
}

///|
test "extism: end-to-end binary plugin with extism:host/env ABI (uppercase transform)" {
  // Build a real Wasm binary module that imports `extism:host/env`:
  //   func 0: import extism:host/env.input_length () -> i64          (type 0)
  //   func 1: import extism:host/env.alloc (i64) -> i64              (type 1)
  //   func 2: import extism:host/env.input_load_u8 (i64) -> i32      (type 2)
  //   func 3: import extism:host/env.store_u8 (i64, i32) -> ()       (type 3)
  //   func 4: import extism:host/env.output_set (i64, i64) -> ()     (type 4)
  //   func 5: export "transform" () -> i32                           (type 5)
  //     Reads 4 bytes from Extism input, converts ASCII lowercase to uppercase (-32),
  //     stores into allocated Extism kernel block, calls output_set(ptr, len), returns 0.
  let wasm_bytes : Array[Byte] = [
    b'\x00', b'\x61', b'\x73', b'\x6d', b'\x01', b'\x00', b'\x00', b'\x00',
    // Section 1: Type Section (6 types, payload = 29 bytes = 0x1d)
     b'\x01', b'\x1d', b'\x06',
    // type 0: () -> i64
     b'\x60', b'\x00', b'\x01', b'\x7e',
    // type 1: (i64) -> i64
     b'\x60', b'\x01', b'\x7e', b'\x01', b'\x7e',
    // type 2: (i64) -> i32
     b'\x60', b'\x01', b'\x7e', b'\x01', b'\x7f',
    // type 3: (i64, i32) -> ()
     b'\x60', b'\x02', b'\x7e', b'\x7f', b'\x00',
    // type 4: (i64, i64) -> ()
     b'\x60', b'\x02', b'\x7e', b'\x7e', b'\x00',
    // type 5: () -> i32
     b'\x60', b'\x00', b'\x01', b'\x7f',
    // Section 2: Import Section (5 imports from "env", payload = 84 bytes = 0x54)
     b'\x02', b'\x54', b'\x05',
    // import 0: "env"."input_length" (func type 0) -> 1+3 + 1+12 + 2 = 19
     b'\x03', b'e', b'n', b'v', b'\x0c', b'i', b'n', b'p', b'u', b't', b'_', b'l',
    b'e', b'n', b'g', b't', b'h', b'\x00', b'\x00',
    // import 1: "env"."alloc" (func type 1) -> 1+3 + 1+5 + 2 = 12
     b'\x03', b'e', b'n', b'v', b'\x05', b'a', b'l', b'l', b'o', b'c', b'\x00', b'\x01',
    // import 2: "env"."input_load_u8" (func type 2) -> 1+3 + 1+13 + 2 = 20
     b'\x03', b'e', b'n', b'v', b'\x0d', b'i', b'n', b'p', b'u', b't', b'_', b'l',
    b'o', b'a', b'd', b'_', b'u', b'8', b'\x00', b'\x02',
    // import 3: "env"."store_u8" (func type 3) -> 1+3 + 1+8 + 2 = 15
     b'\x03', b'e', b'n', b'v', b'\x08', b's', b't', b'o', b'r', b'e', b'_', b'u',
    b'8', b'\x00', b'\x03',
    // import 4: "env"."output_set" (func type 4) -> 1+3 + 1+10 + 2 = 17  (total = 1+19+12+20+15+17 = 84 = 0x54)
     b'\x03', b'e', b'n', b'v', b'\x0a', b'o', b'u', b't', b'p', b'u', b't', b'_',
    b's', b'e', b't', b'\x00', b'\x04',
    // Section 3: Function Section (1 function of type 5)
     b'\x03', b'\x02', b'\x01', b'\x05',
    // Section 5: Memory Section (1 memory, min 1 page)
     b'\x05', b'\x03', b'\x01', b'\x00', b'\x01',
    // Section 7: Export Section (export "run" -> func 5)
     b'\x07', b'\x07', b'\x01', b'\x03', b'r', b'u', b'n', b'\x00', b'\x05',
    // Section 10: Code Section (payload = 64 bytes = 0x40, body = 62 bytes = 0x3e)
     b'\x0a', b'\x40', b'\x01', b'\x3e', b'\x01', b'\x03', b'\x7e', // 1 local group: 3 x i64
     b'\x10', b'\x00', b'\x21', b'\x00', // call 0, local.set 0
     b'\x20', b'\x00', b'\x10', b'\x01', b'\x21', b'\x01', // local.get 0, call 1, local.set 1
     b'\x42', b'\x00', b'\x21', b'\x02', // i64.const 0, local.set 2
     b'\x02', b'\x40', // block (void)
     b'\x03', b'\x40', // loop (void)
     b'\x20', b'\x02', b'\x20', b'\x00', b'\x59', b'\x0d', b'\x01', // local.get 2, local.get 0, i64.ge_s, br_if 1
     b'\x20', b'\x01', b'\x20', b'\x02', b'\x7c', // local.get 1, local.get 2, i64.add
     b'\x20', b'\x02', b'\x10', b'\x02', b'\x41', b'\x20', b'\x6b', // local.get 2, call 2, i32.const 32, i32.sub
     b'\x10', b'\x03', // call 3 (store_u8)
     b'\x20', b'\x02', b'\x42', b'\x01', b'\x7c', b'\x21', b'\x02', // local.get 2, i64.const 1, i64.add, local.set 2
     b'\x0c', b'\x00', // br 0
     b'\x0b', // end loop
     b'\x0b', // end block
     b'\x20', b'\x01', b'\x20', b'\x00', b'\x10', b'\x04', // local.get 1, local.get 0, call 4 (output_set)
     b'\x41', b'\x00', // i32.const 0
     b'\x0b', // end func
  ]

  let policy = @capwasm.CapabilityPolicyBuilder::new()
    .max_memory_pages(4)
    .max_execution_steps(5000)
    .build()
  let cfg = @capwasm.PluginConfig::new("extism-upper-plugin", policy)
  let plugin = match @capwasm.PluginInstance::load(cfg, wasm_bytes) {
    Ok(p) => p
    Err(e) => {
      println("Load failed: " + e.to_string())
      assert_true(false)
      return
    }
  }

  let out = plugin.call_string("run", "moonbit")
  assert_eq(out, Ok("MOONBIT"))
  assert_eq(plugin.get_metrics().total_calls, 1)
  assert_true(plugin.get_metrics().total_gas_consumed > 20)
}

///|
test "extism: capability-gated http_request and config/var state store" {
  let policy = @capwasm.CapabilityPolicyBuilder::new()
    .allow_network_host("api.moonbitlang.com")
    .max_memory_pages(4)
    .build()
  let cfg = @capwasm.PluginConfig::new("extism-http-plugin", policy)
  let wasm_bytes : Array[Byte] = [
    b'\x00', b'\x61', b'\x73', b'\x6d', b'\x01', b'\x00', b'\x00', b'\x00',
    // Memory section: 1 page
     b'\x05', b'\x03', b'\x01', b'\x00', b'\x01',
  ]
  let plugin = match @capwasm.PluginInstance::load(cfg, wasm_bytes) {
    Ok(p) => p
    Err(_) => return
  }

  // Test Config & Var store in ExtismKernel
  plugin.set_extism_config("model", "deepseek-v3")
  assert_eq(plugin.extism_kernel.get_config("model"), Some("deepseek-v3"))

  plugin.set_extism_var("counter", [b'\x2a'])
  assert_eq(plugin.get_extism_var("counter"), Some([b'\x2a']))

  // Test Extism HTTP request capability enforcement via Linker-registered host function
  let mem = match plugin.instance.get_memory(0) {
    Ok(m) => m
    Err(_) => return
  }
  let http_fn = match
    plugin.linker.resolve_func("extism:host/env", "http_request") {
    Some(f) => f
    None => return
  }
  let status_fn = match
    plugin.linker.resolve_func("extism:host/env", "http_status_code") {
    Some(f) => f
    None => return
  }

  // 1. Allowed request to api.moonbitlang.com -> HTTP 200 & valid response block
  let allowed_req_off = match
    plugin.extism_kernel.alloc_and_write_string(
      mem,
      Some(plugin.sec_guard),
      "{\"url\":\"https://api.moonbitlang.com/v1/packages\"}",
    ) {
    Ok(o) => o
    Err(_) => 0L
  }
  let resp1 = (http_fn.callback)(plugin.instance.host_context, [
    @capwasm.Value::I64(allowed_req_off),
    @capwasm.Value::I64(0L),
  ])
  assert_true(resp1 is Ok([@capwasm.Value::I64(off)]) && off > 0L)
  let st1 = (status_fn.callback)(plugin.instance.host_context, [])
  assert_eq(st1, Ok([@capwasm.Value::I32(200)]))

  // 2. Unauthorized request to evil.attacker.org -> HTTP 403 & 0L response handle
  let blocked_req_off = match
    plugin.extism_kernel.alloc_and_write_string(
      mem,
      Some(plugin.sec_guard),
      "{\"url\":\"https://evil.attacker.org/exfiltrate\"}",
    ) {
    Ok(o) => o
    Err(_) => 0L
  }
  let resp2 = (http_fn.callback)(plugin.instance.host_context, [
    @capwasm.Value::I64(blocked_req_off),
    @capwasm.Value::I64(0L),
  ])
  assert_eq(resp2, Ok([@capwasm.Value::I64(0L)]))
  let st2 = (status_fn.callback)(plugin.instance.host_context, [])
  assert_eq(st2, Ok([@capwasm.Value::I32(403)]))

  // Verify security audit log recorded both the allowed and blocked HTTP requests
  let logs = plugin.get_audit_logs()
  assert_eq(logs.length(), 2)
  assert_eq(logs[0].allowed, true)
  assert_eq(logs[1].allowed, false)
}
