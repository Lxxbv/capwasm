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
test "extism: isolated kernel memory allocator, block reuse, and quota enforcement" {
  let policy = @capwasm.CapabilityPolicyBuilder::new()
    .max_memory_pages(2)
    .build()
  let sec_guard = @capwasm.PluginSecurityGuard::new("extism-alloc-test", policy)
  let kernel = @capwasm.ExtismKernel::new()

  // Allocate 64 bytes -> starts at offset 64 in isolated kernel_memory
  let off1 = match kernel.alloc(Some(sec_guard), 64L) {
    Ok(o) => o
    Err(_) => 0L
  }
  assert_eq(off1, 64L)
  assert_eq(kernel.block_length(off1), 64L)

  // Free and re-allocate 32 bytes -> reuses block at 64
  kernel.free(off1)
  assert_eq(kernel.block_length(off1), 0L)
  let off2 = match kernel.alloc(Some(sec_guard), 32L) {
    Ok(o) => o
    Err(_) => 0L
  }
  assert_eq(off2, 64L)

  // Request allocation exceeding 2-page (128 KiB) capability ceiling -> denied (returns 0L)
  let huge = match kernel.alloc(Some(sec_guard), 200000L) {
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

///|
test "manifest: ExtismManifest JSON parser, wildcard hosts, and path mount resolution" {
  let json =
    #|{
    #|  "plugin_id": "markdown-sanitizer",
    #|  "max_pages": 8,
    #|  "max_var_bytes": 4096,
    #|  "max_http_response_bytes": 16384,
    #|  "config": { "theme": "dark", "strict": "true" },
    #|  "allowed_hosts": ["*.moonbitlang.com", "api.github.com"],
    #|  "allowed_paths": { "ro:/host/tenant_a/docs": "/docs", "/host/tenant_a/out": "/out" },
    #|  "allowed_env_vars": ["LANG", "TZ"]
    #|}
  let manifest = match @capwasm.ExtismManifest::from_json(json) {
    Ok(m) => m
    Err(_) => {
      assert_true(false)
      return
    }
  }
  assert_eq(manifest.plugin_id, "markdown-sanitizer")
  assert_eq(manifest.memory.max_pages, 8)
  assert_eq(manifest.memory.max_var_bytes, 4096)
  assert_eq(manifest.memory.max_http_response_bytes, 16384)
  assert_eq(manifest.allowed_hosts.length(), 2)
  assert_eq(manifest.allowed_paths.length(), 2)

  // Verify wildcard host matching (*.moonbitlang.com)
  let policy = manifest.to_capability_policy()
  let sec_guard = @capwasm.PluginSecurityGuard::new(
    "markdown-sanitizer", policy,
  )
  assert_eq(sec_guard.check_network("mooncakes.moonbitlang.com"), Ok(()))
  assert_eq(sec_guard.check_network("docs.sub.moonbitlang.com"), Ok(()))
  assert_true(sec_guard.check_network("evil.com") is Err(_))

  // Verify guest-to-host path mount resolution & read-only enforcement
  let r_read = @capwasm.resolve_mounted_path(
    manifest.allowed_paths,
    "/docs/guide.md",
    false,
  )
  assert_eq(r_read, Ok("/host/tenant_a/docs/guide.md"))

  // Writing to read-only mount "/docs" must be rejected
  let r_write_ro = @capwasm.resolve_mounted_path(
    manifest.allowed_paths,
    "/docs/hack.md",
    true,
  )
  assert_true(r_write_ro is Err(@capwasm.SecurityError::PermissionDenied(_)))

  // Writing to read-write mount "/out" must succeed
  let r_write_rw = @capwasm.resolve_mounted_path(
    manifest.allowed_paths,
    "/out/rendered.html",
    true,
  )
  assert_eq(r_write_rw, Ok("/host/tenant_a/out/rendered.html"))
}

///|
test "pdk & manifest: encode_to_bytes round-trip, FIPS 180-4 SHA-256 hash check, WASI & call_indirect" {
  // Verify NIST FIPS 180-4 SHA-256 standard vector: sha256("abc")
  let abc_sha256 = @capwasm.compute_wasm_sha256([b'a', b'b', b'c'])
  assert_eq(
    abc_sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )

  // Construct a Wasm module using WasmModule AST + encode_to_bytes that:
  // 1. Imports wasi_snapshot_preview1::clock_time_get (type 0: (i32, i64, i32) -> i32)
  // 2. Defines a table of 2 functions and uses CallIndirect (type 1: (i32) -> i32)
  //    - func 1 (double): x * 2
  //    - func 2 (triple): x * 3
  //    - func 3 (exported "compute"): calls clock_time_get, then call_indirect(op_idx, val)
  let t_clock = @capwasm.FuncType::new(
    [@capwasm.ValueType::I32, @capwasm.ValueType::I64, @capwasm.ValueType::I32],
    [@capwasm.ValueType::I32],
  )
  let t_unary = @capwasm.FuncType::new([@capwasm.ValueType::I32], [
    @capwasm.ValueType::I32,
  ])
  let t_entry = @capwasm.FuncType::new(
    [@capwasm.ValueType::I32, @capwasm.ValueType::I32],
    [@capwasm.ValueType::I32],
  )

  let mod_ast : @capwasm.WasmModule = {
    types: [t_clock, t_unary, t_entry],
    imports: [
      @capwasm.ImportEntry::new(
        "wasi_snapshot_preview1",
        "clock_time_get",
        @capwasm.ImportDesc::Func(0),
      ),
    ],
    func_types: [1, 1, 2],
    tables: [
      @capwasm.TableType::new(@capwasm.Limits::{ min: 2, max: Some(2), }),
    ],
    memories: [
      @capwasm.MemoryType::new(@capwasm.Limits::{ min: 1, max: Some(4), }),
    ],
    globals: [],
    exports: [
      @capwasm.ExportEntry::new("compute", @capwasm.ExportDesc::Func(3)),
    ],
    start_func: None,
    elements: [
      @capwasm.ElementSegment::new(
        0,
        [@capwasm.Instruction::I32Const(0), @capwasm.Instruction::End],
        [1, 2],
      ),
    ],
    code: [
      // func 1 (index 1): x * 2
      @capwasm.FunctionBody::new([], [
        @capwasm.Instruction::LocalGet(0),
        @capwasm.Instruction::I32Const(2),
        @capwasm.Instruction::I32Mul,
        @capwasm.Instruction::End,
      ]),
      // func 2 (index 2): x * 3
      @capwasm.FunctionBody::new([], [
        @capwasm.Instruction::LocalGet(0),
        @capwasm.Instruction::I32Const(3),
        @capwasm.Instruction::I32Mul,
        @capwasm.Instruction::End,
      ]),
      // func 3 (index 3): (val, table_slot) -> calls clock_time_get(0, 1000L, 64), then call_indirect(type 1)
      @capwasm.FunctionBody::new([], [
        @capwasm.Instruction::I32Const(0),
        @capwasm.Instruction::I64Const(1000L),
        @capwasm.Instruction::I32Const(64),
        @capwasm.Instruction::Call(0),
        @capwasm.Instruction::Drop,
        @capwasm.Instruction::LocalGet(0),
        @capwasm.Instruction::LocalGet(1),
        @capwasm.Instruction::CallIndirect(1, 0),
        @capwasm.Instruction::End,
      ]),
    ],
    data: [],
  }

  let wasm_bytes = mod_ast.encode_to_bytes()
  let fingerprint = @capwasm.compute_wasm_fingerprint(wasm_bytes)

  let vfs = @capwasm.VirtualFileSystem::new()
  let _ = vfs.create_file("/plugins/math.wasm", wasm_bytes)

  // 1. Tampered hash in manifest must be rejected with PermissionDenied
  let bad_manifest = @capwasm.ExtismManifest::new("tampered-plugin").with_wasm_path(
    "math",
    "/plugins/math.wasm",
    Some("0000000000000000"),
  )
  let bad_load = @capwasm.PluginInstance::load_from_manifest(bad_manifest, vfs)
  assert_true(bad_load is Err(@capwasm.SecurityError::PermissionDenied(_)))

  // 2. Valid hash in manifest loads and executes CallIndirect + WASI clock_time_get
  let good_manifest = @capwasm.ExtismManifest::new("verified-plugin").with_wasm_path(
    "math",
    "/plugins/math.wasm",
    Some(fingerprint),
  )
  let plugin = match
    @capwasm.PluginInstance::load_from_manifest(good_manifest, vfs) {
    Ok(p) => p
    Err(e) => {
      println("Manifest load error: " + e.to_string())
      assert_true(false)
      return
    }
  }

  let res_double = plugin.call("compute", [
    @capwasm.Value::I32(21),
    @capwasm.Value::I32(0),
  ])
  assert_eq(res_double, Ok([@capwasm.Value::I32(42)]))

  let res_triple = plugin.call("compute", [
    @capwasm.Value::I32(21),
    @capwasm.Value::I32(1),
  ])
  assert_eq(res_triple, Ok([@capwasm.Value::I32(63)]))
}

///|
test "wasi & extism: end-to-end WASI path_open + fd_read + Extism output_set via mounted virtual directory" {
  // Build a Wasm guest module that:
  // 1. Imports wasi_snapshot_preview1::path_open, fd_read, fd_close
  // 2. Imports extism:host/env::alloc, store_u8, output_set
  // 3. Opens guest virtual path "/docs/hello.txt" (mapped to host "/host/tenant_a/docs/hello.txt"),
  //    reads 5 bytes ("HELLO") via WASI iovec into linear memory, copies first byte into an
  //    Extism kernel memory block, and publishes it via output_set.
  let t_path_open = @capwasm.FuncType::new(
    [
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I64,
      @capwasm.ValueType::I64,
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I32,
    ],
    [@capwasm.ValueType::I32],
  )
  let t_fd_read = @capwasm.FuncType::new(
    [
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I32,
      @capwasm.ValueType::I32,
    ],
    [@capwasm.ValueType::I32],
  )
  let t_fd_close = @capwasm.FuncType::new([@capwasm.ValueType::I32], [
    @capwasm.ValueType::I32,
  ])
  let t_alloc = @capwasm.FuncType::new([@capwasm.ValueType::I64], [
    @capwasm.ValueType::I64,
  ])
  let t_store_u8 = @capwasm.FuncType::new(
    [@capwasm.ValueType::I64, @capwasm.ValueType::I32],
    [],
  )
  let t_output_set = @capwasm.FuncType::new(
    [@capwasm.ValueType::I64, @capwasm.ValueType::I64],
    [],
  )
  let t_run = @capwasm.FuncType::new([], [@capwasm.ValueType::I32])

  // Data segment at offset 16: "/docs/hello.txt" (15 bytes)
  let guest_path_bytes = @capwasm.BinaryReader::from_string("/docs/hello.txt").bytes

  let mod_ast : @capwasm.WasmModule = {
    types: [
      t_path_open, t_fd_read, t_fd_close, t_alloc, t_store_u8, t_output_set, t_run,
    ],
    imports: [
      @capwasm.ImportEntry::new(
        "wasi_snapshot_preview1",
        "path_open",
        @capwasm.ImportDesc::Func(0),
      ),
      @capwasm.ImportEntry::new(
        "wasi_snapshot_preview1",
        "fd_read",
        @capwasm.ImportDesc::Func(1),
      ),
      @capwasm.ImportEntry::new(
        "wasi_snapshot_preview1",
        "fd_close",
        @capwasm.ImportDesc::Func(2),
      ),
      @capwasm.ImportEntry::new(
        "extism:host/env",
        "alloc",
        @capwasm.ImportDesc::Func(3),
      ),
      @capwasm.ImportEntry::new(
        "extism:host/env",
        "store_u8",
        @capwasm.ImportDesc::Func(4),
      ),
      @capwasm.ImportEntry::new(
        "extism:host/env",
        "output_set",
        @capwasm.ImportDesc::Func(5),
      ),
    ],
    func_types: [6],
    tables: [],
    memories: [
      @capwasm.MemoryType::new(@capwasm.Limits::{ min: 2, max: Some(8), }),
    ],
    globals: [],
    exports: [
      @capwasm.ExportEntry::new("read_doc", @capwasm.ExportDesc::Func(6)),
    ],
    start_func: None,
    elements: [],
    code: [
      @capwasm.FunctionBody::new(
        [
          @capwasm.LocalDecl::new(1, @capwasm.ValueType::I32), // local 0: fd
          @capwasm.LocalDecl::new(1, @capwasm.ValueType::I64), // local 1: out_ptr
        ],
        [
          // Call path_open(dirfd=3, dirflags=0, path_ptr=16, path_len=15, oflags=0, rights_base=2, rights_inh=0, fdflags=0, opened_fd_ptr=64)
          @capwasm.Instruction::I32Const(3),
          @capwasm.Instruction::I32Const(0),
          @capwasm.Instruction::I32Const(16),
          @capwasm.Instruction::I32Const(15),
          @capwasm.Instruction::I32Const(0),
          @capwasm.Instruction::I64Const(2L),
          @capwasm.Instruction::I64Const(0L),
          @capwasm.Instruction::I32Const(0),
          @capwasm.Instruction::I32Const(64),
          @capwasm.Instruction::Call(0),
          @capwasm.Instruction::Drop,
          // Load opened fd from address 64 -> local 0
          @capwasm.Instruction::I32Const(64),
          @capwasm.Instruction::I32Load(@capwasm.MemArg::new(2, 0)),
          @capwasm.Instruction::LocalSet(0),
          // Set up iovec at address 80: { buf_ptr: 128, buf_len: 5 }
          @capwasm.Instruction::I32Const(80),
          @capwasm.Instruction::I32Const(128),
          @capwasm.Instruction::I32Store(@capwasm.MemArg::new(2, 0)),
          @capwasm.Instruction::I32Const(84),
          @capwasm.Instruction::I32Const(5),
          @capwasm.Instruction::I32Store(@capwasm.MemArg::new(2, 0)),
          // Call fd_read(fd=local 0, iovs_ptr=80, iovs_len=1, nread_ptr=96)
          @capwasm.Instruction::LocalGet(0),
          @capwasm.Instruction::I32Const(80),
          @capwasm.Instruction::I32Const(1),
          @capwasm.Instruction::I32Const(96),
          @capwasm.Instruction::Call(1),
          @capwasm.Instruction::Drop,
          // Call fd_close(local 0)
          @capwasm.Instruction::LocalGet(0),
          @capwasm.Instruction::Call(2),
          @capwasm.Instruction::Drop,
          // Allocate 2 bytes via extism alloc(2) -> local 1
          @capwasm.Instruction::I64Const(2L),
          @capwasm.Instruction::Call(3),
          @capwasm.Instruction::LocalSet(1),
          // Copy first 2 bytes from linear memory [128..129] into Extism block
          @capwasm.Instruction::LocalGet(1),
          @capwasm.Instruction::I32Const(128),
          @capwasm.Instruction::I32Load8U(@capwasm.MemArg::new(0, 0)),
          @capwasm.Instruction::Call(4),
          @capwasm.Instruction::LocalGet(1),
          @capwasm.Instruction::I64Const(1L),
          @capwasm.Instruction::I64Add,
          @capwasm.Instruction::I32Const(129),
          @capwasm.Instruction::I32Load8U(@capwasm.MemArg::new(0, 0)),
          @capwasm.Instruction::Call(4),
          // Publish output_set(local 1, 2)
          @capwasm.Instruction::LocalGet(1),
          @capwasm.Instruction::I64Const(2L),
          @capwasm.Instruction::Call(5),
          @capwasm.Instruction::I32Const(0),
          @capwasm.Instruction::End,
        ],
      ),
    ],
    data: [
      @capwasm.DataSegment::new(
        0,
        [@capwasm.Instruction::I32Const(16), @capwasm.Instruction::End],
        guest_path_bytes,
      ),
    ],
  }

  let wasm_bytes = mod_ast.encode_to_bytes()
  let vfs = @capwasm.VirtualFileSystem::new()
  let _ = vfs.create_file("/plugins/doc_reader.wasm", wasm_bytes)
  let _ = vfs.create_file(
    "/host/tenant_a/docs/hello.txt",
    @capwasm.BinaryReader::from_string("OK_FROM_WASI").bytes,
  )

  let manifest = @capwasm.ExtismManifest::new("doc-reader")
    .with_wasm_path("doc-reader", "/plugins/doc_reader.wasm", None)
    .with_mount("/host/tenant_a/docs", "/docs", true)
  let plugin = match
    @capwasm.PluginInstance::load_from_manifest(manifest, vfs) {
    Ok(p) => p
    Err(e) => {
      println("Load error: " + e.to_string())
      assert_true(false)
      return
    }
  }

  let out = plugin.call_string("read_doc", "")
  assert_eq(out, Ok("OK"))
  // Verify guest memory[0] at address 64 still holds the WASI fd (3) and was NOT overwritten by Extism kernel_memory block at handle 64L
  let guest_mem = plugin.instance.get_memory(0).unwrap()
  assert_eq(guest_mem.read_i32(64), Ok(3))
}

///|
test "Extism 1.x Full ABI Contract: SHA-256 NIST Vector & Isolated Kernel Memory" {
  // 1. Verify standard FIPS 180-4 SHA-256 against NIST test vector ("abc")
  let abc_bytes = @capwasm.BinaryReader::from_string("abc").bytes
  let digest = @capwasm.compute_wasm_sha256(abc_bytes)
  assert_eq(
    digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )

  // 2. Verify ExtismKernel operates exclusively on isolated kernel_memory
  let kernel = @capwasm.ExtismKernel::new()
  let handle = kernel
    .alloc_and_write_string(None, "extism-isolated-block")
    .unwrap()
  assert_eq(handle, 64L)
  assert_eq(kernel.read_block_string(handle), Ok("extism-isolated-block"))
}
