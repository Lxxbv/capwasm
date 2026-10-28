// CapWasm: High-Level WebAssembly Plugin Sandbox Runtime
// Coordinates module validation, memory isolation, capability enforcement, and Extism-compatible ABI.

///|
/// PluginConfiguration sets execution boundaries and capability policy for a plugin.
pub(all) struct PluginConfig {
  plugin_id : String
  policy : CapabilityPolicy
  initial_gas : Int32
  vfs : VirtualFileSystem
}

///|
pub fn PluginConfig::new(
  plugin_id : String,
  policy : CapabilityPolicy,
) -> PluginConfig {
  {
    plugin_id,
    policy,
    initial_gas: policy.quota.max_execution_steps,
    vfs: VirtualFileSystem::new(),
  }
}

///|
pub fn PluginConfig::with_vfs(
  self : PluginConfig,
  vfs : VirtualFileSystem,
) -> PluginConfig {
  {
    plugin_id: self.plugin_id,
    policy: self.policy,
    initial_gas: self.initial_gas,
    vfs,
  }
}

///|
/// Execution metrics gathered during plugin invocations.
pub(all) struct PluginMetrics {
  plugin_id : String
  mut total_calls : Int32
  mut total_gas_consumed : Int32
  mut peak_memory_pages : Int32
}

///|
pub fn PluginMetrics::new(plugin_id : String) -> PluginMetrics {
  { plugin_id, total_calls: 0, total_gas_consumed: 0, peak_memory_pages: 0, }
}

///|
/// Sandboxed Plugin Instance holding instantiated runtime state and security monitors.
pub(all) struct PluginInstance {
  config : PluginConfig
  wasm_module : WasmModule
  mut instance : WasmInstance
  sec_guard : PluginSecurityGuard
  linker : Linker
  fd_table : WasiFdTable
  wasi_env : WasiEnvironment
  extism_kernel : ExtismKernel
  metrics : PluginMetrics
}

///|
pub fn PluginInstance::load(
  config : PluginConfig,
  wasm_bytes : Array[Byte],
) -> Result[PluginInstance, SecurityError] {
  // 1. Parse WebAssembly binary module
  let parser = WasmParser::new(wasm_bytes)
  let parsed_mod = match parser.parse_module() {
    Ok(m) => m
    Err(e) =>
      return Err(
        SecurityError::Aborted("Failed to parse WASM module: " + e.to_string()),
      )
  }

  // 2. Validate structural constraints
  let validator = ModuleValidator::new(parsed_mod)
  match validator.validate() {
    Ok(_) => ()
    Err(e) =>
      return Err(
        SecurityError::Aborted("Module validation failed: " + e.to_string()),
      )
  }

  // 3. Setup Security Guard, Linker, WasiEnvironment, ExtismKernel, and HostContext
  let sec_guard = PluginSecurityGuard::new(config.plugin_id, config.policy)
  let linker = Linker::new()
  let fd_table = WasiFdTable::new()
  let wasi_env = WasiEnvironment::new()
  let extism_kernel = ExtismKernel::new()
  let metrics = PluginMetrics::new(config.plugin_id)
  let host_ctx = HostContext::new(config.plugin_id)
  host_ctx.set_guard(sec_guard)

  // 4. Register all default CapWasm, WASI Preview1 (19 syscalls), & Extism (19 syscalls) host imports
  register_capwasm_host_imports(linker, sec_guard, config.vfs)
  register_wasi_preview1_host_functions(
    linker,
    sec_guard,
    config.vfs,
    fd_table,
    wasi_env,
  )
  register_extism_host_functions(linker, extism_kernel, sec_guard)

  // 5. Instantiate Wasm Runtime Instance
  let inst = match
    parsed_mod.instantiate(linker, host_ctx, config.initial_gas) {
    Ok(i) => i
    Err(e) =>
      return Err(
        SecurityError::Aborted("Instantiation failed: " + e.to_string()),
      )
  }

  let initial_pages = match inst.get_memory(0) {
    Ok(mem) => mem.size_in_pages()
    Err(_) => 0
  }
  metrics.peak_memory_pages = initial_pages

  let plugin = {
    config,
    wasm_module: parsed_mod,
    instance: inst,
    sec_guard,
    linker,
    fd_table,
    wasi_env,
    extism_kernel,
    metrics,
  }

  Ok(plugin)
}

///|
/// Loads and instantiates an Extism plugin directly from an `ExtismManifest` and a sandboxed `VirtualFileSystem`.
/// Performs binary fingerprint verification, configures memory/variable/HTTP quotas, injects manifest configs,
/// and mounts virtual guest-to-host directory mappings.
pub fn PluginInstance::load_from_manifest(
  manifest : ExtismManifest,
  vfs : VirtualFileSystem,
) -> Result[PluginInstance, SecurityError] {
  if manifest.wasm_sources.length() == 0 {
    return Err(
      SecurityError::Aborted("ExtismManifest contains no Wasm module sources"),
    )
  }

  // Extract primary Wasm module bytes and verify optional integrity hash
  let (wasm_bytes, expected_hash) = match manifest.wasm_sources[0] {
    ExtismWasmSource::InlineBytes(_, bytes, hash) => (bytes, hash)
    ExtismWasmSource::VfsPath(_, path, hash) =>
      match vfs.read_file(path) {
        Ok(b) => (b, hash)
        Err(e) =>
          return Err(
            SecurityError::Aborted(
              "Failed to read Wasm module from VFS path '" +
              path +
              "': " +
              e.to_string(),
            ),
          )
      }
  }

  match expected_hash {
    Some(h) =>
      if not(verify_wasm_fingerprint(wasm_bytes, h)) {
        return Err(
          SecurityError::PermissionDenied(
            "Wasm binary fingerprint mismatch: expected " +
            h +
            ", got " +
            compute_wasm_fingerprint(wasm_bytes),
          ),
        )
      }
    None => ()
  }

  let policy = manifest.to_capability_policy()
  let cfg = PluginConfig::new(manifest.plugin_id, policy).with_vfs(vfs)
  let plugin = match PluginInstance::load(cfg, wasm_bytes) {
    Ok(p) => p
    Err(e) => return Err(e)
  }

  // Apply ExtismManifest memory options, config entries, and virtual directory mounts
  plugin.extism_kernel.max_var_bytes = manifest.memory.max_var_bytes
  plugin.extism_kernel.max_http_response_bytes = manifest.memory.max_http_response_bytes
  for item in manifest.config {
    let (k, v) = item
    plugin.set_extism_config(k, v)
  }
  for mount in manifest.allowed_paths {
    plugin.wasi_env.add_mount(mount)
  }

  Ok(plugin)
}

///|
fn register_capwasm_host_imports(
  linker : Linker,
  sec_guard : PluginSecurityGuard,
  vfs : VirtualFileSystem,
) -> Unit {
  // capwasm::log(level: i32, ptr: i32, len: i32) -> void
  let log_sig = FuncType::new(
    [ValueType::I32, ValueType::I32, ValueType::I32],
    [],
  )
  linker.register_func(
    "capwasm",
    "log",
    HostFunction::new(log_sig, fn(ctx, args) {
      let level = match args[0] {
        Value::I32(v) => v
        _ => 0
      }
      let ptr = match args[1] {
        Value::I32(v) => v
        _ => 0
      }
      let len = match args[2] {
        Value::I32(v) => v
        _ => 0
      }
      match ctx.get_memory() {
        Ok(mem) => {
          let msg = match mem.read_string(ptr, len) {
            Ok(s) => s
            Err(_) => "<invalid utf8>"
          }
          println("[PluginLog level=" + level.to_string() + "] " + msg)
          Ok([])
        }
        Err(e) => Err(e)
      }
    }),
  )

  // capwasm::fs_read(path_ptr: i32, path_len: i32, dst_buf: i32, max_len: i32) -> i32
  let fs_read_sig = FuncType::new(
    [ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32],
    [ValueType::I32],
  )
  linker.register_func(
    "capwasm",
    "fs_read",
    HostFunction::new(fs_read_sig, fn(ctx, args) {
      let path_ptr = match args[0] {
        Value::I32(v) => v
        _ => 0
      }
      let path_len = match args[1] {
        Value::I32(v) => v
        _ => 0
      }
      let dst_buf = match args[2] {
        Value::I32(v) => v
        _ => 0
      }
      let max_len = match args[3] {
        Value::I32(v) => v
        _ => 0
      }

      let mem = match ctx.get_memory() {
        Ok(m) => m
        Err(e) => return Err(e)
      }

      let raw_path = match mem.read_string(path_ptr, path_len) {
        Ok(s) => s
        Err(e) => return Err(e)
      }

      // Capability verification
      match sec_guard.check_fs_read(raw_path) {
        Ok(_) => ()
        Err(_) => return Ok([Value::I32(-1)]) // Access denied
      }

      // Read from sandboxed VFS
      match vfs.read_file(raw_path) {
        Ok(bytes) => {
          let to_copy = if bytes.length() < max_len {
            bytes.length()
          } else {
            max_len
          }
          let slice = Array::make(to_copy, b'\x00')
          for i = 0; i < to_copy; i = i + 1 {
            slice[i] = bytes[i]
          }
          match mem.write_bytes(dst_buf, slice) {
            Ok(_) => Ok([Value::I32(to_copy)])
            Err(e) => Err(e)
          }
        }
        Err(_) => Ok([Value::I32(-2)]) // Not found
      }
    }),
  )

  // capwasm::fs_write(path_ptr: i32, path_len: i32, src_buf: i32, len: i32) -> i32
  let fs_write_sig = FuncType::new(
    [ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32],
    [ValueType::I32],
  )
  linker.register_func(
    "capwasm",
    "fs_write",
    HostFunction::new(fs_write_sig, fn(ctx, args) {
      let path_ptr = match args[0] {
        Value::I32(v) => v
        _ => 0
      }
      let path_len = match args[1] {
        Value::I32(v) => v
        _ => 0
      }
      let src_buf = match args[2] {
        Value::I32(v) => v
        _ => 0
      }
      let len = match args[3] {
        Value::I32(v) => v
        _ => 0
      }

      let mem = match ctx.get_memory() {
        Ok(m) => m
        Err(e) => return Err(e)
      }

      let raw_path = match mem.read_string(path_ptr, path_len) {
        Ok(s) => s
        Err(e) => return Err(e)
      }

      // Capability verification
      match sec_guard.check_fs_write(raw_path) {
        Ok(_) => ()
        Err(_) => return Ok([Value::I32(-1)]) // Write forbidden
      }

      let bytes = match mem.read_bytes(src_buf, len) {
        Ok(b) => b
        Err(e) => return Err(e)
      }

      match vfs.write_file(raw_path, bytes) {
        Ok(written) => Ok([Value::I32(written)])
        Err(_) => Ok([Value::I32(-3)])
      }
    }),
  )

  // capwasm::net_fetch(host_ptr: i32, host_len: i32) -> i32
  let net_sig = FuncType::new([ValueType::I32, ValueType::I32], [ValueType::I32])
  linker.register_func(
    "capwasm",
    "net_fetch",
    HostFunction::new(net_sig, fn(ctx, args) {
      let host_ptr = match args[0] {
        Value::I32(v) => v
        _ => 0
      }
      let host_len = match args[1] {
        Value::I32(v) => v
        _ => 0
      }
      let mem = match ctx.get_memory() {
        Ok(m) => m
        Err(e) => return Err(e)
      }
      let host_str = match mem.read_string(host_ptr, host_len) {
        Ok(s) => s
        Err(e) => return Err(e)
      }

      match sec_guard.check_network(host_str) {
        Ok(_) => Ok([Value::I32(200)]) // HTTP 200 OK
        Err(_) => Ok([Value::I32(403)]) // Forbidden
      }
    }),
  )
}

///|
/// Invokes an exported Wasm function by name with primitive typed parameters.
pub fn PluginInstance::call(
  self : PluginInstance,
  func_name : String,
  args : Array[Value],
) -> Result[Array[Value], SecurityError] {
  self.metrics.total_calls = self.metrics.total_calls + 1

  match self.instance.call_exported(self.wasm_module, func_name, args) {
    Ok(results) => {
      let current_pages = match self.instance.get_memory(0) {
        Ok(m) => m.size_in_pages()
        Err(_) => 0
      }
      if current_pages > self.metrics.peak_memory_pages {
        self.metrics.peak_memory_pages = current_pages
      }
      self.metrics.total_gas_consumed = self.instance.get_consumed_gas()
      Ok(results)
    }
    Err(trap) =>
      match trap {
        Trap::GasExhausted(_, _) => {
          let _ = self.sec_guard.consume_steps(
            self.config.policy.quota.max_execution_steps + 1,
          )
          Err(
            SecurityError::OutOfQuota(
              "Instruction limit exceeded during call to: " + func_name,
            ),
          )
        }
        Trap::MemoryOutOfBounds(off, len) =>
          Err(SecurityError::MemoryOutOfBounds(off, len))
        Trap::HostError(msg) => Err(SecurityError::Aborted("Host trap: " + msg))
        _ =>
          Err(
            SecurityError::Aborted(
              "Wasm execution trapped: " + trap.to_string(),
            ),
          )
      }
  }
}

///|
/// Extism Host ABI & Slice ABI dispatcher:
/// Supports both:
/// 1. Standard Extism Guest PDK ABI `() -> i32` where the guest interacts via `extism:host/env`
///    (`input_length`, `input_load_u8`, `alloc`, `store_u8`, `output_set`, `error_set`, etc.).
/// 2. Direct Linear Memory Slice ABI `(ptr: i32, len: i32) -> i32` for lightweight Wasm modules.
pub fn PluginInstance::call_extism(
  self : PluginInstance,
  func_name : String,
  input_data : Array[Byte],
) -> Result[Array[Byte], SecurityError] {
  let mem = match self.instance.get_memory(0) {
    Ok(m) => m
    Err(_) =>
      return Err(
        SecurityError::Aborted("Plugin instance has no exported memory"),
      )
  }

  // Initialize Extism Kernel input channel for this invocation
  self.extism_kernel.begin_call(input_data)

  // Inspect exported function signature to determine whether it uses 0-arg Extism PDK ABI or 2-arg Slice ABI
  let param_count = match self.wasm_module.find_func_export(func_name) {
    Some(fidx) =>
      match self.wasm_module.get_func_type(fidx) {
        Ok(ft) => ft.params.length()
        Err(_) => 0
      }
    None =>
      return Err(
        SecurityError::Aborted("Exported function not found: " + func_name),
      )
  }

  if param_count == 0 {
    // Standard Extism Guest PDK ABI: `func() -> i32`
    let ret = match self.call(func_name, []) {
      Ok(r) => r
      Err(e) => return Err(e)
    }

    match self.extism_kernel.error_message {
      Some(err_msg) =>
        return Err(SecurityError::Aborted("Extism plugin error: " + err_msg))
      None => ()
    }

    if ret.length() > 0 {
      match ret[0] {
        Value::I32(rc) =>
          if rc != 0 {
            return Err(
              SecurityError::Aborted(
                "Extism plugin returned non-zero status code: " + rc.to_string(),
              ),
            )
          }
        _ => ()
      }
    }

    let out_off = self.extism_kernel.output_offset.to_int()
    let out_len = self.extism_kernel.output_length.to_int()
    if out_len <= 0 {
      return Ok([])
    }
    match mem.read_bytes(out_off, out_len) {
      Ok(out_bytes) => return Ok(out_bytes)
      Err(e) =>
        return Err(
          SecurityError::Aborted(
            "Failed to read Extism output buffer: " + e.to_string(),
          ),
        )
    }
  }

  // Direct Slice ABI fallback: write input at offset 1024 and invoke `func(offset, length)`
  let input_offset = 1024
  let required_bytes = input_offset + input_data.length() + 1024
  if required_bytes > mem.size_in_bytes() {
    let pages_needed = (required_bytes - mem.size_in_bytes() + 65535) / 65536
    let _ = mem.grow(pages_needed)
  }

  match mem.write_bytes(input_offset, input_data) {
    Ok(_) => ()
    Err(e) =>
      return Err(
        SecurityError::Aborted("Failed to write input slice: " + e.to_string()),
      )
  }

  let args = [Value::I32(input_offset), Value::I32(input_data.length())]
  let ret = match self.call(func_name, args) {
    Ok(r) => r
    Err(e) => return Err(e)
  }

  // If the slice function also set output via extism:host/env::output_set, prefer that
  if self.extism_kernel.output_length > 0L {
    let out_off = self.extism_kernel.output_offset.to_int()
    let out_len = self.extism_kernel.output_length.to_int()
    match mem.read_bytes(out_off, out_len) {
      Ok(out_bytes) => return Ok(out_bytes)
      Err(e) =>
        return Err(
          SecurityError::Aborted(
            "Failed to read Extism output slice: " + e.to_string(),
          ),
        )
    }
  }

  if ret.length() == 0 {
    return Ok([])
  }

  match ret[0] {
    Value::I32(out_off) => {
      if out_off < 0 {
        return Ok([])
      }
      let out_len = if ret.length() > 1 {
        match ret[1] {
          Value::I32(l) => l
          _ => 0
        }
      } else {
        match mem.read_i32(out_off) {
          Ok(l) => l
          Err(_) => 0
        }
      }

      let read_offset = if ret.length() > 1 { out_off } else { out_off + 4 }
      match mem.read_bytes(read_offset, out_len) {
        Ok(out_bytes) => Ok(out_bytes)
        Err(e) =>
          Err(
            SecurityError::Aborted(
              "Failed to read output slice: " + e.to_string(),
            ),
          )
      }
    }
    _ => Ok([])
  }
}

///|
/// Sets an Extism plugin configuration key-value pair accessible via `extism:host/env::config_get`.
pub fn PluginInstance::set_extism_config(
  self : PluginInstance,
  key : String,
  value : String,
) -> Unit {
  self.extism_kernel.set_config(key, value)
}

///|
/// Sets a persistent Extism plugin variable accessible via `extism:host/env::var_get`.
pub fn PluginInstance::set_extism_var(
  self : PluginInstance,
  key : String,
  value : Array[Byte],
) -> Unit {
  self.extism_kernel.set_var(key, value)
}

///|
/// Retrieves a persistent Extism plugin variable modified via `extism:host/env::var_set`.
pub fn PluginInstance::get_extism_var(
  self : PluginInstance,
  key : String,
) -> Array[Byte]? {
  self.extism_kernel.get_var(key)
}

///|
/// Returns structured log records emitted via `extism:host/env::log_*`.
pub fn PluginInstance::get_extism_logs(
  self : PluginInstance,
) -> Array[(String, String)] {
  self.extism_kernel.logs
}

///|
/// Convenient helper for string-based Extism plugin invocation.
pub fn PluginInstance::call_string(
  self : PluginInstance,
  func_name : String,
  input_str : String,
) -> Result[String, SecurityError] {
  let in_bytes = Array::make(input_str.length(), b'\x00')
  for i = 0; i < input_str.length(); i = i + 1 {
    in_bytes[i] = input_str[i].to_int().to_byte()
  }

  let out_bytes = match self.call_extism(func_name, in_bytes) {
    Ok(b) => b
    Err(e) => return Err(e)
  }

  let buf = StringBuilder::new()
  for b in out_bytes {
    buf.write_char(b.to_int().unsafe_to_char())
  }
  Ok(buf.to_string())
}

///|
/// Resets plugin instance for fresh reuse without re-parsing bytecode.
pub fn PluginInstance::reset(
  self : PluginInstance,
) -> Result[Unit, SecurityError] {
  let host_ctx = HostContext::new(self.config.plugin_id)
  host_ctx.set_guard(self.sec_guard)
  let fresh_inst = match
    self.wasm_module.instantiate(self.linker, host_ctx, self.config.initial_gas) {
    Ok(i) => i
    Err(e) =>
      return Err(
        SecurityError::Aborted("Failed to reset instance: " + e.to_string()),
      )
  }
  self.instance = fresh_inst
  Ok(())
}

///|
pub fn PluginInstance::get_audit_logs(
  self : PluginInstance,
) -> Array[AuditRecord] {
  self.sec_guard.get_audit_logs()
}

///|
pub fn PluginInstance::get_metrics(self : PluginInstance) -> PluginMetrics {
  self.metrics
}
