// CapWasm: High-Level WebAssembly Plugin Sandbox Runtime
// Coordinates module validation, memory isolation, capability enforcement, and Extism-compatible ABI.

///|
/// PluginConfiguration sets execution boundaries and capability policy for a plugin.
pub(all) struct PluginConfig {
  plugin_id : String
  policy : CapabilityPolicy
  initial_gas : Int
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
  mut total_calls : Int
  mut total_gas_consumed : Int
  mut peak_memory_pages : Int
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

  // 3. Setup Security Guard, Linker, and HostContext
  let sec_guard = PluginSecurityGuard::new(config.plugin_id, config.policy)
  let linker = Linker::new()
  let fd_table = WasiFdTable::new()
  let metrics = PluginMetrics::new(config.plugin_id)
  let host_ctx = HostContext::new(config.plugin_id)
  host_ctx.set_guard(sec_guard)

  // 4. Instantiate Wasm Runtime Instance
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
    metrics,
  }

  plugin.register_default_host_imports()
  Ok(plugin)
}

///|
fn PluginInstance::register_default_host_imports(self : PluginInstance) -> Unit {
  let sec_guard = self.sec_guard
  let vfs = self.config.vfs
  let fd_table = self.fd_table

  // capwasm::log(level: i32, ptr: i32, len: i32) -> void
  let log_sig = FuncType::new(
    [ValueType::I32, ValueType::I32, ValueType::I32],
    [],
  )
  self.linker.register_func(
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
  self.linker.register_func(
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
  self.linker.register_func(
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
  self.linker.register_func(
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

  // wasi_snapshot_preview1::fd_write(fd: i32, iovs_ptr: i32, iovs_len: i32, nwritten_ptr: i32) -> i32
  let wasi_write_sig = FuncType::new(
    [ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32],
    [ValueType::I32],
  )
  self.linker.register_func(
    "wasi_snapshot_preview1",
    "fd_write",
    HostFunction::new(wasi_write_sig, fn(ctx, args) {
      let fd = match args[0] {
        Value::I32(v) => v
        _ => 0
      }
      let iovs_ptr = match args[1] {
        Value::I32(v) => v
        _ => 0
      }
      let iovs_len = match args[2] {
        Value::I32(v) => v
        _ => 0
      }
      let nwritten_ptr = match args[3] {
        Value::I32(v) => v
        _ => 0
      }

      let mem = match ctx.get_memory() {
        Ok(m) => m
        Err(e) => return Err(e)
      }

      let mut total_written = 0
      for i = 0; i < iovs_len; i = i + 1 {
        let base_off = iovs_ptr + i * 8
        let buf_ptr = match mem.read_i32(base_off) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let buf_len = match mem.read_i32(base_off + 4) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        let bytes = match mem.read_bytes(buf_ptr, buf_len) {
          Ok(b) => b
          Err(e) => return Err(e)
        }
        match fd_table.write(fd, bytes) {
          Ok(w) => total_written = total_written + w
          Err(errno) => return Ok([Value::I32(errno)])
        }
      }

      let _ = mem.write_i32(nwritten_ptr, total_written)
      Ok([Value::I32(wasi_errno_success)])
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
/// Extism-style ABI: invokes an exported function by transferring an input byte buffer
/// and receiving an output byte buffer through sandboxed linear memory.
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

  // Extism protocol: write input at offset 1024 (safely past stack base)
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

  // Invoke target function with (offset, length)
  let args = [Value::I32(input_offset), Value::I32(input_data.length())]
  let ret = match self.call(func_name, args) {
    Ok(r) => r
    Err(e) => return Err(e)
  }

  // Return value is output offset or packed offset+length
  if ret.length() == 0 {
    return Ok([])
  }

  match ret[0] {
    Value::I32(out_off) => {
      if out_off < 0 {
        return Ok([])
      }
      // Output length stored at out_off or 2nd return value
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
