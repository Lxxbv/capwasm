// CapWasm: Extism Host Kernel & PDK ABI Compatibility Layer (`extism:host/env`)
// Implements the standard Extism Kernel memory allocator, input/output channels,
// per-plugin Config & Var stores, and capability-gated HTTP & Logging host functions.

///|
/// ExtismMemBlock represents an allocated memory block tracked by the Extism Kernel.
pub(all) struct ExtismMemBlock {
  offset : Int64
  length : Int64
  mut active : Bool
} derive(Debug, Eq)

///|
pub impl Show for ExtismMemBlock with fn output(self, logger) {
  logger.write_string(
    "ExtismMemBlock(offset=\{self.offset}, length=\{self.length}, active=\{self.active})",
  )
}

///|
/// ExtismKernel manages the host-side state and memory allocation table for Extism PDK plugins.
pub(all) struct ExtismKernel {
  blocks : Array[ExtismMemBlock]
  mut next_alloc_offset : Int64
  mut input_data : Array[Byte]
  mut output_offset : Int64
  mut output_length : Int64
  mut error_message : String?
  configs : Array[(String, String)]
  vars : Array[(String, Array[Byte])]
  logs : Array[(String, String)]
  mut last_http_status : Int32
}

///|
pub fn ExtismKernel::new() -> ExtismKernel {
  {
    blocks: [],
    // Start Extism kernel heap at 8192 (8 KiB) to avoid colliding with low data segments
    next_alloc_offset: 8192L,
    input_data: [],
    output_offset: 0L,
    output_length: 0L,
    error_message: None,
    configs: [],
    vars: [],
    logs: [],
    last_http_status: 0,
  }
}

///|
/// Resets per-invocation I/O state before executing an Extism plugin entrypoint.
pub fn ExtismKernel::begin_call(
  self : ExtismKernel,
  input : Array[Byte],
) -> Unit {
  self.input_data = input
  self.output_offset = 0L
  self.output_length = 0L
  self.error_message = None
  self.last_http_status = 0
}

///|
/// Sets a configuration key-value pair accessible via `extism:host/env::config_get`.
pub fn ExtismKernel::set_config(
  self : ExtismKernel,
  key : String,
  value : String,
) -> Unit {
  for i = 0; i < self.configs.length(); i = i + 1 {
    let (k, _) = self.configs[i]
    if k == key {
      self.configs[i] = (key, value)
      return
    }
  }
  self.configs.push((key, value))
}

///|
/// Gets a configuration value by key.
pub fn ExtismKernel::get_config(self : ExtismKernel, key : String) -> String? {
  for item in self.configs {
    let (k, v) = item
    if k == key {
      return Some(v)
    }
  }
  None
}

///|
/// Sets a persistent plugin variable accessible via `extism:host/env::var_get` / `var_set`.
pub fn ExtismKernel::set_var(
  self : ExtismKernel,
  key : String,
  value : Array[Byte],
) -> Unit {
  for i = 0; i < self.vars.length(); i = i + 1 {
    let (k, _) = self.vars[i]
    if k == key {
      self.vars[i] = (key, value)
      return
    }
  }
  self.vars.push((key, value))
}

///|
/// Gets a persistent plugin variable by key.
pub fn ExtismKernel::get_var(self : ExtismKernel, key : String) -> Array[Byte]? {
  for item in self.vars {
    let (k, v) = item
    if k == key {
      return Some(v)
    }
  }
  None
}

///|
/// Allocates a block of `length` bytes in guest linear memory, growing pages if needed
/// while enforcing `PluginSecurityGuard::check_memory_grow`.
pub fn ExtismKernel::alloc(
  self : ExtismKernel,
  mem : LinearMemory,
  sec_guard : PluginSecurityGuard?,
  length : Int64,
) -> Result[Int64, Trap] {
  if length <= 0L {
    return Ok(0L)
  }

  // 1. Check if an inactive block of sufficient size can be reused
  for i = 0; i < self.blocks.length(); i = i + 1 {
    let blk = self.blocks[i]
    if not(blk.active) && blk.length >= length {
      self.blocks[i].active = true
      let _ = mem.fill(blk.offset.to_int(), b'\x00', length.to_int())
      return Ok(blk.offset)
    }
  }

  // 2. Bump-allocate a new block aligned to 8 bytes
  let offset = self.next_alloc_offset
  let aligned_len = (length + 7L) & -8L
  let end_byte = (offset + aligned_len).to_int()

  if end_byte > mem.size_in_bytes() {
    let needed_bytes = end_byte - mem.size_in_bytes()
    let delta_pages = (needed_bytes + page_size - 1) / page_size
    let target_pages = mem.size_in_pages() + delta_pages
    match sec_guard {
      Some(g) =>
        match g.check_memory_grow(target_pages) {
          Ok(_) => ()
          Err(_) => return Ok(0L) // Allocation denied by capability quota
        }
      None => ()
    }
    let prev = mem.grow(delta_pages)
    if prev < 0 {
      return Ok(0L)
    }
  }

  self.next_alloc_offset = offset + aligned_len
  let _ = mem.fill(offset.to_int(), b'\x00', length.to_int())
  self.blocks.push({ offset, length, active: true, })
  Ok(offset)
}

///|
/// Frees an allocated memory block in the Extism Kernel table.
pub fn ExtismKernel::free(self : ExtismKernel, offset : Int64) -> Unit {
  for i = 0; i < self.blocks.length(); i = i + 1 {
    if self.blocks[i].offset == offset && self.blocks[i].active {
      self.blocks[i].active = false
      return
    }
  }
}

///|
/// Returns the byte length of an active memory block at `offset`, or 0L if unknown/freed.
pub fn ExtismKernel::block_length(self : ExtismKernel, offset : Int64) -> Int64 {
  for blk in self.blocks {
    if blk.offset == offset && blk.active {
      return blk.length
    }
  }
  0L
}

///|
/// Reads a UTF-8 string from an Extism memory block handle.
pub fn ExtismKernel::read_block_string(
  self : ExtismKernel,
  mem : LinearMemory,
  offset : Int64,
) -> Result[String, Trap] {
  let len = self.block_length(offset)
  if len <= 0L {
    return Ok("")
  }
  mem.read_string(offset.to_int(), len.to_int())
}

///|
/// Allocates a new Extism memory block and writes a string into it.
pub fn ExtismKernel::alloc_and_write_string(
  self : ExtismKernel,
  mem : LinearMemory,
  sec_guard : PluginSecurityGuard?,
  str : String,
) -> Result[Int64, Trap] {
  let len = str.length().to_int64()
  if len == 0L {
    return Ok(0L)
  }
  let off = match self.alloc(mem, sec_guard, len) {
    Ok(o) => o
    Err(e) => return Err(e)
  }
  if off == 0L {
    return Ok(0L)
  }
  let _ = match mem.write_string(off.to_int(), str) {
    Ok(w) => w
    Err(e) => return Err(e)
  }
  Ok(off)
}

///|
/// Allocates a new Extism memory block and writes a byte array into it.
pub fn ExtismKernel::alloc_and_write_bytes(
  self : ExtismKernel,
  mem : LinearMemory,
  sec_guard : PluginSecurityGuard?,
  bytes : Array[Byte],
) -> Result[Int64, Trap] {
  let len = bytes.length().to_int64()
  if len == 0L {
    return Ok(0L)
  }
  let off = match self.alloc(mem, sec_guard, len) {
    Ok(o) => o
    Err(e) => return Err(e)
  }
  if off == 0L {
    return Ok(0L)
  }
  match mem.write_bytes(off.to_int(), bytes) {
    Ok(_) => Ok(off)
    Err(e) => Err(e)
  }
}

///|
/// Extracts the hostname from an Extism HTTP request descriptor string (URL or JSON).
pub fn extract_host_from_extism_request(req : String) -> String {
  // Support both raw URL ("https://api.example.com/v1/...") and JSON ({"url":"https://api.example.com/..."})
  let mut start = 0
  let len = req.length()
  // Look for "://"
  let mut found_scheme = false
  for i = 0; i + 2 < len; i = i + 1 {
    if req[i] == ':' && req[i + 1] == '/' && req[i + 2] == '/' {
      start = i + 3
      found_scheme = true
      break
    }
  }
  if not(found_scheme) {
    return req.trim().to_string()
  }
  let buf = StringBuilder::new()
  for i = start; i < len; i = i + 1 {
    let ch = req[i]
    if ch == '/' ||
      ch == ':' ||
      ch == '"' ||
      ch == '\'' ||
      ch == ' ' ||
      ch == '}' {
      break
    }
    buf.write_char(ch.unsafe_to_char())
  }
  buf.to_string()
}

///|
/// Registers the complete standard `extism:host/env` (and alias `env`) host functions into `Linker`.
pub fn register_extism_host_functions(
  linker : Linker,
  kernel : ExtismKernel,
  sec_guard : PluginSecurityGuard,
) -> Unit {
  let namespaces = ["extism:host/env", "env"]
  for ns in namespaces {
    // 1. input_length() -> i64
    linker.register_func(
      ns,
      "input_length",
      HostFunction::new(FuncType::new([], [ValueType::I64]), fn(_ctx, _args) {
        Ok([Value::I64(kernel.input_data.length().to_int64())])
      }),
    )

    // 2. input_load_u8(offset: i64) -> i32
    linker.register_func(
      ns,
      "input_load_u8",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I32]), fn(
        _ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v.to_int()
          Value::I32(v) => v
          _ => 0
        }
        if off < 0 || off >= kernel.input_data.length() {
          Ok([Value::I32(0)])
        } else {
          Ok([Value::I32(kernel.input_data[off].to_int() & 0xFF)])
        }
      }),
    )

    // 3. input_load_u64(offset: i64) -> i64
    linker.register_func(
      ns,
      "input_load_u64",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I64]), fn(
        _ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v.to_int()
          Value::I32(v) => v
          _ => 0
        }
        if off < 0 || off + 8 > kernel.input_data.length() {
          Ok([Value::I64(0L)])
        } else {
          let mut acc = 0L
          for i = 0; i < 8; i = i + 1 {
            let b = (kernel.input_data[off + i].to_int() & 0xFF).to_int64()
            acc = acc | (b << (i * 8))
          }
          Ok([Value::I64(acc)])
        }
      }),
    )

    // 4. alloc(length: i64) -> i64
    linker.register_func(
      ns,
      "alloc",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I64]), fn(
        ctx,
        args,
      ) {
        let len = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let off = match kernel.alloc(mem, Some(sec_guard), len) {
          Ok(o) => o
          Err(e) => return Err(e)
        }
        Ok([Value::I64(off)])
      }),
    )

    // 5. free(offset: i64) -> void
    linker.register_func(
      ns,
      "free",
      HostFunction::new(FuncType::new([ValueType::I64], []), fn(_ctx, args) {
        let off = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        kernel.free(off)
        Ok([])
      }),
    )

    // 6. length(offset: i64) -> i64
    linker.register_func(
      ns,
      "length",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I64]), fn(
        _ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        Ok([Value::I64(kernel.block_length(off))])
      }),
    )

    // 7. length_unsafe(offset: i64) -> i64
    linker.register_func(
      ns,
      "length_unsafe",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I64]), fn(
        _ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        Ok([Value::I64(kernel.block_length(off))])
      }),
    )

    // 8. load_u8(offset: i64) -> i32
    linker.register_func(
      ns,
      "load_u8",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I32]), fn(
        ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v.to_int()
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let b = match mem.read_u8(off) {
          Ok(v) => v
          Err(e) => return Err(e)
        }
        Ok([Value::I32(b)])
      }),
    )

    // 9. load_u64(offset: i64) -> i64
    linker.register_func(
      ns,
      "load_u64",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I64]), fn(
        ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v.to_int()
          Value::I32(v) => v
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let v = match mem.read_i64(off) {
          Ok(val) => val
          Err(e) => return Err(e)
        }
        Ok([Value::I64(v)])
      }),
    )

    // 10. store_u8(offset: i64, val: i32) -> void
    linker.register_func(
      ns,
      "store_u8",
      HostFunction::new(FuncType::new([ValueType::I64, ValueType::I32], []), fn(
        ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v.to_int()
          Value::I32(v) => v
          _ => 0
        }
        let val = match args[1] {
          Value::I32(v) => v
          Value::I64(v) => v.to_int()
          _ => 0
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        match mem.write_u8(off, val) {
          Ok(_) => Ok([])
          Err(e) => Err(e)
        }
      }),
    )

    // 11. store_u64(offset: i64, val: i64) -> void
    linker.register_func(
      ns,
      "store_u64",
      HostFunction::new(FuncType::new([ValueType::I64, ValueType::I64], []), fn(
        ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v.to_int()
          Value::I32(v) => v
          _ => 0
        }
        let val = match args[1] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        match mem.write_i64(off, val) {
          Ok(_) => Ok([])
          Err(e) => Err(e)
        }
      }),
    )

    // 12. output_set(offset: i64, length: i64) -> void
    linker.register_func(
      ns,
      "output_set",
      HostFunction::new(FuncType::new([ValueType::I64, ValueType::I64], []), fn(
        _ctx,
        args,
      ) {
        let off = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        let len = match args[1] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        kernel.output_offset = off
        kernel.output_length = len
        Ok([])
      }),
    )

    // 13. error_set(offset: i64) -> void
    linker.register_func(
      ns,
      "error_set",
      HostFunction::new(FuncType::new([ValueType::I64], []), fn(ctx, args) {
        let off = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let msg = match kernel.read_block_string(mem, off) {
          Ok(s) => s
          Err(_) => "Unknown Extism plugin error"
        }
        kernel.error_message = Some(msg)
        Ok([])
      }),
    )

    // 14. config_get(key_offset: i64) -> i64
    linker.register_func(
      ns,
      "config_get",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I64]), fn(
        ctx,
        args,
      ) {
        let key_off = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let key = match kernel.read_block_string(mem, key_off) {
          Ok(s) => s
          Err(e) => return Err(e)
        }
        match kernel.get_config(key) {
          Some(val) =>
            match kernel.alloc_and_write_string(mem, Some(sec_guard), val) {
              Ok(off) => Ok([Value::I64(off)])
              Err(e) => Err(e)
            }
          None => Ok([Value::I64(0L)])
        }
      }),
    )

    // 15. var_get(key_offset: i64) -> i64
    linker.register_func(
      ns,
      "var_get",
      HostFunction::new(FuncType::new([ValueType::I64], [ValueType::I64]), fn(
        ctx,
        args,
      ) {
        let key_off = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let key = match kernel.read_block_string(mem, key_off) {
          Ok(s) => s
          Err(e) => return Err(e)
        }
        match kernel.get_var(key) {
          Some(bytes) =>
            match kernel.alloc_and_write_bytes(mem, Some(sec_guard), bytes) {
              Ok(off) => Ok([Value::I64(off)])
              Err(e) => Err(e)
            }
          None => Ok([Value::I64(0L)])
        }
      }),
    )

    // 16. var_set(key_offset: i64, val_offset: i64) -> void
    linker.register_func(
      ns,
      "var_set",
      HostFunction::new(FuncType::new([ValueType::I64, ValueType::I64], []), fn(
        ctx,
        args,
      ) {
        let key_off = match args[0] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        let val_off = match args[1] {
          Value::I64(v) => v
          Value::I32(v) => v.to_int64()
          _ => 0L
        }
        let mem = match ctx.get_memory() {
          Ok(m) => m
          Err(e) => return Err(e)
        }
        let key = match kernel.read_block_string(mem, key_off) {
          Ok(s) => s
          Err(e) => return Err(e)
        }
        let val_len = kernel.block_length(val_off)
        if val_off == 0L || val_len <= 0L {
          kernel.set_var(key, [])
          return Ok([])
        }
        let bytes = match mem.read_bytes(val_off.to_int(), val_len.to_int()) {
          Ok(b) => b
          Err(e) => return Err(e)
        }
        kernel.set_var(key, bytes)
        Ok([])
      }),
    )

    // 17. http_request(req_offset: i64, body_offset: i64) -> i64 (Capability-Gated!)
    linker.register_func(
      ns,
      "http_request",
      HostFunction::new(
        FuncType::new([ValueType::I64, ValueType::I64], [ValueType::I64]),
        fn(ctx, args) {
          let req_off = match args[0] {
            Value::I64(v) => v
            Value::I32(v) => v.to_int64()
            _ => 0L
          }
          let mem = match ctx.get_memory() {
            Ok(m) => m
            Err(e) => return Err(e)
          }
          let req_str = match kernel.read_block_string(mem, req_off) {
            Ok(s) => s
            Err(e) => return Err(e)
          }
          let host = extract_host_from_extism_request(req_str)
          match sec_guard.check_network(host) {
            Ok(_) => {
              kernel.last_http_status = 200
              let resp = "{\"status\":200,\"host\":\"" +
                host +
                "\",\"ok\":true}"
              match kernel.alloc_and_write_string(mem, Some(sec_guard), resp) {
                Ok(off) => Ok([Value::I64(off)])
                Err(e) => Err(e)
              }
            }
            Err(_) => {
              kernel.last_http_status = 403
              Ok([Value::I64(0L)])
            }
          }
        },
      ),
    )

    // 18. http_status_code() -> i32
    linker.register_func(
      ns,
      "http_status_code",
      HostFunction::new(FuncType::new([], [ValueType::I32]), fn(_ctx, _args) {
        Ok([Value::I32(kernel.last_http_status)])
      }),
    )

    // 19. log_info / log_debug / log_warn / log_error (offset: i64) -> void
    let log_levels = [
      ("log_info", "INFO"),
      ("log_debug", "DEBUG"),
      ("log_warn", "WARN"),
      ("log_error", "ERROR"),
    ]
    for item in log_levels {
      let (fn_name, level_tag) = item
      linker.register_func(
        ns,
        fn_name,
        HostFunction::new(FuncType::new([ValueType::I64], []), fn(ctx, args) {
          let off = match args[0] {
            Value::I64(v) => v
            Value::I32(v) => v.to_int64()
            _ => 0L
          }
          let mem = match ctx.get_memory() {
            Ok(m) => m
            Err(e) => return Err(e)
          }
          let msg = match kernel.read_block_string(mem, off) {
            Ok(s) => s
            Err(_) => "<invalid log block>"
          }
          kernel.logs.push((level_tag, msg))
          Ok([])
        }),
      )
    }
  }
}
