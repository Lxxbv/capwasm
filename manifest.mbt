// CapWasm: Extism Manifest Specification, JSON Parser, Binary Integrity Hash & Path Mount Resolver
// Implements standard Extism Manifest parsing, host-to-guest path virtualization, and quota mapping.

///|
/// ExtismMemoryOptions defines memory and state buffer quotas in an Extism Manifest.
pub(all) struct ExtismMemoryOptions {
  max_pages : Int32
  max_http_response_bytes : Int32
  max_var_bytes : Int32
} derive(Debug, Eq)

///|
pub fn ExtismMemoryOptions::default() -> ExtismMemoryOptions {
  {
    max_pages: 16,
    max_http_response_bytes: 1048576, // 1 MiB default HTTP response ceiling
    max_var_bytes: 1048576, // 1 MiB default persistent var ceiling
  }
}

///|
/// Normalizes a mount path (converting backslashes to `/`, ensuring leading `/`,
/// and removing trailing `/` unless root `/`).
fn normalize_path(raw_path : String) -> String {
  if raw_path.length() == 0 {
    return "/"
  }
  let buf = StringBuilder::new()
  if raw_path[0] != '/' && raw_path[0] != '\\' {
    buf.write_char('/')
  }
  let mut prev_slash = false
  for i = 0; i < raw_path.length(); i = i + 1 {
    let ch = raw_path[i]
    if ch == '/' || ch == '\\' {
      if not(prev_slash) {
        buf.write_char('/')
        prev_slash = true
      }
    } else {
      buf.write_char(ch.to_int().unsafe_to_char())
      prev_slash = false
    }
  }
  let s = buf.to_string()
  if s.length() > 1 && s[s.length() - 1] == '/' {
    let trimmed = StringBuilder::new()
    for i = 0; i < s.length() - 1; i = i + 1 {
      trimmed.write_char(s[i].to_int().unsafe_to_char())
    }
    trimmed.to_string()
  } else {
    s
  }
}

///|
/// ExtismPathMount maps a sandboxed host VFS directory to a guest-visible virtual path.
pub(all) struct ExtismPathMount {
  host_path : String
  guest_path : String
  read_only : Bool
} derive(Debug, Eq)

///|
pub fn ExtismPathMount::new(
  host_path : String,
  guest_path : String,
  read_only : Bool,
) -> ExtismPathMount {
  {
    host_path: normalize_path(host_path),
    guest_path: normalize_path(guest_path),
    read_only,
  }
}

///|
/// ExtismWasmSource represents a Wasm module entry in the Extism Manifest.
pub(all) enum ExtismWasmSource {
  InlineBytes(String, Array[Byte], String?)
  VfsPath(String, String, String?)
} derive(Debug, Eq)

///|
/// ExtismManifest encapsulates the complete configuration of an Extism plugin.
pub(all) struct ExtismManifest {
  plugin_id : String
  wasm_sources : Array[ExtismWasmSource]
  memory : ExtismMemoryOptions
  config : Array[(String, String)]
  allowed_hosts : Array[String]
  allowed_paths : Array[ExtismPathMount]
  allowed_env_vars : Array[String]
  allow_clock : Bool
  timeout_ms : Int32
  max_execution_steps : Int32
} derive(Debug, Eq)

///|
pub fn ExtismManifest::new(plugin_id : String) -> ExtismManifest {
  {
    plugin_id,
    wasm_sources: [],
    memory: ExtismMemoryOptions::default(),
    config: [],
    allowed_hosts: [],
    allowed_paths: [],
    allowed_env_vars: [],
    allow_clock: false,
    timeout_ms: 30000,
    max_execution_steps: 100000,
  }
}

///|
pub fn ExtismManifest::with_wasm_bytes(
  self : ExtismManifest,
  name : String,
  bytes : Array[Byte],
  hash : String?,
) -> ExtismManifest {
  self.wasm_sources.push(ExtismWasmSource::InlineBytes(name, bytes, hash))
  self
}

///|
pub fn ExtismManifest::with_wasm_path(
  self : ExtismManifest,
  name : String,
  vfs_path : String,
  hash : String?,
) -> ExtismManifest {
  self.wasm_sources.push(ExtismWasmSource::VfsPath(name, vfs_path, hash))
  self
}

///|
pub fn ExtismManifest::with_memory_options(
  self : ExtismManifest,
  max_pages : Int32,
  max_http_response_bytes : Int32,
  max_var_bytes : Int32,
) -> ExtismManifest {
  { ..self, memory: { max_pages, max_http_response_bytes, max_var_bytes, }, }
}

///|
pub fn ExtismManifest::with_config(
  self : ExtismManifest,
  key : String,
  value : String,
) -> ExtismManifest {
  self.config.push((key, value))
  self
}

///|
pub fn ExtismManifest::with_allowed_host(
  self : ExtismManifest,
  host_pattern : String,
) -> ExtismManifest {
  self.allowed_hosts.push(host_pattern)
  self
}

///|
pub fn ExtismManifest::with_mount(
  self : ExtismManifest,
  host_path : String,
  guest_path : String,
  read_only : Bool,
) -> ExtismManifest {
  self.allowed_paths.push(
    ExtismPathMount::new(host_path, guest_path, read_only),
  )
  self
}

///|
/// Computes a deterministic 64-bit FNV-1a hex fingerprint for Wasm module integrity verification.
pub fn compute_wasm_fingerprint(bytes : Array[Byte]) -> String {
  let mut hash : UInt64 = 14695981039346656037UL
  let prime : UInt64 = 1099511628211UL
  for b in bytes {
    hash = (hash ^ b.to_uint64()) * prime
  }
  let hex_chars = "0123456789abcdef"
  let buf = StringBuilder::new()
  for i = 15; i >= 0; i = i - 1 {
    let nibble = ((hash >> (i * 4)) & 0xFUL).to_int()
    buf.write_char(hex_chars[nibble].unsafe_to_char())
  }
  buf.to_string()
}

///|
/// Verifies that a Wasm binary matches the expected manifest fingerprint.
pub fn verify_wasm_fingerprint(
  bytes : Array[Byte],
  expected_hex : String,
) -> Bool {
  compute_wasm_fingerprint(bytes) == expected_hex
}

///|
/// Translates a guest-side virtual path (e.g. `/docs/guide.md`) into the mounted host VFS path
/// (e.g. `/workspace/tenant1/docs/guide.md`) while enforcing read-only mount restrictions.
pub fn resolve_mounted_path(
  mounts : Array[ExtismPathMount],
  guest_raw_path : String,
  require_write : Bool,
) -> Result[String, SecurityError] {
  // Reject explicit directory traversal sequences before normalization
  let len = guest_raw_path.length()
  for i = 0; i < len; i = i + 1 {
    if guest_raw_path[i] == '.' && i + 1 < len && guest_raw_path[i + 1] == '.' {
      return Err(SecurityError::PathTraversalAttempt(guest_raw_path))
    }
  }

  let norm_guest = normalize_path(guest_raw_path)
  if mounts.length() == 0 {
    return Ok(norm_guest)
  }

  for m in mounts {
    let gp = m.guest_path
    let is_match = if gp == "/" {
      true
    } else if norm_guest == gp {
      true
    } else if norm_guest.length() > gp.length() &&
      has_prefix(norm_guest, gp) &&
      (gp[gp.length() - 1] == '/' || norm_guest[gp.length()] == '/') {
      true
    } else {
      false
    }

    if is_match {
      if require_write && m.read_only {
        return Err(
          SecurityError::PermissionDenied(
            "Mount point is read-only: " + guest_raw_path,
          ),
        )
      }
      let suffix_start = if gp == "/" { 1 } else { gp.length() }
      let buf = StringBuilder::new()
      buf.write_string(m.host_path)
      if suffix_start < norm_guest.length() {
        if m.host_path[m.host_path.length() - 1] != '/' &&
          norm_guest[suffix_start] != '/' {
          buf.write_char('/')
        }
        for i = suffix_start; i < norm_guest.length(); i = i + 1 {
          buf.write_char(norm_guest[i].unsafe_to_char())
        }
      }
      return Ok(normalize_path(buf.to_string()))
    }
  }

  Err(
    SecurityError::PermissionDenied(
      "Guest path is not mapped in Extism allowed_paths: " + guest_raw_path,
    ),
  )
}

///|
/// Converts an `ExtismManifest` into CapWasm's `CapabilityPolicy`.
pub fn ExtismManifest::to_capability_policy(
  self : ExtismManifest,
) -> CapabilityPolicy {
  let builder = CapabilityPolicyBuilder::new()
    .allow_clock(self.allow_clock)
    .max_memory_pages(self.memory.max_pages)
    .max_execution_steps(self.max_execution_steps)

  for host in self.allowed_hosts {
    let _ = builder.allow_network_host(host)
  }
  for env_key in self.allowed_env_vars {
    let _ = builder.allow_env_var(env_key)
  }
  for mount in self.allowed_paths {
    let _ = builder.allow_read_path(mount.host_path)
    if not(mount.read_only) {
      let _ = builder.allow_write_path(mount.host_path)
    }
  }
  builder.build()
}

///|
/// Helper: Extracts a JSON string value by key from a flat or nested JSON snippet.
fn extract_json_string_field(json : String, key : String) -> String? {
  let pattern = "\"" + key + "\""
  let plen = pattern.length()
  let jlen = json.length()
  for i = 0; i + plen < jlen; i = i + 1 {
    let mut matched = true
    for k = 0; k < plen; k = k + 1 {
      if json[i + k] != pattern[k] {
        matched = false
        break
      }
    }
    if matched {
      let mut pos = i + plen
      while pos < jlen &&
            (json[pos] == ' ' || json[pos] == '\t' || json[pos] == ':') {
        pos = pos + 1
      }
      if pos < jlen && json[pos] == '"' {
        pos = pos + 1
        let buf = StringBuilder::new()
        while pos < jlen && json[pos] != '"' {
          buf.write_char(json[pos].unsafe_to_char())
          pos = pos + 1
        }
        return Some(buf.to_string())
      }
    }
  }
  None
}

///|
/// Helper: Extracts an integer value by key from a JSON snippet.
fn extract_json_int_field(json : String, key : String) -> Int32? {
  let pattern = "\"" + key + "\""
  let plen = pattern.length()
  let jlen = json.length()
  for i = 0; i + plen < jlen; i = i + 1 {
    let mut matched = true
    for k = 0; k < plen; k = k + 1 {
      if json[i + k] != pattern[k] {
        matched = false
        break
      }
    }
    if matched {
      let mut pos = i + plen
      while pos < jlen &&
            (json[pos] == ' ' || json[pos] == '\t' || json[pos] == ':') {
        pos = pos + 1
      }
      if pos < jlen && json[pos] >= '0' && json[pos] <= '9' {
        let mut val = 0
        while pos < jlen && json[pos] >= '0' && json[pos] <= '9' {
          val = val * 10 + (json[pos].to_int() - '0'.to_int())
          pos = pos + 1
        }
        return Some(val)
      }
    }
  }
  None
}

///|
/// Helper: Extracts a JSON string array `["a", "b"]` for a given key.
fn extract_json_string_array(json : String, key : String) -> Array[String] {
  let res : Array[String] = []
  let pattern = "\"" + key + "\""
  let plen = pattern.length()
  let jlen = json.length()
  for i = 0; i + plen < jlen; i = i + 1 {
    let mut matched = true
    for k = 0; k < plen; k = k + 1 {
      if json[i + k] != pattern[k] {
        matched = false
        break
      }
    }
    if matched {
      let mut pos = i + plen
      while pos < jlen && json[pos] != '[' {
        pos = pos + 1
      }
      if pos < jlen && json[pos] == '[' {
        pos = pos + 1
        while pos < jlen && json[pos] != ']' {
          if json[pos] == '"' {
            pos = pos + 1
            let buf = StringBuilder::new()
            while pos < jlen && json[pos] != '"' {
              buf.write_char(json[pos].unsafe_to_char())
              pos = pos + 1
            }
            res.push(buf.to_string())
          }
          pos = pos + 1
        }
      }
      break
    }
  }
  res
}

///|
/// Helper: Extracts a flat string map `{"k1": "v1", "k2": "v2"}` under a given JSON object key.
fn extract_json_string_map(
  json : String,
  key : String,
) -> Array[(String, String)] {
  let res : Array[(String, String)] = []
  let pattern = "\"" + key + "\""
  let plen = pattern.length()
  let jlen = json.length()
  for i = 0; i + plen < jlen; i = i + 1 {
    let mut matched = true
    for k = 0; k < plen; k = k + 1 {
      if json[i + k] != pattern[k] {
        matched = false
        break
      }
    }
    if matched {
      let mut pos = i + plen
      while pos < jlen && json[pos] != '{' {
        pos = pos + 1
      }
      if pos < jlen && json[pos] == '{' {
        pos = pos + 1
        while pos < jlen && json[pos] != '}' {
          if json[pos] == '"' {
            pos = pos + 1
            let kbuf = StringBuilder::new()
            while pos < jlen && json[pos] != '"' {
              kbuf.write_char(json[pos].unsafe_to_char())
              pos = pos + 1
            }
            pos = pos + 1 // skip closing quote of key
            while pos < jlen && json[pos] != '"' && json[pos] != '}' {
              pos = pos + 1
            }
            if pos < jlen && json[pos] == '"' {
              pos = pos + 1
              let vbuf = StringBuilder::new()
              while pos < jlen && json[pos] != '"' {
                vbuf.write_char(json[pos].unsafe_to_char())
                pos = pos + 1
              }
              res.push((kbuf.to_string(), vbuf.to_string()))
            }
          }
          pos = pos + 1
        }
      }
      break
    }
  }
  res
}

///|
/// Parses a standard Extism Manifest JSON string into an `ExtismManifest` structure.
/// Supports `plugin_id`, `memory` (`max_pages`, `max_http_response_bytes`, `max_var_bytes`),
/// `config`, `allowed_hosts`, `allowed_paths` (including `"ro:/host/path": "/guest/path"`),
/// `allowed_env_vars`, `timeout_ms`, and `max_execution_steps`.
pub fn ExtismManifest::from_json(
  json_str : String,
) -> Result[ExtismManifest, String] {
  let mut trimmed_non_empty = false
  for i = 0; i < json_str.length(); i = i + 1 {
    if json_str[i] == '{' {
      trimmed_non_empty = true
      break
    }
  }
  if not(trimmed_non_empty) {
    return Err("Invalid Extism Manifest JSON: missing root object '{'")
  }

  let plugin_id = match extract_json_string_field(json_str, "plugin_id") {
    Some(id) => id
    None =>
      match extract_json_string_field(json_str, "name") {
        Some(n) => n
        None => "extism-plugin"
      }
  }

  let max_pages = match extract_json_int_field(json_str, "max_pages") {
    Some(p) => p
    None => 16
  }
  let max_http_response_bytes = match
    extract_json_int_field(json_str, "max_http_response_bytes") {
    Some(b) => b
    None => 1048576
  }
  let max_var_bytes = match extract_json_int_field(json_str, "max_var_bytes") {
    Some(b) => b
    None => 1048576
  }
  let timeout_ms = match extract_json_int_field(json_str, "timeout_ms") {
    Some(t) => t
    None => 30000
  }
  let max_execution_steps = match
    extract_json_int_field(json_str, "max_execution_steps") {
    Some(s) => s
    None => 100000
  }

  let config = extract_json_string_map(json_str, "config")
  let allowed_hosts = extract_json_string_array(json_str, "allowed_hosts")
  let allowed_env_vars = extract_json_string_array(json_str, "allowed_env_vars")
  let raw_paths = extract_json_string_map(json_str, "allowed_paths")
  let allowed_paths : Array[ExtismPathMount] = []

  for item in raw_paths {
    let (host_raw, guest_raw) = item
    if host_raw.length() > 3 &&
      host_raw[0] == 'r' &&
      host_raw[1] == 'o' &&
      host_raw[2] == ':' {
      let hbuf = StringBuilder::new()
      for i = 3; i < host_raw.length(); i = i + 1 {
        hbuf.write_char(host_raw[i].unsafe_to_char())
      }
      allowed_paths.push(
        ExtismPathMount::new(hbuf.to_string(), guest_raw, true),
      )
    } else {
      allowed_paths.push(ExtismPathMount::new(host_raw, guest_raw, false))
    }
  }

  let wasm_sources : Array[ExtismWasmSource] = []
  let resolved_wasm_path = match
    extract_json_string_field(json_str, "wasm_path") {
    Some(wp) => Some(wp)
    None => extract_json_string_field(json_str, "path")
  }
  match resolved_wasm_path {
    Some(wp) => {
      let hash = extract_json_string_field(json_str, "hash")
      wasm_sources.push(ExtismWasmSource::VfsPath(plugin_id, wp, hash))
    }
    None => ()
  }

  Ok({
    plugin_id,
    wasm_sources,
    memory: { max_pages, max_http_response_bytes, max_var_bytes, },
    config,
    allowed_hosts,
    allowed_paths,
    allowed_env_vars,
    allow_clock: true,
    timeout_ms,
    max_execution_steps,
  })
}
