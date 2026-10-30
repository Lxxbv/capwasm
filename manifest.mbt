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
/// Right-rotates a 32-bit unsigned integer by `n` bits (for FIPS 180-4 SHA-256).
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
/// Computes the standard FIPS 180-4 SHA-256 64-character lowercase hex digest
/// required by the official Extism Manifest `wasm[].hash` specification.
pub fn compute_wasm_sha256(bytes : Array[Byte]) -> String {
  let k : Array[UInt32] = [
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
    0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
    0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
    0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
  ]

  let mut h0 : UInt32 = 0x6a09e667U
  let mut h1 : UInt32 = 0xbb67ae85U
  let mut h2 : UInt32 = 0x3c6ef372U
  let mut h3 : UInt32 = 0xa54ff53aU
  let mut h4 : UInt32 = 0x510e527fU
  let mut h5 : UInt32 = 0x9b05688cU
  let mut h6 : UInt32 = 0x1f83d9abU
  let mut h7 : UInt32 = 0x5be0cd19U

  // Pre-processing: pad message to multiple of 64 bytes (512 bits)
  let padded : Array[Byte] = []
  for b in bytes {
    padded.push(b)
  }
  padded.push(b'\x80')
  while padded.length() % 64 != 56 {
    padded.push(b'\x00')
  }
  let bit_len : UInt64 = bytes.length().to_uint64() * 8UL
  for shift = 56; shift >= 0; shift = shift - 8 {
    padded.push(((bit_len >> shift) & 0xFFUL).to_int().to_byte())
  }

  let w = Array::make(64, 0U)
  let num_chunks = padded.length() / 64
  for chunk = 0; chunk < num_chunks; chunk = chunk + 1 {
    let base = chunk * 64
    for i = 0; i < 16; i = i + 1 {
      let off = base + i * 4
      let b0 = padded[off].to_int().reinterpret_as_uint()
      let b1 = padded[off + 1].to_int().reinterpret_as_uint()
      let b2 = padded[off + 2].to_int().reinterpret_as_uint()
      let b3 = padded[off + 3].to_int().reinterpret_as_uint()
      w[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
    for i = 16; i < 64; i = i + 1 {
      let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
      let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1
    }

    let mut a = h0
    let mut b = h1
    let mut c = h2
    let mut d = h3
    let mut e = h4
    let mut f = h5
    let mut g = h6
    let mut h = h7

    for i = 0; i < 64; i = i + 1 {
      let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
      let ch = (e & f) ^ (e.lnot() & g)
      let temp1 = h + s1 + ch + k[i] + w[i]
      let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let temp2 = s0 + maj

      h = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b
      b = a
      a = temp1 + temp2
    }

    h0 = h0 + a
    h1 = h1 + b
    h2 = h2 + c
    h3 = h3 + d
    h4 = h4 + e
    h5 = h5 + f
    h6 = h6 + g
    h7 = h7 + h
  }

  let words : Array[UInt32] = [h0, h1, h2, h3, h4, h5, h6, h7]
  let hex_chars = "0123456789abcdef"
  let buf = StringBuilder::new()
  for word in words {
    for nibble_idx = 7; nibble_idx >= 0; nibble_idx = nibble_idx - 1 {
      let nib = ((word >> (nibble_idx * 4)) & 0xFU).reinterpret_as_int()
      buf.write_char(hex_chars[nib].to_int().unsafe_to_char())
    }
  }
  buf.to_string()
}

///|
/// Computes the standard SHA-256 hex digest for Wasm module integrity verification.
pub fn compute_wasm_fingerprint(bytes : Array[Byte]) -> String {
  compute_wasm_sha256(bytes)
}

///|
/// Verifies that a Wasm binary matches the expected Extism Manifest SHA-256 digest.
pub fn verify_wasm_fingerprint(
  bytes : Array[Byte],
  expected_hex : String,
) -> Bool {
  compute_wasm_sha256(bytes) == expected_hex
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
