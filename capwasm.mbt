// CapWasm: Capability-Based WebAssembly Plugin Sandbox for MoonBit
// Designed for production-grade plugin isolation, capability management, and runtime security.

/// SecurityError represents a violation of sandboxing rules or execution limits.
pub(all) enum SecurityError {
  PermissionDenied(String)
  PathTraversalAttempt(String)
  OutOfQuota(String)
  MemoryOutOfBounds(Int, Int)
  Aborted(String)
} derive(Debug, Eq)

pub impl Show for SecurityError with output(self, logger) {
  match self {
    PermissionDenied(msg) => logger.write_string("PermissionDenied: " + msg)
    PathTraversalAttempt(path) => logger.write_string("PathTraversalAttempt: " + path)
    OutOfQuota(msg) => logger.write_string("OutOfQuota: " + msg)
    MemoryOutOfBounds(_off, _len) => logger.write_string("MemoryOutOfBounds")
    Aborted(msg) => logger.write_string("Aborted: " + msg)
  }
}

/// ActionType represents the type of action requested by a plugin.
pub(all) enum ActionType {
  FsRead
  FsWrite
  NetConnect
  ClockRead
  EnvRead
} derive(Debug, Eq)

/// ResourceQuota defines physical resource boundaries for a sandboxed plugin.
pub(all) struct ResourceQuota {
  max_memory_pages : Int
  max_execution_steps : Int
} derive(Debug, Eq)

pub fn ResourceQuota::default() -> ResourceQuota {
  { max_memory_pages: 16, max_execution_steps: 100_000 }
}

/// CapabilityPolicy defines the permissions granted to a specific plugin instance.
pub(all) struct CapabilityPolicy {
  allowed_read_paths : Array[String]
  allowed_write_paths : Array[String]
  allowed_network_hosts : Array[String]
  allow_clock : Bool
  allowed_env_vars : Array[String]
  quota : ResourceQuota
} derive(Debug)

pub fn CapabilityPolicy::builder() -> CapabilityPolicyBuilder {
  CapabilityPolicyBuilder::new()
}

pub(all) struct CapabilityPolicyBuilder {
  mut read_paths : Array[String]
  mut write_paths : Array[String]
  mut hosts : Array[String]
  mut allow_clock : Bool
  mut env_vars : Array[String]
  mut quota : ResourceQuota
}

pub fn CapabilityPolicyBuilder::new() -> CapabilityPolicyBuilder {
  {
    read_paths: [],
    write_paths: [],
    hosts: [],
    allow_clock: false,
    env_vars: [],
    quota: ResourceQuota::default(),
  }
}

pub fn CapabilityPolicyBuilder::allow_read_path(
  self : CapabilityPolicyBuilder,
  path : String
) -> CapabilityPolicyBuilder {
  self.read_paths.push(path)
  self
}

pub fn CapabilityPolicyBuilder::allow_write_path(
  self : CapabilityPolicyBuilder,
  path : String
) -> CapabilityPolicyBuilder {
  self.write_paths.push(path)
  self
}

pub fn CapabilityPolicyBuilder::allow_network_host(
  self : CapabilityPolicyBuilder,
  host : String
) -> CapabilityPolicyBuilder {
  self.hosts.push(host)
  self
}

pub fn CapabilityPolicyBuilder::allow_clock(
  self : CapabilityPolicyBuilder,
  allowed : Bool
) -> CapabilityPolicyBuilder {
  self.allow_clock = allowed
  self
}

pub fn CapabilityPolicyBuilder::set_quota(
  self : CapabilityPolicyBuilder,
  quota : ResourceQuota
) -> CapabilityPolicyBuilder {
  self.quota = quota
  self
}

pub fn CapabilityPolicyBuilder::build(
  self : CapabilityPolicyBuilder
) -> CapabilityPolicy {
  {
    allowed_read_paths: self.read_paths,
    allowed_write_paths: self.write_paths,
    allowed_network_hosts: self.hosts,
    allow_clock: self.allow_clock,
    allowed_env_vars: self.env_vars,
    quota: self.quota,
  }
}

/// Helper function to check if a path contains directory traversal sequences ("..")
fn contains_path_traversal(path : String) -> Bool {
  let len = path.length()
  for i = 0; i < len; i = i + 1 {
    if path[i] == '.' && i + 1 < len && path[i + 1] == '.' {
      return true
    }
  }
  false
}

/// Helper function to test string prefix
fn has_prefix(str : String, prefix : String) -> Bool {
  if str.length() < prefix.length() {
    return false
  }
  for i = 0; i < prefix.length(); i = i + 1 {
    if str[i] != prefix[i] {
      return false
    }
  }
  true
}

/// AuditRecord tracks every privileged host interaction requested by a plugin.
pub(all) struct AuditRecord {
  plugin_id : String
  action : ActionType
  target : String
  allowed : Bool
  reason : String
} derive(Debug, Eq)

/// PluginSecurityGuard enforces capability checks and maintains audit logs.
pub(all) struct PluginSecurityGuard {
  plugin_id : String
  policy : CapabilityPolicy
  audit_logs : Array[AuditRecord]
  mut consumed_steps : Int
}

pub fn PluginSecurityGuard::new(
  plugin_id : String,
  policy : CapabilityPolicy
) -> PluginSecurityGuard {
  {
    plugin_id,
    policy,
    audit_logs: [],
    consumed_steps: 0,
  }
}

pub fn PluginSecurityGuard::get_audit_logs(
  self : PluginSecurityGuard
) -> Array[AuditRecord] {
  self.audit_logs
}

pub fn PluginSecurityGuard::check_fs_read(
  self : PluginSecurityGuard,
  path : String
) -> Result[Unit, SecurityError] {
  if contains_path_traversal(path) {
    let err = SecurityError::PathTraversalAttempt(path)
    self.audit_logs.push({
      plugin_id: self.plugin_id,
      action: ActionType::FsRead,
      target: path,
      allowed: false,
      reason: "Path traversal attempt detected",
    })
    return Err(err)
  }

  let mut matched = false
  for allowed in self.policy.allowed_read_paths {
    if has_prefix(path, allowed) {
      matched = true
      break
    }
  }

  if matched {
    self.audit_logs.push({
      plugin_id: self.plugin_id,
      action: ActionType::FsRead,
      target: path,
      allowed: true,
      reason: "Matched read allowlist",
    })
    Ok(())
  } else {
    self.audit_logs.push({
      plugin_id: self.plugin_id,
      action: ActionType::FsRead,
      target: path,
      allowed: false,
      reason: "Path not in permitted read list",
    })
    Err(SecurityError::PermissionDenied("Path not allowed: " + path))
  }
}

pub fn PluginSecurityGuard::check_fs_write(
  self : PluginSecurityGuard,
  path : String
) -> Result[Unit, SecurityError] {
  if contains_path_traversal(path) {
    let err = SecurityError::PathTraversalAttempt(path)
    self.audit_logs.push({
      plugin_id: self.plugin_id,
      action: ActionType::FsWrite,
      target: path,
      allowed: false,
      reason: "Path traversal attempt detected",
    })
    return Err(err)
  }

  let mut matched = false
  for allowed in self.policy.allowed_write_paths {
    if has_prefix(path, allowed) {
      matched = true
      break
    }
  }

  if matched {
    self.audit_logs.push({
      plugin_id: self.plugin_id,
      action: ActionType::FsWrite,
      target: path,
      allowed: true,
      reason: "Matched write allowlist",
    })
    Ok(())
  } else {
    self.audit_logs.push({
      plugin_id: self.plugin_id,
      action: ActionType::FsWrite,
      target: path,
      allowed: false,
      reason: "Path not in permitted write list",
    })
    Err(SecurityError::PermissionDenied("Write not allowed: " + path))
  }
}

pub fn PluginSecurityGuard::check_network(
  self : PluginSecurityGuard,
  host : String
) -> Result[Unit, SecurityError] {
  let mut matched = false
  for allowed in self.policy.allowed_network_hosts {
    if host == allowed {
      matched = true
      break
    }
  }

  if matched {
    self.audit_logs.push({
      plugin_id: self.plugin_id,
      action: ActionType::NetConnect,
      target: host,
      allowed: true,
      reason: "Host in network allowlist",
    })
    Ok(())
  } else {
    self.audit_logs.push({
      plugin_id: self.plugin_id,
      action: ActionType::NetConnect,
      target: host,
      allowed: false,
      reason: "Host not in network allowlist",
    })
    Err(SecurityError::PermissionDenied("Network forbidden: " + host))
  }
}
